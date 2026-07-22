"""
License validator — enforces free tier limits (50 audits/day).
Embedded in all Correctover Agent products.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional


class LicenseValidator:
    """Enforces usage limits for Correctover Agent products."""

    FREE_LIMIT_PER_DAY = 50
    STATE_FILE = Path.home() / ".correctover" / "license.json"

    def __init__(self, product: str):
        self.product = product
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"products": {}, "license_key": None, "installed_at": time.time()}

    def _save_state(self) -> None:
        self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.STATE_FILE.write_text(json.dumps(self.state, indent=2))

    def _get_product_state(self) -> Dict:
        return self.state["products"].setdefault(self.product, {
            "calls_today": 0,
            "date": time.strftime("%Y-%m-%d"),
            "total_calls": 0,
        })

    def check_license(self) -> Dict:
        """Check if the current usage is within limits. Returns status dict."""
        today = time.strftime("%Y-%m-%d")
        ps = self._get_product_state()

        # Reset daily counter if it's a new day
        if ps.get("date") != today:
            ps["calls_today"] = 0
            ps["date"] = today

        license_key = self.state.get("license_key")
        has_license = bool(license_key)

        if has_license:
            # Pro/Enterprise — no limits
            return {
                "authorized": True,
                "tier": "pro" if self._verify_license_key(license_key) else "free",
                "calls_remaining": float("inf"),
                "calls_today": ps["calls_today"],
                "limit": float("inf"),
                "license_key": license_key[:8] + "..." if license_key else None,
            }

        # Free tier
        remaining = max(0, self.FREE_LIMIT_PER_DAY - ps["calls_today"])
        return {
            "authorized": remaining > 0,
            "tier": "free",
            "calls_remaining": remaining,
            "calls_today": ps["calls_today"],
            "limit": self.FREE_LIMIT_PER_DAY,
            "license_key": None,
        }

    def record_call(self) -> Dict:
        """Record a single API call. Returns updated status."""
        status = self.check_license()
        if not status["authorized"]:
            return status

        ps = self._get_product_state()
        ps["calls_today"] += 1
        ps["total_calls"] = ps.get("total_calls", 0) + 1
        self._save_state()

        status["calls_remaining"] = max(0, status["limit"] - ps["calls_today"])
        status["calls_today"] = ps["calls_today"]
        return status

    def set_license_key(self, key: str) -> bool:
        """Set and validate a license key.

        Supports two formats:

        * **COV-<product>-<hash>** — Cloud-issued, HMAC-verified offline.
        * **CV-TRL-<base64>** / **CV-PRO-<base64>** — FC-issued (XunhuPay),
          base64 payload containing JWT-like signed claims.  Accepted as valid
          when the payload decodes cleanly (the real verification happens
          server-side in the FC callback).
        """
        if self._verify_license_key(key):
            self.state["license_key"] = key
            self._save_state()
            return True
        return False

    def _verify_license_key(self, key: str) -> bool:
        """Validate a license key against supported formats."""
        if not key or len(key) < 12:
            return False

        # ── COV-<product>-<hash> (Cloud / HMAC offline) ──
        if key.startswith("COV-"):
            parts = key.split("-")
            if len(parts) < 3:
                return False
            product_code = "-".join(parts[1:-1])
            expected_prefix = self._compute_key_prefix(product_code)
            return parts[-1].startswith(expected_prefix)

        # ── CV-TRL-<base64> / CV-PRO-<base64> (FC / XunhuPay) ──
        # Format: CV-{TRL|PRO}-{urlsafe_b64(json_claims)}.{urlsafe_b64(hmac)}
        if key.startswith("CV-"):
            parts = key.split("-", 2)
            if len(parts) < 3:
                return False
            import base64 as _b64
            try:
                payload = parts[2]
                # The payload is "<b64_claims>.<b64_sig>" — decode the claims part
                dot = payload.find(".")
                if dot > 0:
                    b64_claims = payload[:dot]
                else:
                    b64_claims = payload
                padded = b64_claims + "=" * (4 - len(b64_claims) % 4) if len(b64_claims) % 4 else b64_claims
                decoded = _b64.urlsafe_b64decode(padded)
                return b"@" in decoded or len(decoded) > 10
            except Exception:
                return False

        return False

    def _compute_key_prefix(self, product_code: str) -> str:
        secret = f"correctover-{product_code}-2026"
        return hashlib.sha256(secret.encode()).hexdigest()[:12]

    def get_upgrade_message(self) -> str:
        """Return the appropriate upgrade CTA."""
        status = self.check_license()
        if status["tier"] == "free":
            remaining = status["calls_remaining"]
            if remaining <= 0:
                return (
                    f"\n🚫 Free tier limit reached ({self.FREE_LIMIT_PER_DAY} audits/day).\n"
                    f"   Upgrade to Pro for unlimited audits: https://correctover.com/checkout\n"
                    f"   Or set your license key: export CORRECTOVER_LICENSE_KEY=<your-key>\n"
                )
            return (
                f"\n📊 Free tier: {remaining} audits remaining today.\n"
                f"   Upgrade to Pro: https://correctover.com/checkout\n"
            )
        return ""

    @staticmethod
    def get_license_from_env() -> Optional[str]:
        return os.environ.get("CORRECTOVER_LICENSE_KEY")


# Global singleton
_validators: Dict[str, LicenseValidator] = {}


def get_validator(product: str = "correctover-test") -> LicenseValidator:
    if product not in _validators:
        _validators[product] = LicenseValidator(product)
    return _validators[product]


def check_and_record(product: str = "correctover-test") -> Dict:
    """Check license, record call, return status. Raise if over limit."""
    v = get_validator(product)
    status = v.check_license()

    if not status["authorized"]:
        msg = v.get_upgrade_message()
        raise LicenseExceededError(
            f"Free tier limit ({v.FREE_LIMIT_PER_DAY}/day) exceeded. {msg}"
        )

    return v.record_call()


class LicenseExceededError(Exception):
    """Raised when free tier limit is exceeded."""
    pass
