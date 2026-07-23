"""
License validator — enforces free tier limits (30 checks/month, no reset).
Embedded in all Correctover Agent products.

Billing model:
  - Free: 30 checks/month (cumulative, no daily reset)
  - Pro:  unlimited
  - 1 check = 1 test scenario executed (e.g. --all = 9 checks)
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional


class LicenseValidator:
    """Enforces usage limits for Correctover Agent products."""

    FREE_LIMIT_PER_MONTH = 30
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
            "checks_used": 0,
            "month": time.strftime("%Y-%m"),
            "total_checks": 0,
        })

    def _current_month(self) -> str:
        return time.strftime("%Y-%m")

    def check_license(self) -> Dict:
        """Check if the current usage is within limits. Returns status dict."""
        current_month = self._current_month()
        ps = self._get_product_state()

        # Reset monthly counter if it's a new month
        if ps.get("month") != current_month:
            ps["checks_used"] = 0
            ps["month"] = current_month

        license_key = self.state.get("license_key")
        has_license = bool(license_key)

        if has_license:
            tier = "pro" if self._verify_license_key(license_key) else "free"
            if tier == "pro":
                return {
                    "authorized": True,
                    "tier": "pro",
                    "checks_remaining": float("inf"),
                    "checks_used": ps["checks_used"],
                    "limit": float("inf"),
                    "license_key": license_key[:8] + "..." if license_key else None,
                }

        # Free tier — monthly cumulative, no daily reset
        remaining = max(0, self.FREE_LIMIT_PER_MONTH - ps["checks_used"])
        return {
            "authorized": remaining > 0,
            "tier": "free",
            "checks_remaining": remaining,
            "checks_used": ps["checks_used"],
            "limit": self.FREE_LIMIT_PER_MONTH,
            "license_key": None,
        }

    def record_call(self, count: int = 1) -> Dict:
        """Record API calls. count = number of checks consumed.
        Returns updated status. If not authorized, returns status without recording."""
        status = self.check_license()
        if not status["authorized"]:
            return status

        ps = self._get_product_state()
        ps["checks_used"] += count
        ps["total_checks"] = ps.get("total_checks", 0) + count
        self._save_state()

        remaining = max(0, self.FREE_LIMIT_PER_MONTH - ps["checks_used"])
        status["checks_remaining"] = remaining
        status["checks_used"] = ps["checks_used"]
        return status

    def can_run(self, count: int) -> bool:
        """Check if user can run `count` checks without exceeding limit."""
        status = self.check_license()
        if status["tier"] == "pro":
            return True
        return status["checks_remaining"] >= count

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
        if key.startswith("CV-"):
            parts = key.split("-", 2)
            if len(parts) < 3:
                return False
            import base64 as _b64
            try:
                payload = parts[2]
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

    def get_upgrade_message(self, context: str = "limit") -> str:
        """Return the appropriate upgrade CTA based on context."""
        status = self.check_license()
        if status["tier"] == "free":
            remaining = status["checks_remaining"]
            if remaining <= 0:
                return (
                    f"\n🚫 Free tier limit reached ({self.FREE_LIMIT_PER_MONTH} checks/month).\n"
                    f"   Upgrade to Pro for unlimited checks + fix recommendations + auto-heal:\n"
                    f"   → https://correctover.com/checkout\n"
                    f"   Or: export CORRECTOVER_LICENSE_KEY=<your-key>\n"
                )
            elif context == "results":
                return (
                    f"\n{'━'*50}\n"
                    f"🔒 {remaining} checks remaining this month.\n"
                    f"   Upgrade to Pro for:\n"
                    f"   • Full risk report (all findings, not just first 2)\n"
                    f"   • Fix recommendations + code patches\n"
                    f"   • Auto-heal (84.1% issues resolved automatically)\n"
                    f"   • HTML/PDF audit reports\n"
                    f"{'━'*50}\n"
                    f"   → https://correctover.com/checkout\n"
                    f"{'━'*50}\n"
                )
            return (
                f"\n📊 Free tier: {remaining} checks remaining this month.\n"
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


def check_and_record(product: str = "correctover-test", count: int = 1) -> Dict:
    """Check license, record calls, return status. Raise if over limit."""
    v = get_validator(product)
    status = v.check_license()

    if not status["authorized"]:
        msg = v.get_upgrade_message(context="limit")
        raise LicenseExceededError(
            f"Free tier limit ({v.FREE_LIMIT_PER_MONTH}/month) exceeded. {msg}"
        )

    return v.record_call(count)


class LicenseExceededError(Exception):
    """Raised when free tier limit is exceeded."""
    pass
