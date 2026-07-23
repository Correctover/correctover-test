"""
License validator — freemium hook model.

  - Free: unlimited scanning (see all risks)
  - Pro: fix recommendations, auto-heal, reports, history
  
The hook: users see ALL their problems for free.
The paywall: solutions are locked.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional


class LicenseValidator:
    """Freemium license — scan free, fix paid."""

    STATE_FILE = Path.home() / ".correctover" / "license.json"

    # Free tier: unlimited scans, but results are gated
    FREE_SCAN_LIMIT = float("inf")  # unlimited scanning
    FREE_FIX_PREVIEW = 2            # show first 2 fix recommendations
    FREE_REPORT = False             # no HTML/PDF reports
    FREE_HISTORY = False            # no scan history

    def __init__(self, product: str):
        self.product = product
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"products": {}, "license_key": None, "installed_at": time.time(), "scan_history": []}

    def _save_state(self) -> None:
        self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.STATE_FILE.write_text(json.dumps(self.state, indent=2))

    def _get_product_state(self) -> Dict:
        return self.state["products"].setdefault(self.product, {
            "total_scans": 0,
            "total_risks_found": 0,
            "first_scan": time.time(),
            "last_scan": None,
        })

    def check_license(self) -> Dict:
        """Check license status. Free tier can always scan."""
        license_key = self.state.get("license_key") or os.environ.get("CORRECTOVER_LICENSE_KEY")

        if license_key and self._verify_license_key(license_key):
            return {
                "tier": "pro",
                "can_scan": True,
                "can_fix": True,
                "can_report": True,
                "can_heal": True,
                "can_history": True,
                "fix_preview": float("inf"),
                "license_key": license_key[:8] + "..." if license_key else None,
            }

        # Free tier — can scan unlimited, but features are gated
        return {
            "tier": "free",
            "can_scan": True,
            "can_fix": False,
            "can_report": False,
            "can_heal": False,
            "can_history": False,
            "fix_preview": self.FREE_FIX_PREVIEW,
            "license_key": None,
        }

    def record_scan(self, risks_found: int = 0) -> Dict:
        """Record a scan. Always allowed — this is the hook."""
        ps = self._get_product_state()
        ps["total_scans"] += 1
        ps["total_risks_found"] += risks_found
        ps["last_scan"] = time.time()
        self._save_state()

        # Also add to scan history (free tier keeps last 1, Pro keeps all)
        history = self.state.setdefault("scan_history", [])
        history.append({
            "time": time.time(),
            "product": self.product,
            "risks": risks_found,
        })
        if len(history) > 1 and self.check_license()["tier"] == "free":
            # Free tier: only keep last scan (previous ones are the hook — "you had 5 risks last time")
            history = history[-1:]
            self.state["scan_history"] = history
        self._save_state()

        return self.check_license()

    def set_license_key(self, key: str) -> bool:
        if self._verify_license_key(key):
            self.state["license_key"] = key
            self._save_state()
            return True
        return False

    def _verify_license_key(self, key: str) -> bool:
        if not key or len(key) < 12:
            return False

        # COV-<product>-<hash> (Cloud / HMAC offline)
        if key.startswith("COV-"):
            parts = key.split("-")
            if len(parts) < 3:
                return False
            product_code = "-".join(parts[1:-1])
            expected_prefix = self._compute_key_prefix(product_code)
            return parts[-1].startswith(expected_prefix)

        # CV-TRL-<base64> / CV-PRO-<base64> (FC / XunhuPay)
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

    def get_fix_cta(self, total_risks: int, hidden_risks: int) -> str:
        """Generate CTA shown after scan results — the hook."""
        status = self.check_license()
        if status["tier"] == "pro":
            return ""

        shown = total_risks - hidden_risks
        lines = [
            f"\n{'━'*55}",
            f"🔒 {hidden_risks} fix recommendation(s) locked.",
        ]
        if total_risks > 0:
            lines.append(f"   You have {total_risks} risk(s) but can only see {shown} fix(es).")
        lines.extend([
            f"",
            f"🛡️  Upgrade to Pro to unlock:",
            f"   ✓ Fix recommendations for all {total_risks} risk(s)",
            f"   ✓ Auto-heal (84.1% issues resolved automatically)",
            f"   ✓ HTML/PDF audit reports",
            f"   ✓ Scan history & tracking",
            f"{'━'*55}",
            f"   → https://correctover.com/checkout",
            f"   → export CORRECTOVER_LICENSE_KEY=<your-key>",
            f"{'━'*55}",
        ])
        return "\n".join(lines)

    def get_no_risk_cta(self) -> str:
        """CTA when no risks found — still hook them."""
        status = self.check_license()
        if status["tier"] == "pro":
            return ""
        return (
            f"\n{'━'*55}\n"
            f"✅ No risks found in this scan.\n\n"
            f"🛡️  Stay protected with Pro:\n"
            f"   ✓ Continuous monitoring (auto-scan on config changes)\n"
            f"   ✓ Auto-heal when risks appear\n"
            f"   ✓ Compliance reports (OAuth 2.1, CCS v1.0)\n"
            f"{'━'*55}\n"
            f"   → https://correctover.com/checkout\n"
            f"{'━'*55}"
        )

    @staticmethod
    def get_license_from_env() -> Optional[str]:
        return os.environ.get("CORRECTOVER_LICENSE_KEY")


# Global singleton
_validators: Dict[str, LicenseValidator] = {}


def get_validator(product: str = "correctover-test") -> LicenseValidator:
    if product not in _validators:
        _validators[product] = LicenseValidator(product)
    return _validators[product]


class LicenseExceededError(Exception):
    """Kept for backward compatibility — no longer raised in freemium model."""
    pass
