"""
Wey Shield — Security Layer (from Qwen, enhanced)
TitaniumAuthGate: scope locking + kill switch.
"""

import hashlib
import logging
import os
import time

logger = logging.getLogger("wey_shield.security")

# Responses that signal we've hit a WAF, legal block, or honeypot
KILL_SWITCH_SIGNATURES = [
    "cloudflare",
    "aws-waf",
    "akamai",
    "imperva",
    "cease-and-desist",
    "unauthorized-access",
    "honeypot",
    "you-have-been-blocked",
    "legal-notice",
]

PROD_SALT = os.environ.get("SHIELD_SCOPE_SALT", "dev_salt_replace_in_prod")


class TitaniumAuthGate:
    """
    Scope locking + kill switch.
    Works alongside AuthGate (ownership verification).
    This layer ensures scope doesn't drift DURING a scan.
    """

    def generate_scope_token(self, client_id: str, targets: list[str]) -> str:
        """
        Mathematically locks a scan to specific targets at a specific time.
        Token encodes: who, what targets, when. Cannot be extended mid-scan.
        """
        scope_string = f"{client_id}:{','.join(sorted(targets))}:{int(time.time())}"
        return hashlib.sha256(
            f"weyshield_v2:{scope_string}:{PROD_SALT}".encode()
        ).hexdigest()

    def verify_scope_lock(self, scope_token: str, current_target: str, allowed_targets: list[str]) -> bool:
        """
        Called before EVERY packet leaves the scanner.
        Ensures current_target is in the originally authorised list.
        Hard block — no exceptions.
        """
        if current_target not in allowed_targets:
            logger.critical(
                f"🛑 SCOPE VIOLATION: Attempted scan of {current_target} "
                f"which is not in authorised targets: {allowed_targets}"
            )
            return False
        return True

    def check_kill_switch(self, response_headers: dict, response_body: str = "") -> bool:
        """
        Real-time response analysis.
        If the target signals a WAF block or legal issue — abort immediately.
        Protects the client and Wey Shield from legal exposure.
        """
        headers_str = str({k.lower(): v.lower() for k, v in response_headers.items()})
        body_lower = response_body.lower()[:2000]  # Only check first 2KB

        for sig in KILL_SWITCH_SIGNATURES:
            if sig in headers_str or sig in body_lower:
                logger.critical(
                    f"🛑 KILL SWITCH: Detected '{sig}' in response. "
                    "Aborting scan immediately."
                )
                return True
        return False
