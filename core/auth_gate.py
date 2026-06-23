"""
Wey Shield — Authorisation Gate
Hard boundary. No scan fires without confirmed target ownership.
This is not optional middleware — it's baked into the orchestrator.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from core.models import AuthRecord

logger = logging.getLogger("wey_shield.auth_gate")

# Authorisation expires after 30 days
AUTH_TTL_DAYS = 30

# Methods a client can use to prove target ownership
VERIFICATION_METHODS = [
    "dns_txt_record",    # Add TXT record to DNS: weyshield-verify=<token>
    "http_file",         # Serve /.well-known/weyshield-verify.txt
    "manual_approval",   # Wey Shield staff manually confirms (enterprise)
]


class AuthGate:
    """
    Every scan must pass through here.
    Stores authorisation records so auditors can verify consent existed.
    """

    def __init__(self):
        self._pending: dict[str, AuthRecord] = {}  # in-memory before DB
        self._approved: dict[str, AuthRecord] = {}

    async def verify(
        self,
        client_id: str,
        targets: list[str],
        token: Optional[str] = None,
    ) -> AuthRecord:
        """
        Verify client is authorised to scan these targets.
        Returns AuthRecord — approved or denied.
        """
        # Check existing valid authorisation
        for target in targets:
            key = self._auth_key(client_id, target)
            if key in self._approved:
                record = self._approved[key]
                if record.expires_at > datetime.now(timezone.utc):
                    logger.info(f"✅ Existing auth found for {client_id} → {target}")
                    continue
                else:
                    logger.warning(f"⚠️  Auth expired for {client_id} → {target}")
                    del self._approved[key]
                    return AuthRecord(
                        id=str(uuid.uuid4()),
                        client_id=client_id,
                        targets=targets,
                        approved=False,
                        reason=f"Authorisation expired for target: {target}. Please re-verify.",
                        approved_at=None,
                        expires_at=None,
                    )

            # No existing auth — check if token was provided
            if token:
                verified = await self._verify_token(client_id, target, token)
                if verified:
                    record = self._create_auth_record(client_id, [target])
                    self._approved[key] = record
                    logger.info(f"✅ New auth granted for {client_id} → {target}")
                else:
                    return AuthRecord(
                        id=str(uuid.uuid4()),
                        client_id=client_id,
                        targets=[target],
                        approved=False,
                        reason=f"Token verification failed for target: {target}",
                        approved_at=None,
                        expires_at=None,
                    )
            else:
                # No auth, no token — deny and explain how to verify
                return AuthRecord(
                    id=str(uuid.uuid4()),
                    client_id=client_id,
                    targets=[target],
                    approved=False,
                    reason=(
                        f"No authorisation found for target: {target}. "
                        f"Verify ownership via: {', '.join(VERIFICATION_METHODS)}"
                    ),
                    approved_at=None,
                    expires_at=None,
                )

        # All targets cleared
        return self._create_auth_record(client_id, targets)

    async def initiate_verification(
        self,
        client_id: str,
        target: str,
        method: str = "dns_txt_record",
    ) -> dict:
        """
        Generate a verification challenge for the client.
        Returns instructions for proving ownership.
        """
        token = self._generate_token(client_id, target)

        instructions = {
            "dns_txt_record": {
                "method": "DNS TXT Record",
                "record_name": f"_weyshield-verify.{target}",
                "record_value": f"weyshield-verify={token}",
                "instructions": (
                    f"Add a TXT record to your DNS for {target}:\n"
                    f"  Name: _weyshield-verify\n"
                    f"  Value: weyshield-verify={token}\n"
                    "Then call /api/v1/auth/confirm to complete verification."
                ),
            },
            "http_file": {
                "method": "HTTP File",
                "url": f"https://{target}/.well-known/weyshield-verify.txt",
                "content": token,
                "instructions": (
                    f"Create a file at: {target}/.well-known/weyshield-verify.txt\n"
                    f"File content: {token}\n"
                    "Then call /api/v1/auth/confirm to complete verification."
                ),
            },
        }

        return {
            "token": token,
            "target": target,
            "method": method,
            "challenge": instructions.get(method, instructions["dns_txt_record"]),
            "expires_in_hours": 24,
        }

    async def _verify_token(
        self, client_id: str, target: str, token: str
    ) -> bool:
        """Verify a submitted token against what was issued."""
        expected = self._generate_token(client_id, target)
        return token == expected

    def _generate_token(self, client_id: str, target: str) -> str:
        raw = f"weyshield:{client_id}:{target}:secret_salt_replace_in_prod"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _auth_key(self, client_id: str, target: str) -> str:
        return f"{client_id}:{target}"

    def _create_auth_record(
        self, client_id: str, targets: list[str]
    ) -> AuthRecord:
        now = datetime.now(timezone.utc)
        return AuthRecord(
            id=str(uuid.uuid4()),
            client_id=client_id,
            targets=targets,
            approved=True,
            reason=None,
            approved_at=now,
            expires_at=now + timedelta(days=AUTH_TTL_DAYS),
        )
