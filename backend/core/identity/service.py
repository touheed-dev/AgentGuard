from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


ISSUER = "agentguard-identity-manager"
AUDIENCE = "agentguard-gateway"


@dataclass(frozen=True)
class VerifiedToken:
    agent_id: str
    task_id: str
    capability_version: str
    scope: frozenset[str]
    security_epoch: int
    jti: str


class IdentityService:
    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
    ) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._issuer = issuer
        self._audience = audience

    def issue_token(
        self,
        agent_id: str,
        task_id: str,
        capability_version: str,
        scope: frozenset[str],
        security_epoch: int,
        lifetime_seconds: int = 60,
    ) -> str:
        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "sub": agent_id,
            "aud": self._audience,
            "task_id": task_id,
            "capability_version": capability_version,
            "scope": sorted(scope),
            "security_epoch": security_epoch,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=lifetime_seconds)).timestamp()),
            "jti": str(uuid4()),
        }
        return jwt.encode(claims, self._private_key, algorithm="EdDSA")

    def verify_token(self, token: str) -> VerifiedToken:
        claims = jwt.decode(
            token,
            self._private_key.public_key(),
            algorithms=["EdDSA"],
            issuer=self._issuer,
            audience=self._audience,
            options={"require": ["iss", "sub", "aud", "task_id", "capability_version", "scope", "security_epoch", "iat", "exp", "jti"]},
        )
        scope = claims["scope"]
        if not isinstance(scope, list) or not all(isinstance(value, str) for value in scope):
            raise jwt.InvalidTokenError("scope must be a list of strings")
        if not isinstance(claims["security_epoch"], int):
            raise jwt.InvalidTokenError("security_epoch must be an integer")
        return VerifiedToken(
            agent_id=claims["sub"],
            task_id=claims["task_id"],
            capability_version=claims["capability_version"],
            scope=frozenset(scope),
            security_epoch=claims["security_epoch"],
            jti=claims["jti"],
        )

    def export_private_key_for_test(self) -> bytes:
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
