from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any


QR_TOKEN_VERSION = "1.0"


def generate_qr_payload(session_id: str, session_secret: str, ttl_seconds: int = 15) -> dict[str, Any]:
    """Generate an ephemeral, HMAC-signed QR token payload."""
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    now = int(time.time())
    token_id = str(uuid.uuid4())
    expires_at = now + ttl_seconds
    message = f"{session_id}:{token_id}:{now}:{expires_at}".encode("utf-8")
    signature = hmac.new(session_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

    return {
        "ver": QR_TOKEN_VERSION,
        "sid": session_id,
        "tid": token_id,
        "iat": now,
        "exp": expires_at,
        "sig": signature,
    }


def verify_qr_token(
    payload: dict[str, Any],
    session_secret: str,
    allowed_drift: int = 2,
) -> bool:
    """Verify the token signature and validity window."""
    try:
        now = int(time.time())
        exp = int(payload["exp"])
        iat = int(payload["iat"])
        sid = str(payload["sid"])
        tid = str(payload["tid"])
        provided_sig = str(payload["sig"])

        if allowed_drift < 0:
            return False
        if now > exp + allowed_drift:
            return False
        if iat > now + allowed_drift:
            return False

        message = f"{sid}:{tid}:{iat}:{exp}".encode("utf-8")
        expected_sig = hmac.new(session_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, provided_sig)
    except (KeyError, ValueError, TypeError):
        return False
