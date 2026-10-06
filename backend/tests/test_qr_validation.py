import hashlib
import hmac
import time
import uuid

from app.services.geofence import verify_geofence
from app.services.qr_crypto import generate_qr_payload, verify_qr_token


def test_generate_qr_payload_has_valid_signature() -> None:
    session_id = str(uuid.uuid4())
    session_secret = "test-session-secret"

    payload = generate_qr_payload(session_id, session_secret, ttl_seconds=15)

    assert payload["ver"] == "1.0"
    assert payload["sid"] == session_id
    assert payload["sig"] == hmac.new(
        session_secret.encode("utf-8"),
        f"{payload['sid']}:{payload['tid']}:{payload['iat']}:{payload['exp']}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert verify_qr_token(payload, session_secret)


def test_verify_qr_token_rejects_expired_token() -> None:
    now = int(time.time())
    payload = {
        "ver": "1.0",
        "sid": str(uuid.uuid4()),
        "tid": str(uuid.uuid4()),
        "iat": now - 30,
        "exp": now - 20,
        "sig": hmac.new(
            b"test-session-secret",
            f"{now - 30}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest(),
    }
    payload["sig"] = hmac.new(
        b"test-session-secret",
        f"{payload['sid']}:{payload['tid']}:{payload['iat']}:{payload['exp']}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert not verify_qr_token(payload, "test-session-secret")


def test_verify_qr_token_rejects_tampered_signature() -> None:
    payload = generate_qr_payload(str(uuid.uuid4()), "test-session-secret")
    payload["sig"] = "0" * 64

    assert not verify_qr_token(payload, "test-session-secret")


def test_verify_geofence_accepts_points_within_radius() -> None:
    assert verify_geofence(40.0, -83.0, 40.0, -83.0001, allowed_radius_meters=50)


def test_verify_geofence_rejects_points_outside_radius() -> None:
    assert not verify_geofence(40.0, -83.0, 40.0, -83.01, allowed_radius_meters=50)
