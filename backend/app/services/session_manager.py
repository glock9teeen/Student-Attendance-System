from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncIterator
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.session import AttendanceSession, AttendanceSessionStatus, QrToken
from app.services.qr_crypto import generate_qr_payload


class AttendanceSessionManager:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_active_session(self, session_id: UUID) -> AttendanceSession | None:
        return self.db.scalar(
            select(AttendanceSession).where(
                AttendanceSession.id == session_id,
                AttendanceSession.status == AttendanceSessionStatus.ACTIVE,
            )
        )

    def end_session(self, session_id: UUID) -> AttendanceSession | None:
        session = self.get_active_session(session_id)
        if session is None:
            return None
        session.status = AttendanceSessionStatus.COMPLETED
        session.end_time = datetime.now(timezone.utc)
        self.db.add(session)
        return session

    async def stream_tokens(self, session: AttendanceSession) -> AsyncIterator[str]:
        while self.get_active_session(session.id) is not None:
            payload = generate_qr_payload(
                session_id=str(session.id),
                session_secret=session.session_secret,
                ttl_seconds=session.token_ttl_seconds,
            )
            token = QrToken(
                session_id=session.id,
                token_nonce=payload["tid"],
                issued_at=datetime.fromtimestamp(payload["iat"], timezone.utc),
                expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc),
                is_revoked=False,
            )
            self.db.add(token)
            self.db.flush()
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(session.token_ttl_seconds)
