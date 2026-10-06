from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_roles
from app.models.course import Course, CourseEnrollment
from app.models.record import AttendanceRecord, AttendanceRecordStatus
from app.models.session import AttendanceSession, AttendanceSessionStatus, QrToken
from app.models.user import User, UserRole
from app.schemas.attendance import AttendanceSubmitRequest, SessionEndRequest, SessionStartRequest
from app.services.geofence import verify_geofence
from app.services.qr_crypto import verify_qr_token
from app.services.session_manager import AttendanceSessionManager


router = APIRouter(prefix="/attendance", tags=["Attendance & QR"])


def _authorized_course(
    db: Session,
    course_id: UUID,
    current_user: User,
) -> Course:
    course = db.scalar(select(Course).where(Course.id == course_id))
    if course is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Course not found")
    if current_user.role == UserRole.TEACHER and course.instructor_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this course")
    return course


@router.post("/sessions/start", status_code=status.HTTP_201_CREATED)
def start_attendance_session(
    body: SessionStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["TEACHER", "ADMIN"])),
) -> dict[str, object]:
    course = _authorized_course(db, body.course_id, current_user)
    if not course.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Course is inactive")

    active_session = db.scalar(
        select(AttendanceSession).where(
            AttendanceSession.course_id == body.course_id,
            AttendanceSession.status == AttendanceSessionStatus.ACTIVE,
        )
    )
    if active_session is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An active session already exists for this course")

    session = AttendanceSession(
        course_id=body.course_id,
        instructor_id=current_user.id,
        session_secret=secrets.token_hex(32),
        start_time=datetime.now(timezone.utc),
        token_ttl_seconds=body.token_ttl_seconds,
        status=AttendanceSessionStatus.ACTIVE,
        geo_latitude=body.geo_latitude,
        geo_longitude=body.geo_longitude,
        geo_radius_meters=body.geo_radius_meters,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return {"session_id": session.id, "status": session.status.value}


@router.post("/sessions/{session_id}/end", status_code=status.HTTP_200_OK)
def end_attendance_session(
    session_id: UUID,
    body: SessionEndRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["TEACHER", "ADMIN"])),
) -> dict[str, str]:
    session = db.scalar(select(AttendanceSession).where(AttendanceSession.id == session_id))
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if current_user.role == UserRole.TEACHER and session.instructor_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this session")
    if session.status != AttendanceSessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session is not active")

    session.status = AttendanceSessionStatus.COMPLETED
    session.end_time = datetime.now(timezone.utc)
    db.commit()
    return {"message": "Attendance session ended", "status": session.status.value}


@router.get("/sessions/{session_id}/stream")
async def stream_dynamic_qr(
    session_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["TEACHER", "ADMIN"])),
) -> StreamingResponse:
    session = db.scalar(select(AttendanceSession).where(AttendanceSession.id == session_id))
    if session is None or session.status != AttendanceSessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active session not found")
    if current_user.role == UserRole.TEACHER and session.instructor_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this session")

    async def token_generator():
        manager = AttendanceSessionManager(db)
        async for event in manager.stream_tokens(session):
            yield event

    return StreamingResponse(token_generator(), media_type="text/event-stream")


@router.post("/submit", status_code=status.HTTP_201_CREATED)
def submit_attendance(
    body: AttendanceSubmitRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
) -> dict[str, str]:
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Student access required")

    session = db.scalar(select(AttendanceSession).where(AttendanceSession.id == body.session_id))
    if session is None or session.status != AttendanceSessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session is not currently active")

    enrollment = db.scalar(
        select(CourseEnrollment).where(
            CourseEnrollment.course_id == session.course_id,
            CourseEnrollment.student_id == current_user.id,
            CourseEnrollment.is_active.is_(True),
        )
    )
    if enrollment is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Student is not enrolled in this course")

    token_payload = {
        "sid": str(body.session_id),
        "tid": str(body.token_id),
        "iat": body.token_iat,
        "exp": body.token_exp,
        "sig": body.token_sig,
    }
    if not verify_qr_token(token_payload, session.session_secret):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired QR code token")

    now = datetime.now(timezone.utc)
    token_record = db.scalar(
        select(QrToken).where(
            QrToken.session_id == body.session_id,
            QrToken.token_nonce == str(body.token_id),
            QrToken.is_revoked.is_(False),
            QrToken.issued_at <= now,
            QrToken.expires_at >= now,
        )
    )
    if token_record is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="QR token is not active for this session")
    if token_record.issued_at.timestamp() != body.token_iat or token_record.expires_at.timestamp() != body.token_exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="QR token metadata does not match")

    if session.geo_latitude is not None and session.geo_longitude is not None:
        if body.latitude is None or body.longitude is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Geolocation is required for this session")
        if not verify_geofence(
            float(session.geo_latitude),
            float(session.geo_longitude),
            float(body.latitude),
            float(body.longitude),
            float(session.geo_radius_meters or 50.0),
        ):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Attendance submission outside allowable classroom radius")

    device_signature_hash = hashlib.sha256(f"{session.id}:{body.device_id}".encode("utf-8")).hexdigest()
    client_ip = request.client.host if request.client else "0.0.0.0"
    record = AttendanceRecord(
        session_id=session.id,
        student_id=current_user.id,
        qr_token_id=token_record.id,
        device_signature_hash=device_signature_hash,
        ip_address=client_ip,
        status=AttendanceRecordStatus.PRESENT,
    )
    try:
        db.add(record)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Duplicate check-in or device already registered for this session") from None

    return {"message": "Attendance successfully recorded", "status": "PRESENT"}
