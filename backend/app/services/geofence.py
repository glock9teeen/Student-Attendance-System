from __future__ import annotations

import math


EARTH_RADIUS_METERS = 6_371_000.0


def verify_geofence(
    session_lat: float,
    session_lng: float,
    student_lat: float,
    student_lng: float,
    allowed_radius_meters: float = 50.0,
) -> bool:
    """Return whether a student's location is within the classroom radius."""
    if allowed_radius_meters < 0:
        return False
    if not all(math.isfinite(value) for value in (session_lat, session_lng, student_lat, student_lng)):
        return False
    if not (-90.0 <= student_lat <= 90.0 and -180.0 <= student_lng <= 180.0):
        return False
    if not (-90.0 <= session_lat <= 90.0 and -180.0 <= session_lng <= 180.0):
        return False

    phi1 = math.radians(session_lat)
    phi2 = math.radians(student_lat)
    delta_phi = math.radians(student_lat - session_lat)
    delta_lambda = math.radians(student_lng - session_lng)
    haversine = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    central_angle = 2.0 * math.atan2(
        math.sqrt(haversine),
        math.sqrt(max(0.0, 1.0 - haversine)),
    )
    distance = EARTH_RADIUS_METERS * central_angle
    return distance <= allowed_radius_meters
