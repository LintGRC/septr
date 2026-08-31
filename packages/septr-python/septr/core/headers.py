"""Advisory security-header checks for runtime responses.

Reports responses missing standard security headers (CSP, HSTS, nosniff,
clickjacking, referrer). Detection-only — Septr never injects headers, since
values like CSP are app-specific and wrong guesses break apps.
"""

import time
from .secrets import DetectionEvent

SECURITY_HEADER_CHECKS: list[tuple[str, str, str]] = [
    ("Content-Security-Policy", "Content-Security-Policy header missing", "medium"),
    ("Strict-Transport-Security", "Strict-Transport-Security (HSTS) header missing", "medium"),
    ("X-Content-Type-Options", "X-Content-Type-Options header missing", "medium"),
    ("X-Frame-Options", "X-Frame-Options header missing", "medium"),
    ("Referrer-Policy", "Referrer-Policy header missing", "low"),
]


def detect_missing_security_headers(headers: list[tuple[bytes, bytes]]) -> list[DetectionEvent]:
    """Given raw response headers (bytes pairs), report the missing ones."""
    present = {
        key.decode("utf-8", "replace").lower()
        for key, _ in headers
    }
    events: list[DetectionEvent] = []
    for name, description, severity in SECURITY_HEADER_CHECKS:
        if name.lower() not in present:
            events.append(DetectionEvent(
                type="security_headers", severity=severity,
                patternId="missing_security_header",
                description=description,
                statusCode=200, timestamp=time.time() * 1000,
            ))
    return events
