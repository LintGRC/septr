import re
import time
from .secrets import DetectionEvent

SSRF_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"127\.0\.0\.\d+"), "Loopback address (127.0.0.x)"),
    (re.compile(r"127\.0\.\d{1,3}\.\d{1,3}"), "Loopback range (127.x.x.x)"),
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "Private network (10.x.x.x)"),
    (re.compile(r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b"), "Private network (172.16-31.x.x)"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "Private network (192.168.x.x)"),
    (re.compile(r"\b0\.0\.0\.0\b"), "Unspecified address (0.0.0.0)"),
    (re.compile(r"\b169\.254\.169\.254\b"), "Cloud metadata endpoint (169.254.169.254)"),
    (re.compile(r"metadata\.google\.internal", re.IGNORECASE), "GCP metadata endpoint"),
    (re.compile(r"localhost", re.IGNORECASE), "localhost URL"),
    (re.compile(r"file:\/\/", re.IGNORECASE), "Local file access (file://)"),
    (re.compile(r"gopher:\/\/", re.IGNORECASE), "Gopher protocol (potential SSRF vector)"),
    (re.compile(r"192\.0\.2\.\d+"), "TEST-NET address (192.0.2.x)"),
    (re.compile(r"198\.51\.100\.\d+"), "TEST-NET-2 address (198.51.100.x)"),
    (re.compile(r"203\.0\.113\.\d+"), "TEST-NET-3 address (203.0.113.x)"),
]


def detect_ssrf(input_str: str) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    seen: set[str] = set()
    now = time.time() * 1000

    for regex, description in SSRF_PATTERNS:
        if regex.search(input_str):
            pattern_id = f"ssrf_{description.split(' ')[0].lower()}"
            if pattern_id not in seen:
                seen.add(pattern_id)
                severity = "critical" if ("metadata" in description.lower() or "cloud" in description.lower()) else "high"
                events.append(DetectionEvent(
                    type="ssrf",
                    severity=severity,
                    patternId=pattern_id,
                    description=description,
                    statusCode=200,
                    timestamp=now,
                ))

    return events
