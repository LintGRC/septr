import re
from typing import Optional
from .secrets import DetectionEvent

PATTERNS: list[dict] = [
    {
        "regex": re.compile(r"429.*too many requests|rate.?limit.*reached|rate.?limit.*exceed", re.I),
        "severity": "high",
        "patternId": "ai_rate_limit_429",
        "description": "AI service returned 429 Too Many Requests",
    },
    {
        "regex": re.compile(r"exceeded your (current )?quota|quota.*exceed", re.I),
        "severity": "critical",
        "patternId": "ai_rate_limit_quota",
        "description": "AI service quota exhausted",
    },
    {
        "regex": re.compile(r"resource has been exhausted", re.I),
        "severity": "critical",
        "patternId": "ai_rate_limit_exhausted",
        "description": "AI service resource exhausted",
    },
    {
        "regex": re.compile(r"x-ratelimit-remaining.*[:\s]+0", re.I),
        "severity": "high",
        "patternId": "ai_rate_limit_remaining_zero",
        "description": "AI service rate limit remaining is zero",
    },
    {
        "regex": re.compile(r"insufficient_quota", re.I),
        "severity": "critical",
        "patternId": "ai_rate_limit_insufficient_quota",
        "description": "AI service returned insufficient quota error",
    },
    {
        "regex": re.compile(r"rate.?limit.*exceeded", re.I),
        "severity": "medium",
        "patternId": "ai_rate_limit_generic",
        "description": "AI rate limit exceeded",
    },
]


def detect_ai_rate_limit(
    body: str,
    route: Optional[str] = None,
    method: Optional[str] = None,
) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    for p in PATTERNS:
        if p["regex"].search(body):
            events.append(DetectionEvent(
                type="ai_rate_limit",
                severity=p["severity"],
                patternId=p["patternId"],
                description=p["description"],
                route=route,
                method=method,
                timestamp=__import__("time").time() * 1000,
            ))
    return events
