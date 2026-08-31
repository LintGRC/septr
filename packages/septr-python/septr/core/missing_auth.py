import re
import time
from typing import Optional
from .secrets import DetectionEvent

PUBLIC_ROUTES = [
    "/auth", "/login", "/register", "/signup", "/logout",
    "/health", "/__septr_ping", "/favicon.ico",
    # FastAPI/Starlette public surface (OpenAPI docs are public by design)
    "/openapi.json", "/docs", "/redoc",
]

SKIP_METHODS = {"OPTIONS", "HEAD"}

_STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".txt", ".xml",
)


def detect_missing_auth(
    path: str,
    method: str,
    auth_header: Optional[str] = None,
) -> Optional[DetectionEvent]:
    normalized_path = path.lower()

    if method.upper() in SKIP_METHODS:
        return None

    if normalized_path.endswith(_STATIC_EXTENSIONS):
        return None

    for public_route in PUBLIC_ROUTES:
        if normalized_path.startswith(public_route):
            return None

    if auth_header and re.search(r"^Bearer\s+", auth_header, re.IGNORECASE):
        return None

    return DetectionEvent(
        type="missing_auth",
        severity="high",
        patternId="missing-auth-no-header",
        description=f"Route {method} {path} has no authentication — add middleware or a per-route auth guard",
        route=path,
        method=method,
        timestamp=time.time() * 1000,
    )
