import re
import base64
import json
import time
from typing import Optional
from .secrets import DetectionEvent


PARAM_PATTERNS = [
    re.compile(r"/:([a-zA-Z_][a-zA-Z0-9_]*)"),
    re.compile(r"/(\{[a-zA-Z_][a-zA-Z0-9_]*\})"),
    re.compile(r"/(\[[a-zA-Z_][a-zA-Z0-9_]*\])"),
    re.compile(r"/<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>"),
]

_PARAM_SEGMENT_PATTERNS = [
    re.compile(r"^:([a-zA-Z_][a-zA-Z0-9_]*)$"),
    re.compile(r"^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$"),
    re.compile(r"^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$"),
    re.compile(r"^<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>$"),
]

BODY_ID_FIELDS = [
    "userId", "user_id", "ownerId", "owner_id", "createdBy", "created_by",
    "accountId", "account_id", "customerId", "customer_id", "employeeId", "employee_id",
    "studentId", "student_id", "patientId", "patient_id", "memberId", "member_id",
]

TOKEN_CLAIMS = ["sub", "user_id", "userId", "id", "account_id", "owner_id"]


def extract_route_params(path: str) -> list[str]:
    params: list[str] = []
    for pattern in PARAM_PATTERNS:
        for match in pattern.finditer(path):
            param = match.group(1).replace("{", "").replace("}", "").replace("[", "").replace("]", "")
            params.append(param)
    return params


def _param_name(segment: str) -> Optional[str]:
    for pattern in _PARAM_SEGMENT_PATTERNS:
        match = pattern.match(segment)
        if match:
            return match.group(1)
    return None


def match_route_template(path: str, templates: list[str]) -> Optional[str]:
    """Find the route template (e.g. `/api/users/:userId` or `/api/users/{user_id}`)
    that structurally matches the concrete request path. Parameter segments match
    anything; static segments must match exactly."""
    path_segments = path.rstrip("/").split("/") or [""]
    for template in templates:
        t_segments = template.rstrip("/").split("/") or [""]
        if len(t_segments) != len(path_segments):
            continue
        matched = True
        for t_seg, p_seg in zip(t_segments, path_segments):
            if _param_name(t_seg) is not None:
                continue
            if t_seg != p_seg:
                matched = False
                break
        if matched:
            return template
    return None


def extract_route_param_values(template: str, path: str) -> dict[str, str]:
    """Extract the actual values of dynamic route params from a concrete path,
    using the route template to locate them. Returns {param_name: value}."""
    values: dict[str, str] = {}
    t_segments = template.rstrip("/").split("/") or [""]
    p_segments = path.rstrip("/").split("/") or [""]
    if len(t_segments) != len(p_segments):
        return values
    for t_seg, p_seg in zip(t_segments, p_segments):
        name = _param_name(t_seg)
        if name is not None:
            values[name] = p_seg
    return values


def _base64url_decode(text: str) -> str:
    b64 = text.replace("-", "+").replace("_", "/")
    padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
    return base64.b64decode(padded).decode("utf-8", errors="replace")


def extract_token_claims(token: str) -> dict[str, str]:
    claims: dict[str, str] = {}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return claims
        payload = json.loads(_base64url_decode(parts[1]))
        for key, value in payload.items():
            if value is None:
                continue
            claims[key] = str(value)
    except Exception:
        pass
    return claims


def detect_bola(
    route_params: list[str],
    body_params: Optional[dict[str, str]],
    token_claims: dict[str, str],
    route: Optional[str] = None,
    method: Optional[str] = None,
    route_param_values: Optional[dict[str, str]] = None,
) -> Optional[DetectionEvent]:
    token_user_id = (
        token_claims.get("sub") or token_claims.get("user_id") or
        token_claims.get("userId") or token_claims.get("id") or
        token_claims.get("account_id") or token_claims.get("owner_id")
    )
    if not token_user_id:
        return None

    if route_param_values:
        for param, value in route_param_values.items():
            if param in BODY_ID_FIELDS and value != token_user_id:
                return DetectionEvent(
                    type="bola", severity="high",
                    patternId="bola_param_mismatch",
                    description=f"Route param `{param}={value}` does not match authenticated user `{token_user_id}`",
                    route=route, method=method,
                    timestamp=time.time() * 1000,
                )

    for param in route_params:
        if param in BODY_ID_FIELDS and (not route_param_values or param not in route_param_values):
            return DetectionEvent(
                type="bola", severity="high",
                patternId="bola_param_mismatch",
                description=f"Route param `{param}` may be manipulable",
                route=route, method=method,
                 timestamp=time.time() * 1000,
            )

    if body_params:
        for field in BODY_ID_FIELDS:
            if field in body_params and body_params[field] != token_user_id:
                return DetectionEvent(
                    type="bola", severity="critical",
                    patternId="bola_body_mismatch",
                    description=f"Body field `{field}` does not match authenticated user",
                    route=route, method=method,
                    timestamp=time.time() * 1000,
                )

    return None
