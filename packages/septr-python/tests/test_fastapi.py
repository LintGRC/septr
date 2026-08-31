import asyncio
import json

from septr.adapters.fastapi import SeptrASGIMiddleware
import septr.adapters.fastapi as mod


class OkApp:
    async def __call__(self, scope, receive, send):
        body = json.dumps({"ok": True}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": body})


BASE_CONFIG = {
    "secrets": False,
    "bola": False,
    "inputSanitize": False,
    "promptInjection": False,
    "ssrf": False,
    "missingAuth": False,
    "tamperDetection": False,
    "aiEndpointShield": False,
    "rateLimit": True,
    "selfTest": False,
    "telemetry": False,
}


def _run(middleware, method, path):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "server": ("127.0.0.1", 8000),
        "client": ("127.0.0.1", 12345),
        "scheme": "http",
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def drive():
        status = None

        async def send(msg):
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]

        await middleware(scope, receive, send)
        return status

    return asyncio.run(drive())


def _run_with_spy(middleware, method, path):
    events = []
    orig = mod.emit_event

    def spy(ev, cfg):
        events.append(ev)
        return orig(ev, cfg)

    mod.emit_event = spy
    try:
        status = _run(middleware, method, path)
    finally:
        mod.emit_event = orig
    return status, events


def test_auth_route_get_uses_general_limiter():
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "rateLimitConfig": {"max": 2, "windowMs": 60000},
    })

    assert _run(mw, "GET", "/auth/me") == 200
    assert _run(mw, "GET", "/auth/me") == 200
    # Session probes like GET /auth/me must not trip the strict 10/min auth
    # limiter — the general limiter (max 2 here) is the one that applies.
    assert _run(mw, "GET", "/auth/me") == 429


def test_auth_route_post_keeps_strict_auth_limiter():
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "rateLimitConfig": {"max": 100, "windowMs": 60000},
    })

    statuses = [_run(mw, "POST", "/auth/login") for _ in range(11)]
    assert statuses[:10] == [200] * 10
    assert statuses[10] == 429


def test_non_auth_get_still_rate_limited():
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "rateLimitConfig": {"max": 2, "windowMs": 60000},
    })

    assert _run(mw, "GET", "/api/data") == 200
    assert _run(mw, "GET", "/api/data") == 200
    assert _run(mw, "GET", "/api/data") == 429


def test_exclude_paths_passes_through_untouched():
    """Excluded prefixes skip every engine — no events, no rate limiting."""
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "missingAuth": True,
        "excludePaths": ["/api/auth"],
    })

    status, events = _run_with_spy(mw, "POST", "/api/auth/login")
    assert status == 200
    assert events == [], f"expected no events on excluded path, got {[e.type for e in events]}"

    # Even repeated traffic doesn't consume the rate limiter
    assert _run(mw, "POST", "/api/auth/login") == 200
    assert _run(mw, "POST", "/api/auth/login") == 200


def test_exclude_paths_only_skips_configured_prefixes():
    """Without the exclusion, the same route would be scanned."""
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "missingAuth": True,
    })

    _, events = _run_with_spy(mw, "POST", "/api/auth/login")
    assert "missing_auth" in [e.type for e in events]


def test_exclude_paths_does_not_affect_other_routes():
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "rateLimitConfig": {"max": 1, "windowMs": 60000},
        "excludePaths": ["/api/auth"],
    })

    assert _run(mw, "GET", "/api/data") == 200
    assert _run(mw, "GET", "/api/data") == 429


def test_missing_security_headers_reported():
    """Responses without CSP/HSTS/nosniff/etc. emit advisory events."""
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "excludePaths": ["/api/auth"],
    })

    _, events = _run_with_spy(mw, "GET", "/api/data")
    types = [e.type for e in events]
    assert "security_headers" in types
    missing = {e.description for e in events if e.type == "security_headers"}
    assert any("Content-Security-Policy" in d for d in missing)
    assert any("X-Frame-Options" in d for d in missing)


def test_excluded_paths_skip_header_checks():
    mw = SeptrASGIMiddleware(OkApp(), {
        **BASE_CONFIG,
        "excludePaths": ["/api/auth"],
    })

    _, events = _run_with_spy(mw, "GET", "/api/auth/login")
    assert all(e.type != "security_headers" for e in events)


def test_missing_auth_flags_only_existing_routes():
    """Missing-auth must not flag paths that map to no registered route (404s).

    A nonexistent route has nothing to protect, so flagging it is noise.
    Septr's own `GET /` (FastAPI returns 404 for it) is the canonical case."""
    from fastapi import FastAPI

    real_app = FastAPI()

    @real_app.get("/api/users")
    def users():
        return {"ok": True}

    @real_app.post("/api/login")
    def login():
        return {"ok": True}

    mw = SeptrASGIMiddleware(real_app, {
        **BASE_CONFIG,
        "missingAuth": True,
    })

    # Existing unauthenticated route → flagged.
    _, events = _run_with_spy(mw, "GET", "/api/users")
    assert "missing_auth" in [e.type for e in events]

    # Nonexistent route (would 404) → not flagged.
    _, events = _run_with_spy(mw, "GET", "/")
    assert all(e.type != "missing_auth" for e in events)
    _, events = _run_with_spy(mw, "GET", "/no/such/route")
    assert all(e.type != "missing_auth" for e in events)

    # Existing route returning 404 via the app still counts as existing.
    @real_app.get("/api/secret")
    def secret():
        from starlette.responses import JSONResponse
        return JSONResponse({"detail": "nope"}, status_code=404)

    _, events = _run_with_spy(mw, "GET", "/api/secret")
    assert "missing_auth" in [e.type for e in events]


def test_missing_auth_does_not_flag_method_with_no_registered_routes():
    """An app with zero routes for a method (e.g. no POST routes at all) must
    not flag POST probes to nonexistent paths — introspection succeeded and
    nothing is registered, so there's nothing to protect.

    Regression: _route_templates returned None for a method with no routes,
    which route_exists treated as 'cannot introspect' and fell back to the
    legacy flag-everything behavior — so POST /api/users /api/login /api/proxy
    probes re-created missing_auth incidents on GET-only apps."""
    from fastapi import FastAPI

    real_app = FastAPI()

    @real_app.get("/api/users")
    def users():
        return {"ok": True}

    mw = SeptrASGIMiddleware(real_app, {
        **BASE_CONFIG,
        "missingAuth": True,
    })

    # No POST routes registered → POST probe to nonexistent path is not flagged.
    for path in ("/api/users", "/api/login", "/api/proxy"):
        _, events = _run_with_spy(mw, "POST", path)
        assert all(e.type != "missing_auth" for e in events), f"POST {path} flagged"

    # GET to the real route is still flagged (it genuinely lacks auth).
    _, events = _run_with_spy(mw, "GET", "/api/users")
    assert "missing_auth" in [e.type for e in events]


class _InnerStyleMiddleware:
    """Middleware that stores its wrapped app as `.inner` (like Septr's own
    SecurityHeadersMiddleware) instead of `.app`."""

    def __init__(self, app):
        self.inner = app

    async def __call__(self, scope, receive, send):
        await self.inner(scope, receive, send)


def test_missing_auth_introspects_through_inner_style_middleware():
    """route_exists must walk through middleware chains whose wrappers store
    the inner app as `.inner` — otherwise the route table can't be found,
    every probe of a nonexistent route (e.g. /swagger, /api/users) gets
    flagged missing_auth, and scans drown in false positives."""
    from fastapi import FastAPI

    real_app = FastAPI()

    @real_app.get("/api/users")
    def users():
        return {"ok": True}

    wrapped = _InnerStyleMiddleware(real_app)
    mw = SeptrASGIMiddleware(wrapped, {
        **BASE_CONFIG,
        "missingAuth": True,
    })

    # Nonexistent routes behind an `.inner`-style wrapper → not flagged.
    for path in ("/", "/swagger", "/swagger.json", "/api/login", "/api/proxy"):
        _, events = _run_with_spy(mw, "GET", path)
        assert all(e.type != "missing_auth" for e in events), f"GET {path} flagged"

    # The real unauthenticated route is still flagged.
    _, events = _run_with_spy(mw, "GET", "/api/users")
    assert "missing_auth" in [e.type for e in events]


class _AuthEnforcedApp:
    """Simulates an app whose own middleware rejects unauthenticated requests
    with 401 — the route IS protected, so missing_auth must not fire."""

    def __init__(self, inner_app):
        self.inner_app = inner_app

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers") or [])
        if b"authorization" not in headers:
            body = b'{"detail": "unauthorized"}'
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return
        await self.inner_app(scope, receive, send)


def test_missing_auth_suppressed_when_app_enforces_auth():
    """A route that returns 401/403 to an unauthenticated probe is protected
    by the app itself — missing_auth must not flag it. Regression: the event
    was emitted before the response arrived, so protected-but-probed routes
    (e.g. POST /handshake) created false incidents on every scan."""
    from fastapi import FastAPI

    real_app = FastAPI()

    @real_app.post("/handshake")
    def handshake():
        return {"ok": True}

    mw = SeptrASGIMiddleware(_AuthEnforcedApp(real_app), {
        **BASE_CONFIG,
        "missingAuth": True,
    })

    # App rejects unauthenticated probe with 401 → no missing_auth event.
    status, events = _run_with_spy(mw, "POST", "/handshake")
    assert status == 401
    assert all(e.type != "missing_auth" for e in events)

    # Same probe again: still 401, still quiet (no spurious noise).
    status, events = _run_with_spy(mw, "POST", "/handshake")
    assert status == 401
    assert all(e.type != "missing_auth" for e in events)
