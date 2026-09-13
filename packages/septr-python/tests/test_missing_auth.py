from septr.core.missing_auth import detect_missing_auth


class TestMissingAuth:
    def test_flags_api_route_without_auth(self):
        assert detect_missing_auth("/api/users", "GET", None) is not None

    def test_skips_with_bearer(self):
        assert detect_missing_auth("/api/users", "GET", "Bearer abc") is None

    def test_skips_public_route(self):
        assert detect_missing_auth("/health", "GET", None) is None

    def test_skips_fastapi_docs_surface(self):
        assert detect_missing_auth("/openapi.json", "GET", None) is None
        assert detect_missing_auth("/docs", "GET", None) is None
        assert detect_missing_auth("/redoc", "GET", None) is None

    def test_skips_options_preflight(self):
        assert detect_missing_auth("/api/users", "OPTIONS", None) is None

    def test_skips_head(self):
        assert detect_missing_auth("/api/users", "HEAD", None) is None

    def test_skips_static_assets(self):
        assert detect_missing_auth("/static/main.js", "GET", None) is None
        assert detect_missing_auth("/app.css", "GET", None) is None

    def test_skips_custom_public_routes(self):
        assert detect_missing_auth("/", "GET", None, ["/"]) is None
        assert detect_missing_auth("/api/v1/health", "GET", None, ["/api/v1/health"]) is None
        assert detect_missing_auth("/api/v1/health", "GET", None, ["/api/v1"]) is None
        assert detect_missing_auth("/api/private", "GET", None, ["/api/v1"]) is not None

    def test_exact_routes_match_only_that_path(self):
        assert detect_missing_auth("/", "GET", None, [], ["/"]) is None
        assert detect_missing_auth("/api/private", "GET", None, [], ["/"]) is not None
        assert detect_missing_auth("/track-record", "GET", None, [], ["/track-record"]) is None
        assert detect_missing_auth("/track-record/extra", "GET", None, [], ["/track-record"]) is not None

    def test_exact_routes_are_case_insensitive(self):
        assert detect_missing_auth("/Track-Record", "GET", None, [], ["/track-record"]) is None
        assert detect_missing_auth("/track-record", "GET", None, [], ["/TracK-Record"]) is None
