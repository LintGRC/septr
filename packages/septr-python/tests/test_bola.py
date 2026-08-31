import pytest
from septr.core.bola import extract_route_params, extract_token_claims, detect_bola, match_route_template, extract_route_param_values


class TestExtractRouteParams:
    def test_extracts_express_params(self):
        params = extract_route_params("/api/users/:userId/orders/:orderId")
        assert "userId" in params
        assert "orderId" in params

    def test_extracts_hono_params(self):
        params = extract_route_params("/api/users/:userId")
        assert "userId" in params

    def test_extracts_flask_params(self):
        params = extract_route_params("/api/users/<user_id>")
        assert "user_id" in params

    def test_extracts_flask_converter_params(self):
        params = extract_route_params("/api/users/<int:user_id>")
        assert "user_id" in params

    def test_empty_for_static_routes(self):
        params = extract_route_params("/api/health")
        assert params == []


class TestMatchRouteTemplate:
    def test_matches_concrete_path_to_template(self):
        assert match_route_template("/api/users/999", ["/api/users/:userId"]) == "/api/users/:userId"
        assert match_route_template("/api/users/999", ["/api/users/{user_id}"]) == "/api/users/{user_id}"
        assert match_route_template("/api/users/999", ["/api/users/<user_id>"]) == "/api/users/<user_id>"

    def test_no_match_on_different_structure(self):
        assert match_route_template("/api/users/999/orders", ["/api/users/:userId"]) is None
        assert match_route_template("/api/health", ["/api/users/:userId"]) is None
        assert match_route_template("/api/items/books", ["/api/users/:userId", "/api/orders/:orderId"]) is None

    def test_picks_first_matching_template(self):
        templates = ["/api/users/:userId", "/api/:resource/:id"]
        assert match_route_template("/api/users/999", templates) == "/api/users/:userId"


class TestExtractRouteParamValues:
    def test_extracts_values_from_concrete_path(self):
        assert extract_route_param_values("/api/users/:userId", "/api/users/999") == {"userId": "999"}
        assert extract_route_param_values("/api/users/{user_id}", "/api/users/999") == {"user_id": "999"}

    def test_empty_for_mismatched_lengths(self):
        assert extract_route_param_values("/api/users/:userId", "/api/users") == {}


class TestExtractTokenClaims:
    def test_extracts_claims_from_valid_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcl9pZCI6IjU2NyIsImlkIjoiODkwIn0.signature"
        claims = extract_token_claims(token)
        assert claims.get("sub") == "1234567890"
        assert claims.get("user_id") == "567"
        assert claims.get("id") == "890"

    def test_empty_for_invalid_token(self):
        claims = extract_token_claims("not-a-token")
        assert claims == {}

    def test_empty_for_empty_token(self):
        assert extract_token_claims("") == {}


class TestDetectBOLA:
    def test_detects_bola_from_route_params(self):
        result = detect_bola(["userId"], None, {"sub": "user_123"}, "/api/users/:userId", "GET")
        assert result is not None
        assert result.type == "bola"
        assert result.patternId == "bola_param_mismatch"

    def test_detects_bola_from_body_fields(self):
        result = detect_bola([], {"userId": "user_456"}, {"sub": "user_123"}, "/api/users", "POST")
        assert result is not None
        assert result.type == "bola"
        assert result.patternId == "bola_body_mismatch"

    def test_returns_none_when_token_matches(self):
        result = detect_bola(["user_123"], None, {"sub": "user_123"}, "/api/users/:userId", "GET")
        assert result is None

    def test_returns_none_when_no_token(self):
        result = detect_bola(["userId"], None, {}, "/api/users/:userId", "GET")
        assert result is None

    def test_returns_none_for_non_id_params(self):
        result = detect_bola(["99"], None, {"sub": "42"}, "/api/users/:userId", "GET")
        assert result is None

    def test_flags_param_value_mismatch(self):
        result = detect_bola(
            ["userId"], None, {"sub": "42"}, "/api/users/:userId", "GET",
            route_param_values={"userId": "999"},
        )
        assert result is not None
        assert result.type == "bola"
        assert result.patternId == "bola_param_mismatch"
        assert "999" in result.description

    def test_passes_when_param_value_matches_token(self):
        result = detect_bola(
            ["userId"], None, {"sub": "42"}, "/api/users/:userId", "GET",
            route_param_values={"userId": "42"},
        )
        assert result is None

    def test_ignores_values_of_non_id_params(self):
        result = detect_bola(
            ["category"], None, {"sub": "42"}, "/api/items/:category", "GET",
            route_param_values={"category": "books"},
        )
        assert result is None


if __name__ == "__main__":
    pytest.main()
