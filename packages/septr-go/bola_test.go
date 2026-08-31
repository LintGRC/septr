package septr

import "testing"

func TestExtractRouteParams_Express(t *testing.T) {
	p := extractRouteParams("/api/users/:userId/orders/:orderId")
	if len(p) < 2 || p[0] != "userId" || p[1] != "orderId" {
		t.Fatalf("expected userId,orderId got %v", p)
	}
}

func TestExtractRouteParams_Static(t *testing.T) {
	if len(extractRouteParams("/api/health")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestTokenClaims_Valid(t *testing.T) {
	c := extractTokenClaims("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcl9pZCI6IjU2NyIsImlkIjoiODkwIn0.signature")
	if c["sub"] != "1234567890" || c["user_id"] != "567" || c["id"] != "890" {
		t.Fatalf("unexpected claims: %v", c)
	}
}

func TestTokenClaims_Invalid(t *testing.T) {
	if len(extractTokenClaims("not-a-token")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestDetectBOLA_RouteParams(t *testing.T) {
	ev := detectBOLA([]string{"userId"}, nil, map[string]string{"sub": "user_123"}, "/api/users/:userId", "GET", nil)
	if ev == nil || ev.PatternID != "bola_param_mismatch" {
		t.Fatal("expected bola_param_mismatch")
	}
}

func TestDetectBOLA_BodyFields(t *testing.T) {
	ev := detectBOLA(nil, map[string]string{"userId": "user_456"}, map[string]string{"sub": "user_123"}, "/api/users", "POST", nil)
	if ev == nil || ev.PatternID != "bola_body_mismatch" {
		t.Fatal("expected bola_body_mismatch")
	}
}

func TestDetectBOLA_NoToken(t *testing.T) {
	ev := detectBOLA([]string{"userId"}, nil, map[string]string{}, "/api/users/:userId", "GET", nil)
	if ev != nil {
		t.Fatal("expected nil when no token")
	}
}

func TestDetectBOLA_NonIDParam(t *testing.T) {
	ev := detectBOLA([]string{"99"}, nil, map[string]string{"sub": "42"}, "/api/users/:userId", "GET", nil)
	if ev != nil {
		t.Fatal("expected nil for non-ID param")
	}
}

func TestMatchRouteTemplate(t *testing.T) {
	if got := MatchRouteTemplate("/api/users/999", []string{"/api/users/:userId"}); got != "/api/users/:userId" {
		t.Fatalf("expected template match, got %q", got)
	}
	if got := MatchRouteTemplate("/api/users/999", []string{"/api/users/{user_id}"}); got != "/api/users/{user_id}" {
		t.Fatalf("expected braces template match, got %q", got)
	}
	if got := MatchRouteTemplate("/api/users/999/orders", []string{"/api/users/:userId"}); got != "" {
		t.Fatalf("expected no match, got %q", got)
	}
	if got := MatchRouteTemplate("/api/health", []string{"/api/users/:userId"}); got != "" {
		t.Fatalf("expected no match for static path, got %q", got)
	}
}

func TestExtractRouteParamValues(t *testing.T) {
	values := ExtractRouteParamValues("/api/users/:userId", "/api/users/999")
	if values["userId"] != "999" {
		t.Fatalf("expected userId=999, got %v", values)
	}
	if len(ExtractRouteParamValues("/api/users/:userId", "/api/users")) != 0 {
		t.Fatal("expected empty for mismatched lengths")
	}
}

func TestDetectBOLA_ParamValueMismatch(t *testing.T) {
	ev := detectBOLA([]string{"userId"}, nil, map[string]string{"sub": "42"}, "/api/users/:userId", "GET", map[string]string{"userId": "999"})
	if ev == nil || ev.PatternID != "bola_param_mismatch" {
		t.Fatal("expected bola_param_mismatch on value mismatch")
	}
}

func TestDetectBOLA_ParamValueMatch(t *testing.T) {
	ev := detectBOLA([]string{"userId"}, nil, map[string]string{"sub": "42"}, "/api/users/:userId", "GET", map[string]string{"userId": "42"})
	if ev != nil {
		t.Fatal("expected nil when param value matches token")
	}
}

func TestDetectBOLA_NonIDParamValue(t *testing.T) {
	ev := detectBOLA([]string{"category"}, nil, map[string]string{"sub": "42"}, "/api/items/:category", "GET", map[string]string{"category": "books"})
	if ev != nil {
		t.Fatal("expected nil for non-ID param values")
	}
}
