package septr

import (
	"testing"
)

func TestDetectMissingAuth_NoHeader(t *testing.T) {
	ev := detectMissingAuth("/api/users", "GET", "")
	if ev == nil {
		t.Fatal("expected missing auth detection on unprotected route")
	}
	if ev.PatternID != "missing-auth-no-header" {
		t.Errorf("expected missing-auth-no-header, got %s", ev.PatternID)
	}
}

func TestDetectMissingAuth_WithBearer(t *testing.T) {
	ev := detectMissingAuth("/api/users", "GET", "Bearer token123")
	if ev != nil {
		t.Error("expected no detection when Bearer token present")
	}
}

func TestDetectMissingAuth_PublicRoutes(t *testing.T) {
	routes := []string{"/auth/signup", "/login", "/register", "/health", "/__septr_ping", "/favicon.ico"}
	for _, route := range routes {
		ev := detectMissingAuth(route, "GET", "")
		if ev != nil {
			t.Errorf("expected no detection on public route %s, got event", route)
		}
	}
}

func TestDetectMissingAuth_PublicRoutePrefix(t *testing.T) {
	ev := detectMissingAuth("/auth/callback", "POST", "")
	if ev != nil {
		t.Error("expected no detection on /auth/* path")
	}
}

func TestDetectMissingAuth_UnauthenticatedAdmin(t *testing.T) {
	ev := detectMissingAuth("/api/admin/users", "DELETE", "")
	if ev == nil {
		t.Fatal("expected missing auth detection on admin route without auth")
	}
	if ev.Severity != "high" {
		t.Errorf("expected severity high, got %s", ev.Severity)
	}
}

func TestMissingAuthSkipsOptionsPreflight(t *testing.T) {
	if ev := detectMissingAuth("/api/users", "OPTIONS", ""); ev != nil {
		t.Fatal("OPTIONS preflight should not be flagged")
	}
}

func TestMissingAuthSkipsHead(t *testing.T) {
	if ev := detectMissingAuth("/api/users", "HEAD", ""); ev != nil {
		t.Fatal("HEAD should not be flagged")
	}
}

func TestMissingAuthSkipsStaticAssets(t *testing.T) {
	if ev := detectMissingAuth("/static/main.js", "GET", ""); ev != nil {
		t.Fatal("static asset should not be flagged")
	}
}

func TestMissingAuthStillFlagsApiRoute(t *testing.T) {
	if ev := detectMissingAuth("/api/users", "GET", ""); ev == nil {
		t.Fatal("API route without auth should be flagged")
	}
}
