package septr

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func netHTTPStatus(t *testing.T, url, method string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-forwarded-for", "1.2.3.4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestNetHTTP_AuthRouteGetUsesGeneralLimiter(t *testing.T) {
	m := NewNetHTTP(&Config{
		RateLimit:      boolPtr(true),
		RateLimitConfig: &RateLimitConfig{Max: 2, WindowMs: 60000},
	})
	ts := httptest.NewServer(m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	for i := 0; i < 2; i++ {
		if status := netHTTPStatus(t, ts.URL+"/auth/me", "GET"); status != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, status)
		}
	}
	// GET /auth/me is a session probe — the general limiter (max 2) applies,
	// not the strict 10/min auth limiter.
	if status := netHTTPStatus(t, ts.URL+"/auth/me", "GET"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd GET /auth/me, got %d", status)
	}
}

func TestNetHTTP_AuthRoutePostKeepsStrictAuthLimiter(t *testing.T) {
	m := NewNetHTTP(&Config{
		RateLimit:      boolPtr(true),
		RateLimitConfig: &RateLimitConfig{Max: 100, WindowMs: 60000},
	})
	ts := httptest.NewServer(m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	for i := 0; i < 10; i++ {
		if status := netHTTPStatus(t, ts.URL+"/auth/login", "POST"); status != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, status)
		}
	}
	// Credential-submitting POSTs keep the strict 10/min auth limiter.
	if status := netHTTPStatus(t, ts.URL+"/auth/login", "POST"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 11th POST /auth/login, got %d", status)
	}
}
