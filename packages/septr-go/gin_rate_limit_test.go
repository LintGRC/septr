//go:build !nogin

package septr

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGin_AuthRouteGetUsesGeneralLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := NewGin(&Config{
		RateLimit:      boolPtr(true),
		RateLimitConfig: &RateLimitConfig{Max: 2, WindowMs: 60000},
	})
	r := gin.New()
	r.Use(m.Handler())
	r.GET("/auth/me", func(c *gin.Context) { c.Status(http.StatusOK) })

	ts := httptest.NewServer(r)
	defer ts.Close()

	for i := 0; i < 2; i++ {
		if status := netHTTPStatus(t, ts.URL+"/auth/me", "GET"); status != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, status)
		}
	}
	if status := netHTTPStatus(t, ts.URL+"/auth/me", "GET"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd GET /auth/me, got %d", status)
	}
}

func TestGin_AuthRoutePostKeepsStrictAuthLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := NewGin(&Config{
		RateLimit:      boolPtr(true),
		RateLimitConfig: &RateLimitConfig{Max: 100, WindowMs: 60000},
	})
	r := gin.New()
	r.Use(m.Handler())
	r.POST("/auth/login", func(c *gin.Context) { c.Status(http.StatusOK) })

	ts := httptest.NewServer(r)
	defer ts.Close()

	for i := 0; i < 10; i++ {
		if status := netHTTPStatus(t, ts.URL+"/auth/login", "POST"); status != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, status)
		}
	}
	if status := netHTTPStatus(t, ts.URL+"/auth/login", "POST"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 11th POST /auth/login, got %d", status)
	}
}
