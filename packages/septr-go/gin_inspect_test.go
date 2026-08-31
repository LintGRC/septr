//go:build !nogin

package septr

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGinInspectWriter_StripsSecretFromResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretsOn := true
	cfg := &Config{APIKey: "vs_test_key", Secrets: &secretsOn, StripFields: []string{"api_key"}, TelemetryURL: "false"}
	// Telemetry disabled, so events buffer in a manager but never post.
	m := NewGin(cfg)
	r.Use(m.Handler())
	r.GET("/secret", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"api_key": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "name": "John"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Septr-Stripped") == "" {
		t.Fatal("expected X-Septr-Stripped header after response stripping")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("sk_live_")) {
		t.Fatal("secret still present in response body")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("John")) {
		t.Fatal("non-secret fields must be preserved")
	}
}

func TestGinInspectWriter_PassthroughOnPlainJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretsOn := true
	cfg := &Config{APIKey: "vs_test_key", Secrets: &secretsOn, StripFields: []string{"api_key"}, TelemetryURL: "false"}
	m := NewGin(cfg)
	r.Use(m.Handler())
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": "John"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Septr-Stripped") != "" {
		t.Fatal("no stripping expected for safe body")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("John")) {
		t.Fatal("body must pass through unchanged")
	}
}
