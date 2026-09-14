package septr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestKillSwitch(t *testing.T) {
	t.Setenv("SEPTR_DISABLED", "true")
	if !killSwitchEngaged() {
		t.Fatal("expected kill switch engaged")
	}
	t.Setenv("SEPTR_DISABLED", "0")
	if killSwitchEngaged() {
		t.Fatal("expected kill switch disengaged")
	}
}

func TestEngineGuard_CatchesPanics(t *testing.T) {
	g := NewEngineGuard(nil)
	got := Guarded(g, "e", "def", func() string { panic("boom") })
	if got != "def" {
		t.Fatalf("expected default after panic, got %q", got)
	}
	if g.IsOpen("e") {
		t.Fatal("breaker must not open on first failure")
	}
}

func TestEngineGuard_OpensAfterThreshold(t *testing.T) {
	reported := 0
	g := NewEngineGuard(func(engine, reason string) { reported++ })
	for i := 0; i < defaultEngineFailureThreshold; i++ {
		Guarded(g, "e", 0, func() int { panic("boom") })
	}
	if !g.IsOpen("e") {
		t.Fatal("expected breaker open after threshold")
	}

	ran := false
	Guarded(g, "e", 0, func() int { ran = true; return 1 })
	if ran {
		t.Fatal("open engine must be skipped")
	}
	if reported != 1 {
		t.Fatalf("expected exactly one degraded report, got %d", reported)
	}
}

func TestEngineGuard_IsolatedPerEngine(t *testing.T) {
	g := NewEngineGuard(nil)
	Guarded(g, "a", 0, func() int { panic("boom") })
	Guarded(g, "a", 0, func() int { panic("boom") })
	Guarded(g, "a", 0, func() int { panic("boom") })
	if !g.IsOpen("a") {
		t.Fatal("expected a open")
	}
	if g.IsOpen("b") {
		t.Fatal("b must be unaffected")
	}
	if got := Guarded(g, "b", 0, func() int { return 7 }); got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
}

func TestGin_KillSwitchBypassesEngines(t *testing.T) {
	t.Setenv("SEPTR_DISABLED", "true")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	secretsOn := true
	cfg := &Config{
		APIKey:       "vs_test_key",
		Secrets:      &secretsOn,
		RateLimit:    boolPtr(false),
		TelemetryURL: "false",
	}
	m := NewGin(cfg)
	r.Use(m.Handler())
	r.GET("/secret", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"api_key": "vs_test_key_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"})
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/secret", nil))

	if w.Header().Get("X-Septr-Stripped") != "" {
		t.Fatal("kill switch must bypass stripping")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("vs_test_key_")) {
		t.Fatal("body must pass through untouched")
	}
}

func TestGin_LargeRequestNotInspected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	sanitizeOn := true
	secretsOff := false
	cfg := &Config{
		APIKey:                 "vs_test_key",
		InputSanitize:          &sanitizeOn,
		Secrets:                &secretsOff,
		RateLimit:              boolPtr(false),
		StrictMode:             true,
		MaxRequestInspectBytes: 64,
		TelemetryURL:           "false",
	}
	m := NewGin(cfg)
	r.Use(m.Handler())
	r.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, body)
	})

	filler := strings.Repeat("x", 256)
	payload := `{"q":"1' OR '1'='1","filler":"` + filler + `"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("oversized body must pass through untouched, got %d", w.Code)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("app body missing: %v", err)
	}
	if got["filler"] != filler {
		t.Fatal("app must receive the full request body")
	}
}

func TestNetHTTP_KillSwitchBypassesEngines(t *testing.T) {
	t.Setenv("SEPTR_DISABLED", "true")
	secretsOn := true
	m := NewNetHTTP(&Config{
		APIKey:    "vs_test_key",
		Secrets:   &secretsOn,
		RateLimit: boolPtr(false),
	})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"api_key":"vs_test_key_redacted"}`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secret", nil))

	if rec.Header().Get("X-Septr-Stripped") != "" {
		t.Fatal("kill switch must bypass stripping")
	}
	if !strings.Contains(rec.Body.String(), "vs_test_key_") {
		t.Fatal("body must pass through untouched")
	}
}

func TestNetHTTP_LargeResponseStreamsThrough(t *testing.T) {
	secretsOn := true
	m := NewNetHTTP(&Config{
		APIKey:               "vs_test_key",
		Secrets:              &secretsOn,
		RateLimit:            boolPtr(false),
		MaxResponseScanBytes: 256,
	})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"api_key":"vs_test_key_redacted","filler":"` + strings.Repeat("x", 1024) + `"}`))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/big", nil))

	if rec.Header().Get("X-Septr-Stripped") != "" {
		t.Fatal("oversized response must not be scanned")
	}
	if !strings.Contains(rec.Body.String(), "vs_test_key_") {
		t.Fatal("oversized response must stream through untouched")
	}
	if rec.Body.Len() <= 256 {
		t.Fatalf("expected full body streamed, got %d bytes", rec.Body.Len())
	}
}

func TestTelemetry_EmitDoesNotBlock(t *testing.T) {
	cfg := &Config{APIKey: "vs_test_key", TelemetryURL: "http://127.0.0.1:1"}
	m := NewTelemetryManager(cfg, "proj-1")
	defer m.Destroy()

	start := time.Now()
	for i := 0; i < maxBatchSize*3; i++ {
		m.Emit(DetectionEvent{Type: "secrets", Severity: "high", Description: "x"})
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("Emit blocked the request path for %s", elapsed)
	}
}
