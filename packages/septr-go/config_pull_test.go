package septr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteConfigEnabled(t *testing.T) {
	t.Setenv("SEPTR_REMOTE_CONFIG", "")
	if (&Config{APIKey: "x"}).RemoteConfigEnabled() != true {
		t.Fatal("expected enabled with apiKey")
	}
	if (&Config{APIKey: "x", RemoteConfig: boolPtr(false)}).RemoteConfigEnabled() {
		t.Fatal("expected disabled when RemoteConfig=false")
	}
	if (&Config{}).RemoteConfigEnabled() {
		t.Fatal("expected disabled without apiKey")
	}
}


func TestProjectIDFromKey(t *testing.T) {
	pid := projectIDFromKey("septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab")
	if pid != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("unexpected pid: %q", pid)
	}
	if projectIDFromKey("vs_live_deadbeef") != "" {
		t.Fatal("legacy key should not parse")
	}
}

func TestFetchRemoteConfigAndApply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+VALID_V2_KEY {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"config": map[string]interface{}{
				"strictMode": true,
				"bola":       false,
				"secrets":    true,
			},
		})
	}))
	defer srv.Close()

	cfg := &Config{
		APIKey:       VALID_V2_KEY,
		TelemetryURL: srv.URL + "/events",
	}
	remote := FetchRemoteConfig(cfg)
	if remote == nil {
		t.Fatal("expected remote config")
	}
	ApplyRemoteConfig(cfg, remote)

	if !cfg.StrictMode {
		t.Fatal("strictMode should be true after apply")
	}
	if cfg.BOLA == nil || *cfg.BOLA != false {
		t.Fatal("bola should be false after apply")
	}
	if cfg.Secrets == nil || *cfg.Secrets != true {
		t.Fatal("secrets should stay true after apply")
	}
}

func TestFetchRemoteConfigFailure(t *testing.T) {
	cfg := &Config{APIKey: VALID_V2_KEY, TelemetryURL: "http://127.0.0.1:1/events"}
	if remote := FetchRemoteConfig(cfg); remote != nil {
		t.Fatal("expected nil on unreachable backend")
	}
}

func TestApplyRemoteConfigIgnoresNonRuntimeKeys(t *testing.T) {
	cfg := &Config{APIKey: "k", StrictMode: false}
	ApplyRemoteConfig(cfg, map[string]interface{}{
		"apiKey":       "evil",
		"telemetryUrl": "http://evil",
		"strictMode":   true,
	})
	if cfg.APIKey != "k" {
		t.Fatal("apiKey must not be clobbered")
	}
	if cfg.TelemetryURL != "" {
		t.Fatal("telemetryUrl must not be clobbered")
	}
	if !cfg.StrictMode {
		t.Fatal("strictMode should be applied")
	}
}

func TestStartConfigPollingAppliesAndTick(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		strict := calls == 1
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"config": map[string]interface{}{"strictMode": strict},
		})
	}))
	defer srv.Close()

	cfg := &Config{
		APIKey:       VALID_V2_KEY,
		TelemetryURL: srv.URL + "/events",
		ConfigPollMs: 30,
	}
	StartConfigPolling(cfg)
	defer StopConfigPolling()

	if !cfg.StrictModeLocked() {
		t.Fatal("first fetch should apply strictMode=true")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cfg.mu.RLock()
		val := cfg.StrictMode
		cfg.mu.RUnlock()
		if !val {
			return // tick applied strictMode=false
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected next tick to flip strictMode to false")
}

func TestStartConfigPollingDisabled(t *testing.T) {
	cfg := &Config{APIKey: "x", RemoteConfig: boolPtr(false)}
	StartConfigPolling(cfg)
	StopConfigPolling()
}

const VALID_V2_KEY = "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab"
