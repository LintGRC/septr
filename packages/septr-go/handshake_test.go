package septr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendHandshake(t *testing.T) {
	var gotBody map[string]interface{}
	var gotAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/handshake" {
			t.Errorf("expected /handshake, got %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"connected","project":{"id":"p1","name":"Demo"}}`))
	}))
	defer server.Close()

	url := strings.TrimSuffix(server.URL, "/") + "/events"
	config := &Config{APIKey: "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab", TelemetryURL: url, framework: "gin"}

	if ok := sendHandshake(config, config.APIKey); !ok {
		t.Fatal("expected handshake to succeed")
	}
	if gotAuth != "Bearer "+config.APIKey {
		t.Errorf("expected bearer auth, got %q", gotAuth)
	}
	if gotBody["runtime"] != "gin" {
		t.Errorf("expected runtime gin, got %v", gotBody["runtime"])
	}
	if gotBody["package"] != "septr" {
		t.Errorf("expected package septr, got %v", gotBody["package"])
	}
	if gotBody["version"] != sdkVersion {
		t.Errorf("expected version %s, got %v", sdkVersion, gotBody["version"])
	}
}

func TestSendHandshakeRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"Invalid API key"}`))
	}))
	defer server.Close()

	config := &Config{APIKey: "bad", TelemetryURL: server.URL + "/events"}
	if ok := sendHandshake(config, config.APIKey); ok {
		t.Fatal("expected handshake to fail on 401")
	}
}

func TestSendHandshakeNoKey(t *testing.T) {
	config := &Config{}
	if ok := sendHandshake(config, ""); ok {
		t.Fatal("expected handshake to fail without a key")
	}
}

func TestHandshakeURL(t *testing.T) {
	cases := []struct {
		telemetryURL string
		want         string
	}{
		{"https://api.septr.com/v1/events", "https://api.septr.com/v1/handshake"},
		{"http://localhost:8000/v1/events", "http://localhost:8000/v1/handshake"},
		{"http://localhost:8000/events", "http://localhost:8000/handshake"},
		{"", "https://api.septr.com/v1/handshake"},
	}
	for _, c := range cases {
		config := &Config{TelemetryURL: c.telemetryURL}
		if got := handshakeURL(config); got != c.want {
			t.Errorf("handshakeURL(%q) = %q, want %q", c.telemetryURL, got, c.want)
		}
	}
}
