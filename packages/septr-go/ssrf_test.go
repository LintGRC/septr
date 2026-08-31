package septr

import (
	"testing"
)

func TestDetectSSRF_Loopback(t *testing.T) {
	events := detectSSRF("http://127.0.0.1/admin")
	if len(events) == 0 {
		t.Fatal("expected SSRF detection for 127.0.0.1")
	}
	found := false
	for _, e := range events {
		if e.PatternID == "ssrf_loopback" {
			found = true
			if e.Severity != "high" {
				t.Errorf("expected severity high, got %s", e.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ssrf_loopback pattern")
	}
}

func TestDetectSSRF_CloudMetadata(t *testing.T) {
	events := detectSSRF("http://169.254.169.254/latest/meta-data/")
	if len(events) == 0 {
		t.Fatal("expected SSRF detection for cloud metadata endpoint")
	}
	found := false
	for _, e := range events {
		if e.PatternID == "ssrf_cloud_metadata" {
			found = true
			if e.Severity != "critical" {
				t.Errorf("expected severity critical, got %s", e.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ssrf_cloud_metadata pattern")
	}
}

func TestDetectSSRF_GCPMetadata(t *testing.T) {
	events := detectSSRF("metadata.google.internal/computeMetadata/v1/")
	if len(events) == 0 {
		t.Fatal("expected SSRF detection for GCP metadata endpoint")
	}
	found := false
	for _, e := range events {
		if e.PatternID == "ssrf_gcp_metadata" {
			found = true
		}
	}
	if !found {
		t.Error("expected ssrf_gcp_metadata pattern")
	}
}

func TestDetectSSRF_PrivateNetwork(t *testing.T) {
	tests := []string{
		"http://10.0.0.1/admin",
		"http://172.16.0.1/admin",
		"http://192.168.1.1/admin",
	}
	for _, input := range tests {
		events := detectSSRF(input)
		if len(events) == 0 {
			t.Errorf("expected SSRF detection for %s", input)
		}
	}
}

func TestDetectSSRF_FileProtocol(t *testing.T) {
	events := detectSSRF("file:///etc/passwd")
	if len(events) == 0 {
		t.Fatal("expected SSRF detection for file://")
	}
}

func TestDetectSSRF_Safe(t *testing.T) {
	events := detectSSRF("https://api.example.com/users")
	if len(events) > 0 {
		t.Errorf("expected no SSRF detection for safe URL, got %d events", len(events))
	}
}

func TestDetectSSRF_Dedup(t *testing.T) {
	events := detectSSRF("http://127.0.0.1/admin and 127.0.0.1/test")
	count := 0
	for _, e := range events {
		if e.PatternID == "ssrf_loopback" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected dedup, got %d loopback events", count)
	}
}
