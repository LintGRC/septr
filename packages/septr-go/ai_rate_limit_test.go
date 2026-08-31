package septr

import (
	"testing"
)

func TestDetectAIRateLimit_429(t *testing.T) {
	events := detectAIRateLimit("429 Too Many Requests", "", "")
	if len(events) == 0 {
		t.Fatal("expected AI rate limit 429 detection")
	}
}

func TestDetectAIRateLimit_QuotaExceeded(t *testing.T) {
	events := detectAIRateLimit(`{"error": "exceeded your current quota"}`, "", "")
	if len(events) == 0 {
		t.Fatal("expected quota exceeded detection")
	}
	if events[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", events[0].Severity)
	}
}

func TestDetectAIRateLimit_ResourceExhausted(t *testing.T) {
	events := detectAIRateLimit("resource has been exhausted", "", "")
	if len(events) == 0 {
		t.Fatal("expected resource exhausted detection")
	}
}

func TestDetectAIRateLimit_InsufficientQuota(t *testing.T) {
	events := detectAIRateLimit(`{"error": {"code": "insufficient_quota"}}`, "", "")
	if len(events) == 0 {
		t.Fatal("expected insufficient_quota detection")
	}
}

func TestDetectAIRateLimit_MultipleMatches(t *testing.T) {
	body := `{"error": "rate limit exceeded", "message": "429 Too Many Requests"}`
	events := detectAIRateLimit(body, "/api/chat", "POST")
	if len(events) < 2 {
		t.Errorf("expected at least 2 events, got %d", len(events))
	}
	for _, e := range events {
		if e.Route != "/api/chat" {
			t.Errorf("expected route /api/chat, got %s", e.Route)
		}
		if e.Method != "POST" {
			t.Errorf("expected method POST, got %s", e.Method)
		}
	}
}

func TestDetectAIRateLimit_SafeResponse(t *testing.T) {
	events := detectAIRateLimit(`{"id": "chatcmpl-123", "choices": [{"message": {"content": "Hello!"}}]}`, "", "")
	if len(events) > 0 {
		t.Errorf("expected no detection on normal response, got %d", len(events))
	}
}
