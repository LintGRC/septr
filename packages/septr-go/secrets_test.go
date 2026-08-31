package septr

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDetectSecrets_OpenAI(t *testing.T) {
	result := detectSecrets("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
	if result[0].PatternID != "secret_openai" {
		t.Errorf("expected secret_openai, got %s", result[0].PatternID)
	}
}

func TestDetectSecrets_StripeLive(t *testing.T) {
	result := detectSecrets("sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSecrets_StripeTest(t *testing.T) {
	result := detectSecrets("sk_test_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
	if len(result[0].PatternID) == 0 {
		t.Error("expected patternId")
	}
}

func TestDetectSecrets_AWSKey(t *testing.T) {
	result := detectSecrets("AKIA" + "XXXXXXXXXXXXXXXX")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSecrets_JWT(t *testing.T) {
	result := detectSecrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSecrets_DatabaseURI(t *testing.T) {
	result := detectSecrets("postgres://user:password@localhost:5432/db")
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSecrets_SafeInput(t *testing.T) {
	result := detectSecrets("hello world this is safe")
	if len(result) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestDetectSecrets_CustomPatterns(t *testing.T) {
	result := detectSecrets("my-secret-token-12345", []string{"secret-token-\\d+"})
	if len(result) == 0 {
		t.Fatal("expected detection")
	}
	if result[0].PatternID != "secret_custom" {
		t.Errorf("expected secret_custom, got %s", result[0].PatternID)
	}
}

func TestShouldStripKey_Empty(t *testing.T) {
	if shouldStripKey("") {
		t.Error("expected false for empty key")
	}
}

func TestShouldStripKey_Password(t *testing.T) {
	if !shouldStripKey("password") {
		t.Error("expected true for password")
	}
}

func TestShouldStripKey_Normalized(t *testing.T) {
	if !shouldStripKey("my_password_hash") {
		t.Error("expected true for my_password_hash")
	}
}

func TestShouldStripKey_CaseInsensitive(t *testing.T) {
	if !shouldStripKey("API_KEY") {
		t.Error("expected true for API_KEY")
	}
}

func TestShouldStripKey_CustomFields(t *testing.T) {
	if !shouldStripKey("custom_secret_key", []string{"custom_secret"}) {
		t.Error("expected true with custom fields")
	}
}

func TestDetectSecrets_NewPatterns(t *testing.T) {
	cases := []struct {
		id    string
		input string
	}{
		{"secret_openai_svc", "sk-svcacct-abcdefghijklmnopqrstuvwxyz123456"},
		{"secret_github_fine_grained", "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"},
		{"secret_twilio", "SK0123456789abcdef" + "0123456789abcdef"},
		{"secret_slack_webhook", "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"},
		{"secret_shopify", "shpat_" + "0123456789abcdef0123456789abcdef"},
		{"secret_discord_bot", "M0gQ1w2E3r4T5y6U7i8O9p0a.abcdef.ABCDEFGHIJKLMNOPQRSTUVWXYZA"},
		{"secret_google_client_secret", "GOCSPX-abcdefghijklmnopqrstuvwxyz123456"},
	}
	for _, c := range cases {
		events := detectSecrets(c.input)
		found := false
		for _, e := range events {
			if e.PatternID == c.id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s for input %q", c.id, c.input)
		}
	}
}

func TestDetectSecrets_SupabaseServiceRole(t *testing.T) {
	header := base64URLEncode(`{"alg":"HS256"}`)
	svc := header + "." + base64URLEncode(`{"role":"service_role"}`) + ".signature"
	anon := header + "." + base64URLEncode(`{"role":"anon"}`) + ".signature"

	svcEvents := detectSecrets(svc)
	found := false
	for _, e := range svcEvents {
		if e.PatternID == "secret_supabase_service_role" {
			found = true
			if e.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", e.Severity)
			}
		}
	}
	if !found {
		t.Error("expected service_role detection")
	}

	for _, e := range detectSecrets(anon) {
		if e.PatternID == "secret_supabase_service_role" {
			t.Error("anon key must not be flagged as service_role")
		}
	}
}

func TestDetectHighEntropySecrets(t *testing.T) {
	events := DetectHighEntropySecrets(`{"apiKey": "x9F2kQ7vL3pZ8nB4cD6mW1rT"}`)
	if len(events) == 0 || events[0].PatternID != "secret_high_entropy" {
		t.Fatalf("expected entropy detection, got %v", events)
	}

	if len(DetectHighEntropySecrets(`{"token": "3f2a9c1e-8b4d-47e6-9a2f-1c3d5e7b8a9f"}`)) != 0 {
		t.Error("UUID-like values must not be flagged")
	}
	if len(DetectHighEntropySecrets(`{"token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)) != 0 {
		t.Error("low-entropy values must not be flagged")
	}
}

func TestStripEntropyDoesNotRedact(t *testing.T) {
	value := "x9F2kQ7vL3pZ8nB4cD6mW1rT"
	note := `{"apiKey": "` + value + `"}`
	cleaned, dets := stripSensitiveData(map[string]interface{}{"note": note})
	if cleaned.(map[string]interface{})["note"] != note {
		t.Error("entropy-only value must not be redacted")
	}
	hasEntropy := false
	for _, d := range dets {
		if d.PatternID == "secret_high_entropy" {
			hasEntropy = true
		}
	}
	if !hasEntropy {
		t.Error("expected entropy detection to be reported")
	}
}

func TestDetectSecrets_SupabaseAnon_AdvisoryOnly(t *testing.T) {
	header := base64URLEncode(`{"alg":"HS256"}`)
	anon := header + "." + base64URLEncode(`{"role":"anon"}`) + ".signature"
	events := detectSecrets(anon)

	foundAnon := false
	for _, e := range events {
		if e.PatternID == "secret_supabase_anon" {
			foundAnon = true
			if e.Severity != "low" {
				t.Errorf("expected low severity for anon, got %s", e.Severity)
			}
			if e.Redactable == nil || *e.Redactable {
				t.Error("supabase_anon must be non-redactable")
			}
		}
		if e.PatternID == "secret_generic_jwt" {
			t.Error("supabase anon JWT must not be flagged as generic_jwt")
		}
	}
	if !foundAnon {
		t.Error("expected supabase_anon detection")
	}
}

func TestDetectSecrets_GoogleAPI_AdvisoryOnly(t *testing.T) {
	events := detectSecrets("AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI")
	found := false
	for _, e := range events {
		if e.PatternID == "secret_google_api" {
			found = true
			if e.Severity != "low" {
				t.Errorf("expected low severity for google_api, got %s", e.Severity)
			}
			if e.Redactable == nil || *e.Redactable {
				t.Error("google_api must be non-redactable")
			}
		}
	}
	if !found {
		t.Error("expected google_api detection")
	}
}

func TestDetectSecrets_SupabaseServiceRole_NotAffected(t *testing.T) {
	header := base64URLEncode(`{"alg":"HS256"}`)
	svc := header + "." + base64URLEncode(`{"role":"service_role"}`) + ".signature"
	events := detectSecrets(svc)
	found := false
	for _, e := range events {
		if e.PatternID == "secret_supabase_service_role" {
			found = true
			if e.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", e.Severity)
			}
			if e.Redactable != nil && !*e.Redactable {
				t.Error("supabase_service_role must be redactable")
			}
		}
	}
	if !found {
		t.Error("expected supabase_service_role detection")
	}
}

func TestStrip_SupabaseAnon_NotRedacted(t *testing.T) {
	header := base64URLEncode(`{"alg":"HS256"}`)
	anon := header + "." + base64URLEncode(`{"role":"anon"}`) + ".signature"
	cleaned, _ := stripSensitiveData(map[string]interface{}{"data": anon})
	if cleaned.(map[string]interface{})["data"] != anon {
		t.Error("supabase anon key must not be redacted in strip")
	}
}

func TestDetectHighEntropy_PublishableKey(t *testing.T) {
	tests := []string{
		`{"apiKey": "pk_live_abc123def456ghi789"}`,
		`{"apiKey": "pk_test_abc123def456ghi789"}`,
		`{"apiKey": "pk_prod_abc123def456ghi789"}`,
		`{"apiKey": "pk.abc123def456ghi789jkl012mno"}`,
		`{"apiKey": "phc_abc123def456ghi789jkl012mno"}`,
		`{"apiKey": "phx_abc123def456ghi789jkl012mno"}`,
	}
	for _, input := range tests {
		if len(DetectHighEntropySecrets(input)) != 0 {
			t.Errorf("publishable key must not be flagged: %s", input)
		}
	}
}

func base64URLEncode(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	return strings.TrimRight(encoded, "=")
}
