package septr

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

type secretPattern struct {
	id          string
	pattern     *regexp.Regexp
	description string
	severity    string
	verify      func(string) bool
	redactable  bool
}

var secretPatterns = []secretPattern{
	{id: "openai", pattern: regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`), description: "OpenAI API key", severity: "high", redactable: true},
	{id: "openai_legacy", pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}`), description: "OpenAI legacy key", severity: "high", redactable: true},
	{id: "openai_svc", pattern: regexp.MustCompile(`sk-svcacct-[A-Za-z0-9_-]{20,}`), description: "OpenAI service account key", severity: "high", redactable: true},
	{id: "openai_admin", pattern: regexp.MustCompile(`sk-admin-[A-Za-z0-9_-]{20,}`), description: "OpenAI admin key", severity: "critical", redactable: true},
	{id: "anthropic", pattern: regexp.MustCompile(`sk-ant-api03-[A-Za-z0-9_-]{20,}`), description: "Anthropic API key", severity: "high", redactable: true},
	{id: "stripe_live", pattern: regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`), description: "Stripe live secret key", severity: "high", redactable: true},
	{id: "stripe_test", pattern: regexp.MustCompile(`sk_test_[A-Za-z0-9]{20,}`), description: "Stripe test secret key", severity: "medium", redactable: true},
	{id: "stripe_restricted", pattern: regexp.MustCompile(`rk_live_[A-Za-z0-9]{20,}`), description: "Stripe restricted key", severity: "high", redactable: true},
	{id: "aws_access", pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), description: "AWS access key ID", severity: "high", redactable: true},
	{id: "aws_session", pattern: regexp.MustCompile(`ASIA[0-9A-Z]{16}`), description: "AWS session token key ID", severity: "high", redactable: true},
	{id: "aws_secret", pattern: regexp.MustCompile(`[A-Za-z0-9/+]{40}`), description: "AWS secret access key", severity: "high", verify: awsSecretLike, redactable: true},
	{id: "github_pat", pattern: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), description: "GitHub personal access token", severity: "high", redactable: true},
	{id: "github_fine_grained", pattern: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), description: "GitHub fine-grained token", severity: "high", redactable: true},
	{id: "github_oauth", pattern: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), description: "GitHub OAuth token", severity: "high", redactable: true},
	{id: "github_app", pattern: regexp.MustCompile(`(?:ghu|ghs)_[A-Za-z0-9]{36}`), description: "GitHub app token", severity: "high", redactable: true},
	{id: "slack_bot", pattern: regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`), description: "Slack bot token", severity: "high", redactable: true},
	{id: "slack_user", pattern: regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`), description: "Slack user token", severity: "high", redactable: true},
	{id: "slack_webhook", pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}`), description: "Slack webhook URL", severity: "high", redactable: true},
	{id: "google_api", pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), description: "Google API key", severity: "low", redactable: false},
	{id: "google_client_secret", pattern: regexp.MustCompile(`GOCSPX-[A-Za-z0-9_-]{20,}`), description: "Google OAuth client secret", severity: "high", redactable: true},
	{id: "sendgrid", pattern: regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`), description: "SendGrid API key", severity: "high", redactable: true},
	{id: "twilio", pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), description: "Twilio API key", severity: "high", redactable: true},
	{id: "shopify", pattern: regexp.MustCompile(`sh(?:pat|pss)_[0-9a-fA-F]{32}`), description: "Shopify access token", severity: "high", redactable: true},
	{id: "mailchimp", pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), description: "Mailchimp API key", severity: "medium", redactable: true},
	{id: "discord_bot", pattern: regexp.MustCompile(`[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`), description: "Discord bot token", severity: "high", redactable: true},
	{id: "azure_storage", pattern: regexp.MustCompile(`AccountKey=[A-Za-z0-9+/=]{88}`), description: "Azure Storage account key", severity: "high", redactable: true},
	{id: "npm_token", pattern: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), description: "npm access token", severity: "high", redactable: true},
	{id: "supabase_service_role", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`), description: "Supabase service_role key", severity: "critical", verify: jwtHasRole("service_role"), redactable: true},
	{id: "supabase_anon", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`), description: "Supabase anon key (public)", severity: "low", verify: jwtHasRole("anon"), redactable: false},
	{id: "generic_jwt", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`), description: "JWT token", severity: "medium", verify: notSupabaseAnon, redactable: true},
	{id: "private_key", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----`), description: "Private key", severity: "critical", redactable: true},
	{id: "database_uri", pattern: regexp.MustCompile(`(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s]+:[^\s]+@[^\s]+`), description: "Database URI with credentials", severity: "high", redactable: true},
}

func awsSecretLike(text string) bool {
	if len(text) != 40 {
		return false
	}
	upper, lower, digits := 0, 0, 0
	for _, c := range text {
		if c >= 'A' && c <= 'Z' {
			upper++
		} else if c >= 'a' && c <= 'z' {
			lower++
		} else if c >= '0' && c <= '9' {
			digits++
		}
	}
	return upper >= 4 && lower >= 4 && digits >= 1
}

func jwtHasRole(role string) func(string) bool {
	return func(token string) bool {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return false
		}
		decoded := base64URLDecode(parts[1])
		if decoded == "" {
			return false
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(decoded), &payload); err != nil {
			return false
		}
		return payload["role"] == role
	}
}

var supabaseAnonCheck = jwtHasRole("anon")

func notSupabaseAnon(token string) bool {
	return !supabaseAnonCheck(token)
}

var publishablePrefixes = []string{
	"pk_live_", "pk_test_", "pk_prod_", "pk.",
	"phc_", "phx_",
}

func isPublishableKey(value string) bool {
	for _, prefix := range publishablePrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

var defaultSensitiveKeys = []string{
	"password", "password_hash", "passwordHash", "secret", "secret_key", "secretKey",
	"api_key", "apiKey", "private_key", "privateKey", "stripe_secret", "stripeSecret",
	"ssn", "credit_card", "creditCard", "token", "access_token", "accessToken",
	"refresh_token", "refreshToken", "authorization",
}

func detectSecrets(input string, customPatterns ...[]string) []DetectionEvent {
	var events []DetectionEvent
	for _, sp := range secretPatterns {
		matches := sp.pattern.FindAllString(input, -1)
		for _, m := range matches {
			if sp.verify != nil && !sp.verify(m) {
				continue
			}
			var redactable *bool
			if !sp.redactable {
				v := false
				redactable = &v
			}
			events = append(events, DetectionEvent{
				Type: "secret_exposure", Severity: sp.severity,
				PatternID: "secret_" + sp.id, Description: sp.description,
				StatusCode: 200, Timestamp: nowMs(),
				Redactable: redactable,
			})
		}
	}
	if len(customPatterns) > 0 {
		for _, ps := range customPatterns[0] {
			if re, err := regexp.Compile(ps); err == nil {
				for range re.FindAllString(input, -1) {
					events = append(events, DetectionEvent{
						Type: "secret_exposure", Severity: "high",
						PatternID: "secret_custom", Description: "Custom pattern match detected",
						StatusCode: 200, Timestamp: nowMs(),
					})
				}
			}
		}
	}
	return events
}

// ── keyword + entropy detection (advisory, telemetry only) ──

var entropyAssignRe = regexp.MustCompile(`["']?(?:apiKey|api_key|apiSecret|api_secret|secret|secretKey|secret_key|clientSecret|client_secret|token|accessToken|access_token|refreshToken|refresh_token|password|privateKey|private_key|bearerToken|authToken)["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']`)
var pureHexDashRe = regexp.MustCompile(`^[0-9a-fA-F\-]+$`)

const entropyThreshold = 3.5

func charClasses(value string) int {
	classes := 0
	if regexp.MustCompile(`[a-z]`).MatchString(value) {
		classes++
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(value) {
		classes++
	}
	if regexp.MustCompile(`[0-9]`).MatchString(value) {
		classes++
	}
	if regexp.MustCompile(`[+/=_.-]`).MatchString(value) {
		classes++
	}
	return classes
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range value {
		counts[c]++
	}
	n := float64(len(value))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func matchesSpecificPattern(value string) bool {
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// DetectHighEntropySecrets reports high-entropy values assigned to secret-like
// keys. Advisory only — never used for redaction.
func DetectHighEntropySecrets(input string) []DetectionEvent {
	var events []DetectionEvent
	for _, m := range entropyAssignRe.FindAllStringSubmatch(input, -1) {
		if len(m) < 2 {
			continue
		}
		value := m[1]
		if len(value) > 128 || charClasses(value) < 3 || pureHexDashRe.MatchString(value) || matchesSpecificPattern(value) || isPublishableKey(value) {
			continue
		}
		if shannonEntropy(value) < entropyThreshold {
			continue
		}
		events = append(events, DetectionEvent{
			Type: "secret_exposure", Severity: "medium",
			PatternID: "secret_high_entropy",
			Description: "High-entropy value assigned to a secret-like key (possible API key or token)",
			StatusCode: 200, Timestamp: nowMs(),
		})
	}
	return events
}

func shouldStripKey(key string, customFields ...[]string) bool {
	if key == "" {
		return false
	}
	normalized := stripKeyNormalize(key)
	allSensitive := defaultSensitiveKeys
	if len(customFields) > 0 {
		allSensitive = append(allSensitive, customFields[0]...)
	}
	for _, field := range allSensitive {
		nf := stripKeyNormalize(field)
		if contains(normalized, nf) || contains(nf, normalized) {
			return true
		}
	}
	return false
}

func stripKeyNormalize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b = append(b, c+32)
		} else if c != '_' && c != '-' {
			b = append(b, c)
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(substr) <= len(s) && (len(substr) == 0 || searchString(s, substr))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
