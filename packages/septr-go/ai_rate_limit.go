package septr

import (
	"regexp"
	"strings"
)

var aiRateLimitPatterns = []struct {
	id          string
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{id: "ai_rate_limit_429", pattern: regexp.MustCompile(`(?i)429.*too many requests|rate.?limit.*reached|rate.?limit.*exceed`), description: "AI service returned 429 Too Many Requests", severity: "high"},
	{id: "ai_rate_limit_quota", pattern: regexp.MustCompile(`(?i)exceeded your (?:current )?quota|quota.*exceed`), description: "AI service quota exhausted", severity: "critical"},
	{id: "ai_rate_limit_exhausted", pattern: regexp.MustCompile(`(?i)resource has been exhausted`), description: "AI service resource exhausted", severity: "critical"},
	{id: "ai_rate_limit_remaining_zero", pattern: regexp.MustCompile(`(?i)x-ratelimit-remaining.*[:\s]+0`), description: "AI service rate limit remaining is zero", severity: "high"},
	{id: "ai_rate_limit_insufficient_quota", pattern: regexp.MustCompile(`(?i)insufficient_quota`), description: "AI service returned insufficient quota error", severity: "critical"},
	{id: "ai_rate_limit_generic", pattern: regexp.MustCompile(`(?i)rate.?limit.*exceeded`), description: "AI rate limit exceeded", severity: "medium"},
}

// hasRateLimitHint is a cheap substring prefilter so the full pattern set only
// runs when the body could plausibly contain a rate-limit/quota message.
// Response bodies can be large app payloads; six regexes over every response
// is wasted work when none of the literal markers are present.
func hasRateLimitHint(body string) bool {
	lowered := strings.ToLower(body)
	return strings.Contains(lowered, "429") ||
		strings.Contains(lowered, "rate") ||
		strings.Contains(lowered, "quota")
}

func detectAIRateLimit(body string, route, method string) []DetectionEvent {
	var events []DetectionEvent
	for _, sp := range aiRateLimitPatterns {
		if sp.pattern.MatchString(body) {
			events = append(events, DetectionEvent{
				Type:        "ai_rate_limit",
				Severity:    sp.severity,
				PatternID:   sp.id,
				Description: sp.description,
				Route:       route,
				Method:      method,
				Timestamp:   nowMs(),
			})
		}
	}
	return events
}
