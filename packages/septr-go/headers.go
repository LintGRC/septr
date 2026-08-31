package septr

import (
	"net/http"
)

var securityHeaderChecks = []struct {
	name        string
	description string
	severity    string
}{
	{"Content-Security-Policy", "Content-Security-Policy header missing", "medium"},
	{"Strict-Transport-Security", "Strict-Transport-Security (HSTS) header missing", "medium"},
	{"X-Content-Type-Options", "X-Content-Type-Options header missing", "medium"},
	{"X-Frame-Options", "X-Frame-Options header missing", "medium"},
	{"Referrer-Policy", "Referrer-Policy header missing", "low"},
}

// DetectMissingSecurityHeaders reports responses missing standard security
// headers. Advisory only — Septr never injects headers.
func DetectMissingSecurityHeaders(h http.Header) []DetectionEvent {
	present := map[string]bool{}
	for name := range h {
		present[lowerName(name)] = true
	}
	var events []DetectionEvent
	for _, c := range securityHeaderChecks {
		if !present[lowerName(c.name)] {
			events = append(events, DetectionEvent{
				Type: "security_headers", Severity: c.severity,
				PatternID: "missing_security_header", Description: c.description,
				StatusCode: 200, Timestamp: nowMs(),
			})
		}
	}
	return events
}

func lowerName(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
