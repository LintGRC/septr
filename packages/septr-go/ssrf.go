package septr

import (
	"regexp"
)

var ssrfPatterns = []struct {
	id          string
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{id: "ssrf_loopback", pattern: regexp.MustCompile(`127\.0\.0\.\d+`), description: "Loopback address (127.0.0.x)", severity: "high"},
	{id: "ssrf_loopback_range", pattern: regexp.MustCompile(`127\.0\.\d{1,3}\.\d{1,3}`), description: "Loopback range (127.x.x.x)", severity: "high"},
	{id: "ssrf_private_10", pattern: regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), description: "Private network (10.x.x.x)", severity: "high"},
	{id: "ssrf_private_172", pattern: regexp.MustCompile(`\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b`), description: "Private network (172.16-31.x.x)", severity: "high"},
	{id: "ssrf_private_192", pattern: regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`), description: "Private network (192.168.x.x)", severity: "high"},
	{id: "ssrf_unspecified", pattern: regexp.MustCompile(`\b0\.0\.0\.0\b`), description: "Unspecified address (0.0.0.0)", severity: "high"},
	{id: "ssrf_cloud_metadata", pattern: regexp.MustCompile(`\b169\.254\.169\.254\b`), description: "Cloud metadata endpoint (169.254.169.254)", severity: "critical"},
	{id: "ssrf_gcp_metadata", pattern: regexp.MustCompile(`(?i)metadata\.google\.internal`), description: "GCP metadata endpoint", severity: "critical"},
	{id: "ssrf_localhost", pattern: regexp.MustCompile(`(?i)localhost`), description: "localhost URL", severity: "high"},
	{id: "ssrf_file_proto", pattern: regexp.MustCompile(`(?i)file:\/\/`), description: "Local file access (file://)", severity: "high"},
	{id: "ssrf_gopher", pattern: regexp.MustCompile(`(?i)gopher:\/\/`), description: "Gopher protocol (potential SSRF vector)", severity: "high"},
	{id: "ssrf_test_net", pattern: regexp.MustCompile(`192\.0\.2\.\d+`), description: "TEST-NET address (192.0.2.x)", severity: "high"},
	{id: "ssrf_test_net2", pattern: regexp.MustCompile(`198\.51\.100\.\d+`), description: "TEST-NET-2 address (198.51.100.x)", severity: "high"},
	{id: "ssrf_test_net3", pattern: regexp.MustCompile(`203\.0\.113\.\d+`), description: "TEST-NET-3 address (203.0.113.x)", severity: "high"},
}

func detectSSRF(input string) []DetectionEvent {
	seen := make(map[string]bool)
	var events []DetectionEvent
	for _, sp := range ssrfPatterns {
		if sp.pattern.MatchString(input) {
			if !seen[sp.id] {
				seen[sp.id] = true
				events = append(events, DetectionEvent{
					Type:        "ssrf",
					Severity:    sp.severity,
					PatternID:   sp.id,
					Description: sp.description,
					Timestamp:   nowMs(),
				})
			}
		}
	}
	return events
}
