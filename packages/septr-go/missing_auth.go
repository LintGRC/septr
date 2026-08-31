package septr

import (
	"regexp"
	"strings"
)

var publicRoutePrefixes = []string{
	"/auth", "/login", "/register", "/signup", "/logout",
	"/health", "/__septr_ping", "/favicon.ico",
}

var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".map", ".webp", ".txt", ".xml",
}

var bearerPattern = regexp.MustCompile(`(?i)^Bearer\s+`)

func detectMissingAuth(path, method, authHeader string) *DetectionEvent {
	normalizedPath := strings.ToLower(path)
	upperMethod := strings.ToUpper(method)

	if upperMethod == "OPTIONS" || upperMethod == "HEAD" {
		return nil
	}

	for _, ext := range staticExtensions {
		if strings.HasSuffix(normalizedPath, ext) {
			return nil
		}
	}

	for _, prefix := range publicRoutePrefixes {
		if strings.HasPrefix(normalizedPath, prefix) {
			return nil
		}
	}

	if authHeader != "" && bearerPattern.MatchString(authHeader) {
		return nil
	}

	return &DetectionEvent{
		Type:        "missing_auth",
		Severity:    "high",
		PatternID:   "missing-auth-no-header",
		Description: "Route " + method + " " + path + " has no authentication — add middleware or a per-route auth guard",
		Route:       path,
		Method:      method,
		Timestamp:   nowMs(),
	}
}
