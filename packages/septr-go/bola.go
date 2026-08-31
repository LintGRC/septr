package septr

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

var paramPatterns = []string{
	`/:([a-zA-Z_][a-zA-Z0-9_]*)`,
	`/(\{[a-zA-Z_][a-zA-Z0-9_]*\})`,
	`/(\[[a-zA-Z_][a-zA-Z0-9_]*\])`,
	`/<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>`,
}

var paramSegmentPatterns = []string{
	`^:([a-zA-Z_][a-zA-Z0-9_]*)$`,
	`^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$`,
	`^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$`,
	`^<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>$`,
}

var bodyIDFields = []string{
	"userId", "user_id", "ownerId", "owner_id", "createdBy", "created_by",
	"accountId", "account_id", "customerId", "customer_id", "employeeId", "employee_id",
	"studentId", "student_id", "patientId", "patient_id", "memberId", "member_id",
}

var tokenClaims = []string{"sub", "user_id", "userId", "id", "account_id", "owner_id"}

func extractRouteParams(path string) []string {
	var params []string
	for _, ps := range paramPatterns {
		re := regexp.MustCompile(ps)
		matches := re.FindAllStringSubmatch(path, -1)
		for _, m := range matches {
			if len(m) > 1 {
				param := strings.Trim(m[1], "{}[]")
				params = append(params, param)
			}
		}
	}
	return params
}

func paramName(segment string) string {
	for _, ps := range paramSegmentPatterns {
		re := regexp.MustCompile(ps)
		m := re.FindStringSubmatch(segment)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func splitPath(path string) []string {
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

// MatchRouteTemplate finds the route template (e.g. `/api/users/:userId`) that
// structurally matches the concrete request path. Parameter segments match
// anything; static segments must match exactly.
func MatchRouteTemplate(path string, templates []string) string {
	pathSegments := splitPath(path)
	for _, template := range templates {
		tSegments := splitPath(template)
		if len(tSegments) != len(pathSegments) {
			continue
		}
		matched := true
		for i, tSeg := range tSegments {
			if paramName(tSeg) != "" {
				continue
			}
			if tSeg != pathSegments[i] {
				matched = false
				break
			}
		}
		if matched {
			return template
		}
	}
	return ""
}

// ExtractRouteParamValues extracts the actual values of dynamic route params
// from a concrete path using the route template. Returns {param_name: value}.
func ExtractRouteParamValues(template string, path string) map[string]string {
	values := map[string]string{}
	tSegments := splitPath(template)
	pSegments := splitPath(path)
	if len(tSegments) != len(pSegments) {
		return values
	}
	for i, tSeg := range tSegments {
		name := paramName(tSeg)
		if name != "" {
			values[name] = pSegments[i]
		}
	}
	return values
}

func base64URLDecode(s string) string {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func extractTokenClaims(token string) map[string]string {
	claims := make(map[string]string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims
	}
	decoded := base64URLDecode(parts[1])
	if decoded == "" {
		return claims
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &payload); err != nil {
		return claims
	}
	for key, val := range payload {
		if val != nil {
			claims[key] = toString(val)
		}
	}
	return claims
}

func detectBOLA(routeParams []string, bodyParams map[string]string, tokenClaims map[string]string, route string, method string, routeParamValues map[string]string) *DetectionEvent {
	tokenUserID := tokenClaims["sub"]
	if tokenUserID == "" {
		tokenUserID = tokenClaims["user_id"]
	}
	if tokenUserID == "" {
		tokenUserID = tokenClaims["userId"]
	}
	if tokenUserID == "" {
		tokenUserID = tokenClaims["id"]
	}
	if tokenUserID == "" {
		tokenUserID = tokenClaims["account_id"]
	}
	if tokenUserID == "" {
		tokenUserID = tokenClaims["owner_id"]
	}
	if tokenUserID == "" {
		return nil
	}

	for param, value := range routeParamValues {
		for _, field := range bodyIDFields {
			if param == field && value != tokenUserID {
				return &DetectionEvent{
					Type: "bola", Severity: "high",
					PatternID: "bola_param_mismatch",
					Description: "Route param `" + param + "=" + value + "` does not match authenticated user `" + tokenUserID + "`",
					Route: route, Method: method,
					Timestamp: nowMs(),
				}
			}
		}
	}

	for _, param := range routeParams {
		for _, field := range bodyIDFields {
			if param == field {
				if _, hasValue := routeParamValues[param]; hasValue {
					continue
				}
				return &DetectionEvent{
					Type: "bola", Severity: "high",
					PatternID: "bola_param_mismatch",
					Description: "Route param `" + param + "` may be manipulable",
					Route: route, Method: method,
					Timestamp: nowMs(),
				}
			}
		}
	}

	if bodyParams != nil {
		for _, field := range bodyIDFields {
			if val, ok := bodyParams[field]; ok && val != tokenUserID {
				return &DetectionEvent{
					Type: "bola", Severity: "critical",
					PatternID: "bola_body_mismatch",
					Description: "Body field `" + field + "` does not match authenticated user",
					Route: route, Method: method,
					Timestamp: nowMs(),
				}
			}
		}
	}

	return nil
}

func toString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		b, _ := json.Marshal(s)
		return string(b)
	}
}
