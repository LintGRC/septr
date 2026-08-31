package septr

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	libinjection "github.com/corazawaf/libinjection-go"
)

var sqliPatterns = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{id: "sqli_union", pattern: regexp.MustCompile(`(?i)(\bUNION\b\s+\bSELECT\b)`)},
	{id: "sqli_or_1_1", pattern: regexp.MustCompile(`(?i)(\bOR\b\s+1\s*=\s*1)`)},
	{id: "sqli_or_true", pattern: regexp.MustCompile(`(?i)(\bOR\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)`)},
	{id: "sqli_drop", pattern: regexp.MustCompile(`(?i)(\bDROP\b\s+\bTABLE\b)`)},
	{id: "sqli_insert", pattern: regexp.MustCompile(`(?i)(\bINSERT\b\s+\bINTO\b)`)},
	{id: "sqli_delete", pattern: regexp.MustCompile(`(?i)(\bDELETE\b\s+\bFROM\b)`)},
	{id: "sqli_alter", pattern: regexp.MustCompile(`(?i)(\bALTER\b\s+\bTABLE\b)`)},
	{id: "sqli_exec", pattern: regexp.MustCompile(`(?i)(\bEXEC\b|\bEXECUTE\b)\s*\(`)},
	{id: "sqli_comment", pattern: regexp.MustCompile(`--\s*$|/\*[\s\S]*?\*/`)},
	{id: "sqli_pg_sleep", pattern: regexp.MustCompile(`(?i)(\bPG_SLEEP\b\s*\()`)},
	{id: "sqli_waitfor", pattern: regexp.MustCompile(`(?i)(\bWAITFOR\b\s+\bDELAY\b)`)},
	{id: "sqli_benchmark", pattern: regexp.MustCompile(`(?i)(\bBENCHMARK\b\s*\()`)},
	{id: "sqli_into_outfile", pattern: regexp.MustCompile(`(?i)(\bINTO\b\s+\bOUTFILE\b)`)},
	{id: "sqli_information_schema", pattern: regexp.MustCompile(`(?i)(\bINFORMATION_SCHEMA\b)`)},
}

var xssPatterns = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{id: "xss_script_tag", pattern: regexp.MustCompile(`(?i)<script[\s>]`)},
	{id: "xss_onerror", pattern: regexp.MustCompile(`(?i)\bonerror\s*=`)},
	{id: "xss_onload", pattern: regexp.MustCompile(`(?i)\bonload\s*=`)},
	{id: "xss_onclick", pattern: regexp.MustCompile(`(?i)\bonclick\s*=`)},
	{id: "xss_onmouseover", pattern: regexp.MustCompile(`(?i)\bonmouseover\s*=`)},
	{id: "xss_onsubmit", pattern: regexp.MustCompile(`(?i)\bonsubmit\s*=`)},
	{id: "xss_onfocus", pattern: regexp.MustCompile(`(?i)\bonfocus\s*=`)},
	{id: "xss_onblur", pattern: regexp.MustCompile(`(?i)\bonblur\s*=`)},
	{id: "xss_onchange", pattern: regexp.MustCompile(`(?i)\bonchange\s*=`)},
	{id: "xss_javascript_url", pattern: regexp.MustCompile(`(?i)javascript\s*:\s*['"]`)},
	{id: "xss_document_cookie", pattern: regexp.MustCompile(`(?i)document\s*\.\s*cookie`)},
	{id: "xss_alert", pattern: regexp.MustCompile(`(?i)alert\s*[(]`)},
	{id: "xss_eval", pattern: regexp.MustCompile(`(?i)\beval\s*[(]`)},
	{id: "xss_iframe", pattern: regexp.MustCompile(`(?i)<iframe[\s>]`)},
	{id: "xss_object", pattern: regexp.MustCompile(`(?i)<object[\s>]`)},
	{id: "xss_embed", pattern: regexp.MustCompile(`(?i)<embed[\s>]`)},
	{id: "xss_svg_script", pattern: regexp.MustCompile(`(?i)<svg[\s>][\s\S]*?<script`)},
}


var sqlKeywords = []string{
	"SELECT", "UNION", "INSERT", "DELETE", "DROP", "ALTER", "UPDATE", "CREATE",
	"EXEC", "EXECUTE", "FROM", "WHERE", "TABLE", "INTO", "OUTFILE", "LOAD_FILE",
	"BENCHMARK", "PG_SLEEP", "WAITFOR", "INFORMATION_SCHEMA",
}

// NormalizeSQLInput de-obfuscates common SQLi encoding tricks (URL-encoding,
// /* comments */, -- comments, 0x hex literals, char() calls, split keywords)
// so pattern detectors see the underlying query. Detection-only.
func NormalizeSQLInput(input string) string {
	if input == "" {
		return input
	}
	if decoded, err := url.QueryUnescape(input); err == nil {
		input = decoded
	}
	input = strings.ReplaceAll(input, "+", " ")
	input = commentRe.ReplaceAllString(input, " ")
	input = dashCommentRe.ReplaceAllString(input, " ")

	// Comments can split a keyword (SEL/**/ECT) — rejoin known keywords.
	for _, kw := range sqlKeywords {
		parts := strings.Split(kw, "")
		pattern := "\\b" + parts[0] + "\\s*" + strings.Join(parts[1:], "\\s*") + "\\b"
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			input = re.ReplaceAllString(input, kw)
		}
	}

	input = hexLiteralRe.ReplaceAllStringFunc(input, func(m string) string {
		hex := strings.TrimPrefix(m, "0x")
		if len(hex)%2 != 0 {
			return m
		}
		var out strings.Builder
		for i := 0; i < len(hex); i += 2 {
			var b int
			if _, err := fmt.Sscanf(hex[i:i+2], "%02x", &b); err != nil {
				return m
			}
			if b < 32 || b > 126 {
				return m
			}
			out.WriteByte(byte(b))
		}
		return out.String()
	})

	input = charCallRe.ReplaceAllStringFunc(input, func(m string) string {
		inner := strings.TrimSuffix(strings.TrimPrefix(m[strings.Index(m, "(")+1:], "("), ")")
		parts := strings.Split(inner, ",")
		var out strings.Builder
		for _, p := range parts {
			var c int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &c); err != nil {
				return m
			}
			if c < 32 || c > 126 {
				return m
			}
			out.WriteByte(byte(c))
		}
		return out.String()
	})

	return whitespaceRe.ReplaceAllString(input, " ")
}

var (
	commentRe     = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	dashCommentRe = regexp.MustCompile(`--[^\n\r]*`)
	hexLiteralRe  = regexp.MustCompile(`(?i)0x[0-9a-f]{4,}`)
	charCallRe    = regexp.MustCompile(`(?i)\b(?:char|chr)\s*\(\s*[0-9]+(?:\s*,\s*[0-9]+)*\s*\)`)
	whitespaceRe  = regexp.MustCompile(`\s+`)
)

func detectSQLi(input string) []DetectionEvent {
	var events []DetectionEvent
	seen := map[string]bool{}
	scan := func(text string) {
		for _, sp := range sqliPatterns {
			if seen[sp.id] {
				continue
			}
			if sp.pattern.MatchString(text) {
				seen[sp.id] = true
				events = append(events, DetectionEvent{
					Type: "input_sanitize", Severity: "high",
					PatternID: sp.id, Description: "SQLi pattern: " + sp.id,
					StatusCode: 400, Timestamp: nowMs(),
				})
			}
		}
	}
	scan(input)
	normalized := NormalizeSQLInput(input)
	if normalized != input {
		scan(normalized)
	}
	// libinjection fingerprint detection (BSD-3 port of the industry-standard
	// tokenizer) — catches non-obvious SQL syntax regexes miss.
	if ok, _ := libinjection.IsSQLi(input); ok && !seen["sqli_libinjection"] {
		seen["sqli_libinjection"] = true
		events = append(events, DetectionEvent{
			Type: "input_sanitize", Severity: "high",
			PatternID: "sqli_libinjection", Description: "SQLi pattern: sqli_libinjection",
			StatusCode: 400, Timestamp: nowMs(),
		})
	}
	return events
}

func detectXSS(input string) []DetectionEvent {
	var events []DetectionEvent
	for _, sp := range xssPatterns {
		if sp.pattern.MatchString(input) {
			events = append(events, DetectionEvent{
				Type: "input_sanitize", Severity: "medium",
				PatternID: sp.id, Description: "XSS pattern: " + sp.id,
				StatusCode: 400, Timestamp: nowMs(),
			})
		}
	}
	if libinjection.IsXSS(input) {
		events = append(events, DetectionEvent{
			Type: "input_sanitize", Severity: "medium",
			PatternID: "xss_libinjection", Description: "XSS pattern: xss_libinjection",
			StatusCode: 400, Timestamp: nowMs(),
		})
	}
	return events
}

func sanitizeString(input string) []DetectionEvent {
	return append(append(detectSQLi(input), detectXSS(input)...), DetectNoSQLi(input)...)
}

func sanitizeQuery(query map[string]interface{}) (bool, []DetectionEvent) {
	var detections []DetectionEvent
	for _, val := range query {
		switch v := val.(type) {
		case string:
			detections = append(detections, sanitizeString(v)...)
		case []string:
			for _, s := range v {
				detections = append(detections, sanitizeString(s)...)
			}
		}
	}
	return len(detections) > 0, detections
}

func sanitizeInput(body interface{}, depth int) (bool, []DetectionEvent) {
	if depth > 10 {
		return false, nil
	}
	var detections []DetectionEvent
	switch v := body.(type) {
	case string:
		detections = sanitizeString(v)
	case map[string]interface{}:
		for key, val := range v {
			detections = append(detections, sanitizeString(key)...)
			if sub, ok := val.(string); ok {
				detections = append(detections, sanitizeString(sub)...)
			} else {
				_, subDets := sanitizeInput(val, depth+1)
				detections = append(detections, subDets...)
			}
		}
	case []interface{}:
		for _, item := range v {
			_, subDets := sanitizeInput(item, depth+1)
			detections = append(detections, subDets...)
		}
	}
	return len(detections) > 0, detections
}

var nosqliPatterns = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{id: "nosqli_ne", pattern: regexp.MustCompile(`\$ne\b`)},
	{id: "nosqli_gt", pattern: regexp.MustCompile(`\$gt\b`)},
	{id: "nosqli_gte", pattern: regexp.MustCompile(`\$gte\b`)},
	{id: "nosqli_lt", pattern: regexp.MustCompile(`\$lt\b`)},
	{id: "nosqli_lte", pattern: regexp.MustCompile(`\$lte\b`)},
	{id: "nosqli_in", pattern: regexp.MustCompile(`\$in\b`)},
	{id: "nosqli_nin", pattern: regexp.MustCompile(`\$nin\b`)},
	{id: "nosqli_where", pattern: regexp.MustCompile(`\$where\b`)},
	{id: "nosqli_exists", pattern: regexp.MustCompile(`\$exists\b`)},
	{id: "nosqli_regex", pattern: regexp.MustCompile(`\$regex\b`)},
	{id: "nosqli_all", pattern: regexp.MustCompile(`\$all\b`)},
	{id: "nosqli_mod", pattern: regexp.MustCompile(`\$mod\b`)},
	{id: "nosqli_size", pattern: regexp.MustCompile(`\$size\b`)},
	{id: "nosqli_elem_match", pattern: regexp.MustCompile(`\$elemMatch\b`)},
}

// DetectNoSQLi reports NoSQL injection operators ($ne, $where, $gt, ...).
func DetectNoSQLi(input string) []DetectionEvent {
	var events []DetectionEvent
	for _, sp := range nosqliPatterns {
		if sp.pattern.MatchString(input) {
			events = append(events, DetectionEvent{
				Type: "input_sanitize", Severity: "high",
				PatternID: sp.id, Description: "NoSQL injection: " + strings.TrimPrefix(sp.id, "nosqli_") + " operator",
				StatusCode: 400, Timestamp: nowMs(),
			})
		}
	}
	return events
}
