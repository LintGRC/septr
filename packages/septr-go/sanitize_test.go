package septr

import "testing"

func TestDetectSQLi_UnionSelect(t *testing.T) {
	r := detectSQLi("1 UNION SELECT * FROM users")
	if len(r) == 0 || r[0].PatternID != "sqli_union" {
		t.Fatal("expected sqli_union")
	}
}

func TestDetectSQLi_Or1Eq1(t *testing.T) {
	r := detectSQLi("' OR 1=1 --")
	if len(r) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSQLi_DropTable(t *testing.T) {
	r := detectSQLi("DROP TABLE users")
	if len(r) == 0 {
		t.Fatal("expected detection")
	}
}

func TestDetectSQLi_Safe(t *testing.T) {
	if len(detectSQLi("hello world")) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestDetectSQLi_CaseInsensitive(t *testing.T) {
	if len(detectSQLi("union select * from users")) == 0 {
		t.Fatal("expected detection for lowercase")
	}
}

func TestDetectXSS_ScriptTag(t *testing.T) {
	r := detectXSS("<script>alert('xss')</script>")
	if len(r) == 0 || r[0].PatternID != "xss_script_tag" {
		t.Fatal("expected xss_script_tag")
	}
}

func TestDetectXSS_Onerror(t *testing.T) {
	r := detectXSS("<img onerror=alert(1)>")
	if len(r) == 0 || r[0].PatternID != "xss_onerror" {
		t.Fatal("expected xss_onerror")
	}
}

func TestDetectXSS_Safe(t *testing.T) {
	if len(detectXSS("hello world")) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestSanitizeInput_BodyString(t *testing.T) {
	block, dets := sanitizeInput("1 UNION SELECT * FROM users", 0)
	if !block || len(dets) == 0 {
		t.Fatal("expected blocked")
	}
}

func TestSanitizeInput_SafeBody(t *testing.T) {
	block, dets := sanitizeInput(map[string]interface{}{"name": "John"}, 0)
	if block || len(dets) > 0 {
		t.Fatal("expected not blocked")
	}
}

func TestSanitizeInput_Nested(t *testing.T) {
	block, dets := sanitizeInput(map[string]interface{}{
		"user": map[string]interface{}{"name": "<script>alert(1)</script>"},
	}, 0)
	if !block || len(dets) == 0 {
		t.Fatal("expected blocked")
	}
}

func TestSanitizeInput_List(t *testing.T) {
	block, dets := sanitizeInput([]interface{}{"DROP TABLE users", "hello"}, 0)
	if !block || len(dets) == 0 {
		t.Fatal("expected blocked")
	}
}

func TestSanitizeQuery_Safe(t *testing.T) {
	block, _ := sanitizeQuery(map[string]interface{}{"search": "hello"})
	if block {
		t.Fatal("expected not blocked")
	}
}

func TestSanitizeQuery_Dangerous(t *testing.T) {
	block, _ := sanitizeQuery(map[string]interface{}{"q": "1 UNION SELECT * FROM users"})
	if !block {
		t.Fatal("expected blocked")
	}
}

func TestDetectNoSQLi(t *testing.T) {
	events := DetectNoSQLi(`{"$ne": null}`)
	found := false
	for _, e := range events {
		if e.PatternID == "nosqli_ne" {
			found = true
			if e.Severity != "high" {
				t.Errorf("expected high severity, got %s", e.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected $ne detection")
	}

	if len(DetectNoSQLi(`{"q": "hello world"}`)) != 0 {
		t.Error("clean input must not be flagged")
	}
}

func TestSanitizeStringCatchesNoSQLi(t *testing.T) {
	events := sanitizeString(`{"username": {"$where": "sleep(5000)"}}`)
	for _, e := range events {
		if e.PatternID == "nosqli_where" {
			return
		}
	}
	t.Error("expected nosqli_where from sanitizeString")
}

func TestDetectMissingSecurityHeaders(t *testing.T) {
	h := map[string][]string{
		"Content-Type": {"application/json"},
	}
	events := DetectMissingSecurityHeaders(h)
	if len(events) != 5 {
		t.Fatalf("expected 5 missing headers, got %d", len(events))
	}
	found := false
	for _, e := range events {
		if e.PatternID == "missing_security_header" && e.Type == "security_headers" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_security_header events")
	}
}

func TestDetectMissingSecurityHeadersAllPresent(t *testing.T) {
	h := map[string][]string{
		"Content-Security-Policy":    {"default-src 'self'"},
		"Strict-Transport-Security":  {"max-age=31536000"},
		"X-Content-Type-Options":     {"nosniff"},
		"X-Frame-Options":            {"DENY"},
		"Referrer-Policy":            {"strict-origin-when-cross-origin"},
		"content-type":               {"application/json"},
	}
	if events := DetectMissingSecurityHeaders(h); len(events) != 0 {
		t.Fatalf("expected no missing headers, got %d", len(events))
	}
}

func TestSQLiObfuscation(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"x' OR/**/1=1--", "sqli_or_1_1"},
		{"x' AND 0x554E494F4E2053454C454354--", "sqli_union"}, // "UNION SELECT" hex
		{"x' AND char(85,78,73,79,78,32,83,69,76,69,67,84)--", "sqli_union"},
		{"x%27%20OR%201%3D1--", "sqli_or_1_1"},
		{"x' UNI/**/ON SEL/**/ECT password FROM admins--", "sqli_union"},
	}
	for _, c := range cases {
		events := detectSQLi(c.input)
		found := false
		for _, e := range events {
			if e.PatternID == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s for %q (got %v)", c.want, c.input, events)
		}
	}
}

func TestSQLiObfuscationBenign(t *testing.T) {
	for _, s := range []string{"hello world", "https://example.com/path?q=search", "color code #ff0000 is red", "what time is it? 5:30"} {
		for _, e := range detectSQLi(s) {
			t.Errorf("benign %q flagged: %s", s, e.PatternID)
		}
	}
}

func TestLibinjectionIntegration(t *testing.T) {
	found := false
	for _, e := range detectSQLi("1' OR '1'='1") {
		if e.PatternID == "sqli_libinjection" {
			found = true
		}
	}
	if !found {
		t.Error("expected libinjection detection on classic SQLi")
	}
	foundXSS := false
	for _, e := range detectXSS("<script>alert(1)</script>") {
		if e.PatternID == "xss_libinjection" {
			foundXSS = true
		}
	}
	if !foundXSS {
		t.Error("expected libinjection XSS detection")
	}
}
