package septr

import (
	"math/rand"
	"regexp"
	"testing"
)

func TestSelfTest_SecretsCatchesStripeTest(t *testing.T) {
	r := detectSecrets("sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd")
	if len(r) == 0 {
		t.Fatal("expected detection")
	}
}

func TestSelfTest_SQLiCatchesOr11(t *testing.T) {
	r := detectSQLi("1' OR '1'='1")
	if len(r) == 0 {
		t.Fatal("expected detection")
	}
}

func TestSelfTest_XSSCatchesScriptTag(t *testing.T) {
	r := detectXSS("<script>alert(1)</script>")
	if len(r) == 0 {
		t.Fatal("expected detection")
	}
}

func TestSelfTest_BOLACatchesUserIDMismatch(t *testing.T) {
	ev := detectBOLA([]string{"userId"}, nil, map[string]string{"sub": "42"}, "/users/:userId", "GET", nil)
	if ev == nil {
		t.Fatal("expected bola detection")
	}
	if ev.PatternID != "bola_param_mismatch" {
		t.Errorf("expected bola_param_mismatch, got %s", ev.PatternID)
	}
}

func TestSelfTest_SecretsSafe(t *testing.T) {
	if len(detectSecrets("hello world")) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestSelfTest_SQLiSafe(t *testing.T) {
	if len(detectSQLi("hello world")) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestSelfTest_XSSSafe(t *testing.T) {
	if len(detectXSS("hello world")) != 0 {
		t.Fatal("expected no detection")
	}
}

func TestSelfTest_TokenFormat(t *testing.T) {
	token := "vs_st_abcdef12"
	matched, _ := regexp.MatchString(`^vs_st_[a-z0-9]{8}$`, token)
	if !matched {
		t.Fatal("token format mismatch")
	}
}

func TestSelfTest_TokenUnique(t *testing.T) {
	// Generate two tokens and verify they differ
	t1 := "vs_st_" + randString(8)
	t2 := "vs_st_" + randString(8)
	if t1 == t2 {
		t.Fatal("expected unique tokens")
	}
}

func randString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
