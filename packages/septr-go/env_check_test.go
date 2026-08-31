package septr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testKeyA = "septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff"
	testKeyB = "septr_live_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_0123456789abcdef0123456789abcdef"
)

func TestMaskKey(t *testing.T) {
	if got := maskKey("short"); got != "***" {
		t.Errorf("expected *** for short key, got %s", got)
	}
	if got := maskKey(testKeyA); got != "septr_live_aaaa…aaaa_ff…ffff" {
		t.Errorf("unexpected mask: %s", got)
	}
	if got := maskKey(testKeyB); got != "septr_live_bbbb…bbbb_01…cdef" {
		t.Errorf("unexpected mask: %s", got)
	}
}

func TestReadDotenvKey(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("# comment\nSEPTR_API_KEY=\"septr_live_aaaa\"\nSEPTR_TELEMETRY_URL='http://x'\n"), 0o600)
	if got := readDotenvKey(env, "SEPTR_API_KEY"); got != "septr_live_aaaa" {
		t.Errorf("expected septr_live_aaaa, got %q", got)
	}
	if got := readDotenvKey(env, "SEPTR_TELEMETRY_URL"); got != "http://x" {
		t.Errorf("expected http://x, got %q", got)
	}
	if got := readDotenvKey(env, "MISSING"); got != "" {
		t.Errorf("expected empty for missing key, got %q", got)
	}
	if got := readDotenvKey(filepath.Join(dir, "nope.env"), "SEPTR_API_KEY"); got != "" {
		t.Errorf("expected empty for missing file, got %q", got)
	}
}

func TestEnvDotenvCandidates(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	got := envDotenvCandidates(dir)
	if !hasPath(got, filepath.Join(dir, ".env")) {
		t.Errorf("missing cwd .env candidate: %v", got)
	}
	if !hasPath(got, filepath.Join(dir, "..", ".env")) {
		t.Errorf("missing parent .env candidate: %v", got)
	}
	if !hasPath(got, filepath.Join(dir, "sub", ".env")) {
		t.Errorf("missing child .env candidate: %v", got)
	}
}

func TestCheckEnvVsDotenv_WarnsOnce(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("SEPTR_API_KEY=\""+testKeyB+"\"\n"), 0o600)

	first := checkEnvVsDotenv(testKeyA, "SEPTR_API_KEY", []string{env})
	if len(first) != 1 {
		t.Fatalf("expected one warning, got %d", len(first))
	}
	if !strings.Contains(first[0], "bbbb…bbbb") || !strings.Contains(first[0], "aaaa…aaaa") {
		t.Errorf("warning missing masked keys: %s", first[0])
	}
	if strings.Contains(first[0], "ffffffffffffffffffffffffffffffff") {
		t.Errorf("warning leaked full secret: %s", first[0])
	}
	if second := checkEnvVsDotenv(testKeyA, "SEPTR_API_KEY", []string{env}); len(second) != 0 {
		t.Errorf("expected no second warning, got %v", second)
	}
}

func TestCheckEnvVsDotenv_MatchingKeySilent(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("SEPTR_API_KEY=\""+testKeyB+"\"\n"), 0o600)
	if got := checkEnvVsDotenv(testKeyB, "SEPTR_API_KEY", []string{env}); len(got) != 0 {
		t.Errorf("expected silence on match, got %v", got)
	}
}

func TestCheckEnvVsDotenv_NoEnvFileSilent(t *testing.T) {
	if got := checkEnvVsDotenv(testKeyA, "SEPTR_API_KEY", []string{filepath.Join(t.TempDir(), ".env")}); len(got) != 0 {
		t.Errorf("expected silence without .env, got %v", got)
	}
}

func TestCheckEnvVsDotenv_SilenceEnvVar(t *testing.T) {
	t.Setenv("SEPTR_SILENCE_ENV_WARNING", "1")
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("SEPTR_API_KEY=\""+testKeyB+"\"\n"), 0o600)
	if got := checkEnvVsDotenv(testKeyA, "SEPTR_API_KEY", []string{env}); len(got) != 0 {
		t.Errorf("expected silence with SEPTR_SILENCE_ENV_WARNING, got %v", got)
	}
}

func hasPath(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
