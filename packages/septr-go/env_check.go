package septr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Fail-loud diagnostics for SEPTR_* environment configuration.
//
// Detects the classic "wrong key inherited" footgun: a SEPTR_API_KEY exported
// by the shell or a launch script overrides the app's own .env file (dotenv
// loads default to override=false, so the inherited value wins). When that
// happens telemetry lands in the wrong project with no error anywhere.
//
// Best-effort discovery: .env files are looked up near the process working
// directory (cwd/.env, the parent's .env, and one level of cwd children).

var envWarned = false

var septrKeyRE = regexp.MustCompile(`^(septr_live_|vs_live_)([0-9a-fA-F-]{36})_([0-9a-fA-F]{32})$`)

// maskKey hides an API key for display while keeping the embedded project id
// visible — the id is what identifies the *wrong* project in a misrouting
// scenario.
func maskKey(key string) string {
	m := septrKeyRE.FindStringSubmatch(key)
	if m != nil {
		return m[1] + m[2][:4] + "…" + m[2][len(m[2])-4:] + "_" + m[3][:2] + "…" + m[3][len(m[3])-4:]
	}
	if len(key) <= 12 {
		return "***"
	}
	return key[:8] + "…" + key[len(key)-4:]
}

// readDotenvKey does a best-effort parse of KEY=VALUE from a .env file.
func readDotenvKey(file, keyName string) string {
	content, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(line[:eq]) != keyName {
			continue
		}
		value := strings.TrimSpace(line[eq+1:])
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		return value
	}
	return ""
}

// envDotenvCandidates returns likely locations for the app's .env file.
func envDotenvCandidates(cwd string) []string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	candidates := []string{filepath.Join(cwd, ".env"), filepath.Join(cwd, "..", ".env")}
	if entries, err := os.ReadDir(cwd); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, filepath.Join(cwd, e.Name(), ".env"))
			}
		}
	}
	return candidates
}

// checkEnvVsDotenv returns warning lines when the process env key differs from
// the key in a discovered local .env file. Fires at most once per process.
func checkEnvVsDotenv(envKey, keyName string, candidates []string) []string {
	if envWarned || envKey == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SEPTR_SILENCE_ENV_WARNING"))) {
	case "1", "true", "yes":
		return nil
	}
	for _, file := range candidates {
		if local := readDotenvKey(file, keyName); local != "" && local != envKey {
			envWarned = true
			return []string{fmt.Sprintf(
				"⚠️  [septr] WARNING: the %s in this process environment (%s) does not match "+
					"the one in %s (%s). Telemetry may be routing to the wrong project. "+
					"Check for %s exported by your shell or launch script — it overrides "+
					"the app's .env file.",
				keyName, maskKey(envKey), file, maskKey(local), keyName,
			)}
		}
	}
	return nil
}

// warnEnvVsDotenv prints the env-vs-.env mismatch warning to stderr (once).
func warnEnvVsDotenv(envKey string) {
	for _, line := range checkEnvVsDotenv(envKey, "SEPTR_API_KEY", envDotenvCandidates("")) {
		fmt.Fprintln(os.Stderr, line)
	}
}

// resetEnvCheck clears the once-per-process guard (test helper).
func resetEnvCheck() {
	envWarned = false
}
