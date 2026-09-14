package septr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Live remote config: poll the Septr backend for the project config
// (strictMode, engine toggles, rate-limit settings) and apply it to the
// running middleware without redeploying.
//
// StartConfigPolling fetches on startup and then every ConfigPollMs
// (default 60_000). On backend failure the last-known config is kept and the
// next cycle retries. Disable with RemoteConfig=false in the config or
// SEPT_REMOTE_CONFIG=false in the environment.

const defaultConfigPollMs = 60_000

var (
	configPollMu     sync.Mutex
	configPollStopCh chan struct{}
)

var v2KeyPattern = regexp.MustCompile(`^septr_live_([0-9a-fA-F-]{36})_[0-9a-f]{32}$`)

func projectIDFromKey(apiKey string) string {
	m := v2KeyPattern.FindStringSubmatch(apiKey)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func remoteConfigBaseURL(cfg *Config) string {
	url := cfg.TelemetryURL
	if url == "" {
		url = "https://app.septr.dev/v1/events"
	}
	return strings.TrimSuffix(url, "/events")
}

// FetchRemoteConfig returns the project's remote config, or nil on failure.
func FetchRemoteConfig(cfg *Config) map[string]interface{} {
	pid := projectIDFromKey(cfg.APIKey)
	if pid == "" {
		pid = cfg.ProjectID
	}
	if pid == "" {
		pid = cfg.APIKey
	}
	if pid == "" {
		return nil
	}

	url := fmt.Sprintf("%s/projects/%s/config", remoteConfigBaseURL(cfg), pid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	// Edge proxies (Cloudflare) reject default Go-http-client agents.
	req.Header.Set("User-Agent", "Septr-SDK/"+sdkVersion)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var parsed struct {
		Config map[string]interface{} `json:"config"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	return parsed.Config
}

var remoteRuntimeKeys = map[string]bool{
	"strictMode":             true,
	"secrets":                true,
	"bola":                   true,
	"rateLimit":              true,
	"inputSanitize":          true,
	"ssrf":                   true,
	"promptInjection":        true,
	"missingAuth":            true,
	"aiRateLimit":            true,
	"aiEndpointShield":       true,
	"tamper":                 true,
	"tenantAware":            true,
	"stripFields":            true,
	"rateLimitConfig":        true,
	"aiRateLimitConfig":      true,
	"maxResponseScanBytes":   true,
	"maxRequestInspectBytes": true,
}

// ApplyRemoteConfig merges runtime-affecting keys into cfg under the config lock.
func ApplyRemoteConfig(cfg *Config, remote map[string]interface{}) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	for key, value := range remote {
		if !remoteRuntimeKeys[key] {
			continue
		}
		switch key {
		case "strictMode":
			if v, ok := value.(bool); ok {
				cfg.StrictMode = v
			}
		case "secrets":
			if v, ok := value.(bool); ok {
				cfg.Secrets = &v
			}
		case "bola":
			if v, ok := value.(bool); ok {
				cfg.BOLA = &v
			}
		case "rateLimit":
			if v, ok := value.(bool); ok {
				cfg.RateLimit = &v
			}
		case "inputSanitize":
			if v, ok := value.(bool); ok {
				cfg.InputSanitize = &v
			}
		case "ssrf":
			if v, ok := value.(bool); ok {
				cfg.SSRF = &v
			}
		case "promptInjection":
			if v, ok := value.(bool); ok {
				cfg.PromptInjection = &v
			}
		case "missingAuth":
			if v, ok := value.(bool); ok {
				cfg.MissingAuth = &v
			}
		case "aiRateLimit":
			if v, ok := value.(bool); ok {
				cfg.AIRateLimit = &v
			}
		case "tamper":
			if v, ok := value.(bool); ok {
				cfg.Tamper = &v
			}
		case "aiEndpointShield":
			if v, ok := value.(bool); ok {
				cfg.AIRateLimit = &v
			}
		case "stripFields":
			if v, ok := value.([]interface{}); ok {
				fields := make([]string, 0, len(v))
				for _, f := range v {
					if s, ok := f.(string); ok {
						fields = append(fields, s)
					}
				}
				cfg.StripFields = fields
			}
		case "securityHeaders":
			if v, ok := value.(bool); ok {
				cfg.SecurityHeaders = &v
			}
		case "maxResponseScanBytes":
			switch v := value.(type) {
			case float64:
				cfg.MaxResponseScanBytes = int(v)
			case int:
				cfg.MaxResponseScanBytes = v
			}
		case "maxRequestInspectBytes":
			switch v := value.(type) {
			case float64:
				cfg.MaxRequestInspectBytes = int(v)
			case int:
				cfg.MaxRequestInspectBytes = v
			}
		}
	}
}

// StartConfigPolling begins polling the backend for remote config. Safe to
// call multiple times (restarts the loop). Returns when the first fetch has
// been applied (or failed) so strictMode is correct before traffic arrives.
func StartConfigPolling(cfg *Config) {
	if !cfg.RemoteConfigEnabled() {
		return
	}

	// First fetch is synchronous so strictMode applies before traffic arrives.
	if remote := FetchRemoteConfig(cfg); remote != nil {
		ApplyRemoteConfig(cfg, remote)
	}

	intervalMs := cfg.ConfigPollMs
	if intervalMs <= 0 {
		intervalMs = defaultConfigPollMs
	}

	configPollMu.Lock()
	if configPollStopCh != nil {
		close(configPollStopCh)
	}
	configPollStopCh = make(chan struct{})
	stop := configPollStopCh
	configPollMu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if remote := FetchRemoteConfig(cfg); remote != nil {
					ApplyRemoteConfig(cfg, remote)
				}
			case <-stop:
				return
			}
		}
	}()
}

// StopConfigPolling stops the background polling loop, if running.
func StopConfigPolling() {
	configPollMu.Lock()
	defer configPollMu.Unlock()
	if configPollStopCh != nil {
		close(configPollStopCh)
		configPollStopCh = nil
	}
}
