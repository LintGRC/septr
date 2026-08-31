package septr

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DetectionEvent struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	PatternID   string  `json:"patternId"`
	Description string  `json:"description"`
	Route       string  `json:"route,omitempty"`
	Method      string  `json:"method,omitempty"`
	StatusCode  int     `json:"statusCode,omitempty"`
	Redactable  *bool   `json:"redactable,omitempty"`
	Timestamp   float64 `json:"timestamp"`
}

// TestResult reports whether a single detection engine passed its self-test payload.
type TestResult struct {
	Engine string
	Passed bool
}

type Config struct {
	APIKey            string             `json:"apiKey"`
	ProjectID         string             `json:"projectId,omitempty"`
	Secrets           *bool              `json:"secrets,omitempty"`
	BOLA              *bool              `json:"bola,omitempty"`
	RateLimit         *bool              `json:"rateLimit,omitempty"`
	InputSanitize     *bool              `json:"inputSanitize,omitempty"`
	SSRF              *bool              `json:"ssrf,omitempty"`
	PromptInjection   *bool              `json:"promptInjection,omitempty"`
	MissingAuth       *bool              `json:"missingAuth,omitempty"`
	Tamper            *bool              `json:"tamper,omitempty"`
	AIRateLimit       *bool              `json:"aiRateLimit,omitempty"`
	StrictMode        bool               `json:"strictMode"`
	Telemetry         *bool              `json:"telemetry,omitempty"`
	TelemetryURL      string             `json:"telemetryUrl,omitempty"`
	StripFields       []string           `json:"stripFields,omitempty"`
	RouteTemplates    []string           `json:"routeTemplates,omitempty"`
	SensitivePatterns []string           `json:"sensitivePatterns,omitempty"`
	SelfTest          *bool              `json:"selfTest,omitempty"`
	RemoteConfig      *bool              `json:"remoteConfig,omitempty"`
	ConfigPollMs      int                `json:"configPollMs,omitempty"`
	RateLimitConfig   *RateLimitConfig   `json:"rateLimitConfig,omitempty"`
	FieldConstraints  []FieldConstraint  `json:"fieldConstraints,omitempty"`
	TenantAware       *TenantAwareConfig `json:"tenantAware,omitempty"`

	// framework is set by adapters (gin/nethttp) and reported to the backend
	// as the runtime in the startup handshake. Not part of the remote config.
	framework string

	// mu guards fields mutated by the remote-config poller at runtime.
	mu sync.RWMutex
}

// StrictModeLocked returns strictMode under the remote-config lock.
func (c *Config) StrictModeLocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.StrictMode
}

type RateLimitConfig struct {
	Max      int `json:"max"`
	WindowMs int `json:"windowMs"`
}

type FieldConstraintDef struct {
	Type   string        `json:"type"`
	Min    *float64      `json:"min,omitempty"`
	Max    *float64      `json:"max,omitempty"`
	Values []interface{} `json:"values,omitempty"`
}

type FieldConstraint struct {
	Field      string             `json:"field"`
	Constraint FieldConstraintDef `json:"constraint"`
}

type TenantAwareConfig struct {
	TenantColumn    string `json:"tenantColumn"`
	JWTClaim        string `json:"jwtClaim"`
	BlockOnMismatch bool   `json:"blockOnMismatch,omitempty"`
}

func (c *Config) defaultBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (c *Config) RemoteConfigEnabled() bool {
	if c.RemoteConfig != nil && !*c.RemoteConfig {
		return false
	}
	if v := os.Getenv("SEPTR_REMOTE_CONFIG"); v != "" {
		return strings.ToLower(strings.TrimSpace(v)) != "false"
	}
	return c.APIKey != ""
}

func (c *Config) SecretsEnabled() bool         { return c.defaultBool(c.Secrets, true) }
func (c *Config) SelfTestEnabled() bool        { return c.defaultBool(c.SelfTest, true) }
func (c *Config) BOLAEnabled() bool            { return c.defaultBool(c.BOLA, true) }
func (c *Config) RateLimitEnabled() bool       { return c.defaultBool(c.RateLimit, true) }
func (c *Config) InputSanitizeEnabled() bool   { return c.defaultBool(c.InputSanitize, true) }
func (c *Config) SSRFEnabled() bool            { return c.defaultBool(c.SSRF, true) }
func (c *Config) PromptInjectionEnabled() bool { return c.defaultBool(c.PromptInjection, true) }
func (c *Config) MissingAuthEnabled() bool     { return c.defaultBool(c.MissingAuth, true) }
func (c *Config) TamperEnabled() bool          { return c.defaultBool(c.Tamper, true) }
func (c *Config) AIRateLimitEnabled() bool     { return c.defaultBool(c.AIRateLimit, true) }
func (c *Config) TelemetryEnabled() bool       { return c.defaultBool(c.Telemetry, false) }

func nowMs() float64 {
	return float64(time.Now().UnixNano()) / 1e6
}

func toNumber(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}
