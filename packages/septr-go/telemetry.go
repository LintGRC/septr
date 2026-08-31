package septr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	defaultFlushIntervalMs = 30000
	maxBatchSize           = 50
	maxBufferSize          = 500
	maxRetryIntervalMs     = 300000

	// sdkVersion is the septr-go release. Go modules have no runtime version
	// metadata, so this is kept in sync manually with the module tag.
	sdkVersion = "0.1.0"
)

type TelemetryManager struct {
	mu                  sync.Mutex
	buffer              []DetectionEvent
	projectID           string
	config              *Config
	currentFlushInterval int
	ticker              *time.Ticker
	done                chan struct{}
	destroyed           bool
}

var defaultManager *TelemetryManager

func initTelemetry(config *Config, projectID string) {
	if defaultManager != nil {
		defaultManager.Destroy()
	}
	// Fail-loud: warn once when the SEPTR_API_KEY in this process environment
	// differs from the one in a local .env file (shell / launcher export
	// footgun — dotenv loads won't override an already-set env var). Runs even
	// when the app injects the env key into the middleware config explicitly.
	envKey := os.Getenv("SEPTR_API_KEY")
	if envKey == "" {
		envKey = os.Getenv("VS_API_KEY")
	}
	warnEnvVsDotenv(envKey)
	defaultManager = NewTelemetryManager(config, projectID)

	// Handshake: verify the key and report runtime/version to the backend.
	// Retries in the background on failure (self-dogfooding apps handshake
	// before their own port is listening).
	apiKey := config.APIKey
	if apiKey == "" {
		apiKey = envKey
	}
	if apiKey != "" {
		go func() {
			if !sendHandshake(config, apiKey) {
				startHandshakeRetry(config, apiKey)
			}
		}()
	}
}

func handshakeURL(config *Config) string {
	url := config.TelemetryURL
	if url == "" {
		url = "https://api.septr.com/v1/events"
	}
	if len(url) >= len("/events") && url[len(url)-len("/events"):] == "/events" {
		url = url[:len(url)-len("/events")]
	}
	return url + "/handshake"
}

func sendHandshake(config *Config, apiKey string) bool {
	if apiKey == "" {
		return false
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"runtime":     config.framework,
		"package":     "septr",
		"version":     sdkVersion,
		"environment": envOrDefault("NODE_ENV", "production"),
	})
	req, err := http.NewRequest("POST", handshakeURL(config), bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	var data struct {
		Status  string `json:"status"`
		Project struct {
			Name string `json:"name"`
		} `json:"project"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false
	}
	if data.Status != "connected" {
		return false
	}
	name := data.Project.Name
	if name == "" {
		name = config.ProjectID
	}
	fmt.Printf("[septr] Connected to project '%s' (id=%s) — handshake OK\n", name, config.ProjectID)
	return true
}

func startHandshakeRetry(config *Config, apiKey string) {
	backoff := 10 * time.Second
	go func() {
		for {
			time.Sleep(backoff)
			if defaultManager == nil || defaultManager.destroyed {
				return
			}
			if sendHandshake(config, apiKey) {
				return
			}
			backoff = min(backoff*2, 60*time.Second)
		}
	}()
}

func NewTelemetryManager(config *Config, projectID string) *TelemetryManager {
	t := &TelemetryManager{
		buffer:              make([]DetectionEvent, 0, maxBatchSize),
		projectID:           projectID,
		config:              config,
		currentFlushInterval: defaultFlushIntervalMs,
		done:                make(chan struct{}),
	}
	if t.currentFlushInterval > 0 {
		t.ticker = time.NewTicker(time.Duration(t.currentFlushInterval) * time.Millisecond)
		go t.flushLoop()
	}
	return t
}

func (t *TelemetryManager) flushLoop() {
	for {
		select {
		case <-t.ticker.C:
			t.Flush()
		case <-t.done:
			return
		}
	}
}

func (t *TelemetryManager) Emit(event DetectionEvent) {
	if t.destroyed || (t.config != nil && !t.config.TelemetryEnabled()) {
		return
	}
	t.mu.Lock()
	t.buffer = append(t.buffer, event)
	if len(t.buffer) > maxBufferSize {
		t.buffer = t.buffer[len(t.buffer)-maxBufferSize:]
	}
	shouldFlush := len(t.buffer) >= maxBatchSize
	t.mu.Unlock()

	if shouldFlush {
		t.Flush()
	}
}

func (t *TelemetryManager) Flush() {
	t.mu.Lock()
	if t.destroyed || len(t.buffer) == 0 || t.projectID == "" {
		t.mu.Unlock()
		return
	}
	batch := make([]DetectionEvent, min(maxBatchSize, len(t.buffer)))
	copy(batch, t.buffer[:len(batch)])
	t.buffer = t.buffer[len(batch):]
	t.mu.Unlock()

	if err := t.sendBatch(batch); err != nil {
		t.mu.Lock()
		t.buffer = append(batch, t.buffer...)
		t.currentFlushInterval = min(t.currentFlushInterval*2, maxRetryIntervalMs)
		if t.ticker != nil {
			t.ticker.Reset(time.Duration(t.currentFlushInterval) * time.Millisecond)
		}
		t.mu.Unlock()
	} else {
		t.mu.Lock()
		t.currentFlushInterval = defaultFlushIntervalMs
		t.mu.Unlock()
	}
}

func (t *TelemetryManager) sendBatch(batch []DetectionEvent) error {
	url := t.config.TelemetryURL
	if url == "" {
		url = "https://api.septr.com/v1/events"
	}

	events := make([]map[string]interface{}, len(batch))
	for i, e := range batch {
		m := map[string]interface{}{
			"type":       e.Type,
			"severity":   e.Severity,
			"patternId":  e.PatternID,
			"description": e.Description,
		}
		if e.Route != "" {
			m["route"] = e.Route
		}
		if e.Method != "" {
			m["method"] = e.Method
		}
		if e.StatusCode != 0 {
			m["http_status"] = e.StatusCode
		}
		if e.PatternID != "" {
			m["patternId"] = e.PatternID
		}
		if e.Type != "" {
			m["detection_type"] = e.Type
		}
		m["event"] = e.Description
		m["timestamp"] = e.Timestamp
		events[i] = m
	}

	payload := map[string]interface{}{
		"events":    events,
		"projectId": t.projectID,
		"packageName": "septr",
		"packageVersion": sdkVersion,
		"environment": envOrDefault("NODE_ENV", "production"),
		"schemaVersion": "0.1",
		"framework": t.config.framework,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Septr-Telemetry/"+sdkVersion)
	if t.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.APIKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return errTelemetryRejected
	}
	return nil
}

func (t *TelemetryManager) SendVerified(runtimeInfo map[string]interface{}) {
	desc := "Self-test passed"
	if len(runtimeInfo) > 0 {
		if b, err := json.Marshal(runtimeInfo); err == nil {
			desc += " (" + string(b) + ")"
		}
	}
	t.Emit(DetectionEvent{
		Type: "system", Severity: "info",
		PatternID: "self_test", Description: desc,
		Route: "__verified__", Timestamp: nowMs(),
	})
}

func (t *TelemetryManager) SendTestResults(results []TestResult, runtimeInfo map[string]interface{}) {
	for _, r := range results {
		severity := "info"
		if !r.Passed {
			severity = "high"
		}
		t.Emit(DetectionEvent{
			Type: "system", Severity: severity,
			PatternID: "test_" + r.Engine, Description: r.Engine,
			Route: "__test_result__", Timestamp: nowMs(),
		})
	}
	t.SendVerified(runtimeInfo)
	t.Flush()
}

func (t *TelemetryManager) Destroy() {
	t.destroyed = true
	if t.ticker != nil {
		t.ticker.Stop()
	}
	close(t.done)
	t.mu.Lock()
	t.buffer = nil
	t.mu.Unlock()
}

func emitEvent(event DetectionEvent, config *Config) {
	if config != nil && !config.TelemetryEnabled() {
		return
	}
	if defaultManager != nil && !defaultManager.destroyed {
		defaultManager.Emit(event)
	}
}

func sendVerified(runtimeInfo map[string]interface{}) {
	if defaultManager != nil && !defaultManager.destroyed {
		defaultManager.SendVerified(runtimeInfo)
	}
}

func sendTestResults(results []TestResult, runtimeInfo map[string]interface{}) {
	if defaultManager != nil && !defaultManager.destroyed {
		defaultManager.SendTestResults(results, runtimeInfo)
	}
}

func destroyTelemetry() {
	if defaultManager != nil {
		defaultManager.Destroy()
		defaultManager = nil
	}
}

var errTelemetryRejected = &telemetryError{"telemetry API rejected"}

type telemetryError struct{ msg string }

func (e *telemetryError) Error() string { return e.msg }

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
