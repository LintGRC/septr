//go:build !nogin

package septr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type GinMiddleware struct {
	config         *Config
	generalLimiter *SlidingWindowRateLimiter
	authLimiter    *SlidingWindowRateLimiter
	selfTestEvent  *sync.WaitGroup
	selfTestToken  string
	selfTestDone   bool
	selfTestMu     sync.Mutex
}

func NewGin(config *Config) *GinMiddleware {
	m := &GinMiddleware{config: config}
	if config.RateLimitEnabled() {
		rc := config.RateLimitConfig
		max, windowMs := 60, 60000
		if rc != nil {
			if rc.Max > 0 {
				max = rc.Max
			}
			if rc.WindowMs > 0 {
				windowMs = rc.WindowMs
			}
		}
		m.generalLimiter = NewSlidingWindowRateLimiter(max, windowMs)
		m.authLimiter = NewSlidingWindowRateLimiter(10, 60000)
	}
	if config.APIKey != "" && config.TelemetryEnabled() {
		pid := config.ProjectID
		if pid == "" {
			pid = config.APIKey
		}
		if config.framework == "" {
			config.framework = "gin"
		}
		initTelemetry(config, pid)
	}
	StartConfigPolling(config)
	m.selfTestToken = fmt.Sprintf("vs_st_%08x", rand.Int63())
	return m
}

func (m *GinMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method
		headers := c.Request.Header

		autoSelfTest(m.config, &m.selfTestDone, &m.selfTestMu)

		if path == selfTestPath && headers.Get("x-septr-self-test") == m.selfTestToken {
			if m.selfTestEvent != nil {
				m.selfTestEvent.Done()
			}
			testBody := map[string]interface{}{
				"api_key": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
				"status":  "ok",
			}
			cleaned, stripDets := stripSensitiveData(testBody, m.config.StripFields)
			c.Header("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
			c.JSON(http.StatusOK, cleaned)
			c.Abort()
			return
		}

		event := m.runPipeline(c.Writer, c.Request, path, method, headers, c.FullPath())
		if event != nil {
			if event.statusCode == 429 {
				c.JSON(event.statusCode, gin.H{"error": "Too many requests"})
				c.Abort()
				return
			}
			if event.statusCode == 403 {
				c.JSON(event.statusCode, gin.H{"error": "Request blocked by Septr security filter"})
				c.Abort()
				return
			}
			if event.statusCode == 400 {
				c.JSON(event.statusCode, gin.H{"error": "Request blocked by Septr security filter"})
				c.Abort()
				return
			}
			if event.statusCode == 404 {
				c.AbortWithStatus(event.statusCode)
				return
			}
			return
		}

		needsResponseInspection := m.config.SecretsEnabled() || m.config.AIRateLimitEnabled() || m.config.TenantAware != nil
		if needsResponseInspection {
			iw := &ginInspectWriter{ResponseWriter: c.Writer, statusCode: http.StatusOK}
			c.Writer = iw
			c.Next()
			iw.finalize(m.config, path, method, headers)
			return
		}

		c.Next()
	}
}

type ginInspectWriter struct {
	gin.ResponseWriter
	buf         bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func (w *ginInspectWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code
}

func (w *ginInspectWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.statusCode = http.StatusOK
	}
	return w.buf.Write(b)
}

func (w *ginInspectWriter) WriteString(s string) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.statusCode = http.StatusOK
	}
	return w.buf.WriteString(s)
}

func (w *ginInspectWriter) WriteHeaderNow() {}

func (w *ginInspectWriter) Status() int { return w.statusCode }

func (w *ginInspectWriter) Size() int { return w.buf.Len() }

func (w *ginInspectWriter) finalize(config *Config, path, method string, headers http.Header) {
	// Advisory: report responses missing standard security headers.
	for _, d := range DetectMissingSecurityHeaders(w.Header()) {
		emitEvent(d, config)
	}
	if w.statusCode >= 200 && w.statusCode < 300 && w.buf.Len() > 0 {
		ct := w.Header().Get("Content-Type")
		isJSON := strings.Contains(ct, "application/json")

		if config.AIRateLimitEnabled() {
			aiEvents := detectAIRateLimit(w.buf.String(), path, method)
			for _, d := range aiEvents {
				emitEvent(d, config)
			}
		}

		if config.TenantAware != nil && isJSON {
			auth := headers.Get("authorization")
			token := ""
			if strings.HasPrefix(auth, "Bearer ") {
				token = auth[7:]
			}
			claims := extractTokenClaims(token)
			tenantID := extractTenantFromJwt(claims, config.TenantAware.JWTClaim)
			if tenantID != "" {
				var respBody interface{}
				if err := json.Unmarshal(w.buf.Bytes(), &respBody); err == nil {
					blocked, leaks := createTenantCheckResponse(tenantID, respBody, *config.TenantAware)
					for _, leak := range leaks {
						emitEvent(DetectionEvent{
							Type: "cross_tenant_leak", Severity: "critical",
							PatternID: "cross_tenant_mismatch",
							Description: "Cross-tenant data leak at " + leak.Path + " — value does not match tenant " + tenantID,
							Route: path, Method: method, Timestamp: nowMs(),
						}, config)
					}
					if blocked {
						body := `{"error":"Cross-tenant data leak blocked"}`
						w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
						w.ResponseWriter.WriteHeader(http.StatusForbidden)
						w.ResponseWriter.Write([]byte(body))
						return
					}
				}
			}
		}

		if config.SecretsEnabled() && isJSON {
			var bodyData interface{}
			if err := json.Unmarshal(w.buf.Bytes(), &bodyData); err == nil {
				cleaned, stripDets := stripSensitiveData(bodyData, config.StripFields)
				if len(stripDets) > 0 {
					for _, d := range stripDets {
						emitEvent(d, config)
					}
					newBody, _ := json.Marshal(cleaned)
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
					w.Header().Set("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
					w.ResponseWriter.WriteHeader(w.statusCode)
					w.ResponseWriter.Write(newBody)
					return
				}
			}
		}
	}

	w.ResponseWriter.WriteHeader(w.statusCode)
	w.ResponseWriter.Write(w.buf.Bytes())
}

type pipelineEvent struct {
	statusCode int
}

func (m *GinMiddleware) runPipeline(w http.ResponseWriter, r *http.Request, path, method string, headers http.Header, routeTemplate string) *pipelineEvent {
	ip := headers.Get("x-forwarded-for")
	if ip == "" {
		ip = r.RemoteAddr
	} else {
		ip = strings.Split(ip, ",")[0]
	}
	ip = strings.TrimSpace(ip)

	// Phase 1: Rate limit
	if m.config.RateLimitEnabled() && path != selfTestPath {
		limiter := m.generalLimiter
		if isAuthRoute(path) && (method == "POST" || method == "PUT" || method == "PATCH") {
			limiter = m.authLimiter
		}
		if limiter != nil {
			allowed, _, _ := limiter.Check(ip)
			if !allowed {
				emitEvent(DetectionEvent{
					Type: "rate_limit", Severity: "medium",
					PatternID: "rate_limit_exceeded",
					Description: "Rate limit exceeded for " + path,
					Route: path, Method: method, Timestamp: nowMs(),
				}, m.config)
				return &pipelineEvent{statusCode: 429}
			}
		}
	}

	// Phase 2: Read body once
	var bodyBytes []byte
	var bodyMap map[string]interface{}
	needsBody := m.config.InputSanitizeEnabled() || m.config.TamperEnabled() || m.config.SSRFEnabled() || m.config.PromptInjectionEnabled()
	if needsBody && (method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE") {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
		if len(bodyBytes) > 0 {
			json.Unmarshal(bodyBytes, &bodyMap)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Phase 3: Tamper
	if m.config.TamperEnabled() && bodyMap != nil {
		tamperEvents := detectBusinessLogicTamper(bodyMap, m.config.FieldConstraints, path, method)
		for _, d := range tamperEvents {
			emitEvent(d, m.config)
		}
		if m.config.StrictMode && len(tamperEvents) > 0 {
			return &pipelineEvent{statusCode: 400}
		}
	}

	// Phase 4: Input sanitize
	if m.config.InputSanitizeEnabled() {
		if bodyMap != nil {
			if block, sanitizeDets := sanitizeInput(bodyMap, 0); block {
				for _, d := range sanitizeDets {
					emitEvent(d, m.config)
				}
				if m.config.StrictMode {
					return &pipelineEvent{statusCode: 400}
				}
			}
		}

		queryMap := make(map[string]interface{})
		for k, vals := range r.URL.Query() {
			if len(vals) == 1 {
				queryMap[k] = vals[0]
			} else {
				queryMap[k] = vals
			}
		}
		if len(queryMap) > 0 {
			if _, qd := sanitizeQuery(queryMap); len(qd) > 0 {
				for _, d := range qd {
					emitEvent(d, m.config)
				}
				if m.config.StrictMode {
					return &pipelineEvent{statusCode: 400}
				}
			}
		}
	}

	// Phase 5: SSRF
	if m.config.SSRFEnabled() {
		ssrfInput := path
		if len(r.URL.RawQuery) > 0 {
			ssrfInput += " " + r.URL.RawQuery
		}
		if len(bodyBytes) > 0 {
			ssrfInput += " " + string(bodyBytes)
		}
		ssrfEvents := detectSSRF(ssrfInput)
		for _, d := range ssrfEvents {
			emitEvent(d, m.config)
		}
		if m.config.StrictMode && len(ssrfEvents) > 0 {
			return &pipelineEvent{statusCode: 403}
		}
	}

	// Phase 6: Prompt injection
	if m.config.PromptInjectionEnabled() {
		piInput := r.URL.RawQuery
		if len(bodyBytes) > 0 {
			piInput += " " + string(bodyBytes)
		}
		piEvents := detectPromptInjection(piInput)
		for _, d := range piEvents {
			emitEvent(d, m.config)
		}
		if m.config.StrictMode && len(piEvents) > 0 {
			return &pipelineEvent{statusCode: 403}
		}
	}

	// Phase 7: BOLA
	if m.config.BOLAEnabled() {
		auth := headers.Get("authorization")
		token := ""
		if strings.HasPrefix(auth, "Bearer ") {
			token = auth[7:]
		}
		tokenClaims := extractTokenClaims(token)
		template := routeTemplate
		routeParams := extractRouteParams(path)
		routeParamValues := map[string]string{}
		routeForEvent := path
		if template != "" {
			routeParams = extractRouteParams(template)
			routeParamValues = ExtractRouteParamValues(template, path)
			routeForEvent = template
		}
		if ev := detectBOLA(routeParams, nil, tokenClaims, routeForEvent, method, routeParamValues); ev != nil {
			emitEvent(*ev, m.config)
			if m.config.StrictMode {
				return &pipelineEvent{statusCode: 404}
			}
		}
	}

	// Phase 8: Missing auth (advisory)
	if m.config.MissingAuthEnabled() {
		authHeader := headers.Get("authorization")
		if ev := detectMissingAuth(path, method, authHeader); ev != nil {
			emitEvent(*ev, m.config)
		}
	}

	return nil
}

func (m *GinMiddleware) SelfTest(port int) bool {
	results := runEngineSelfTest()
	pipelineWorks := true
	for _, r := range results {
		if !r.Passed {
			pipelineWorks = false
			break
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	m.selfTestEvent = wg

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, selfTestPath))
	if err != nil {
		m.selfTestEvent = nil
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	stripped := resp.Header.Get("X-Septr-Stripped")
	responseInPipeline := stripped != ""
	m.selfTestEvent = nil

	if pipelineWorks && responseInPipeline {
		sendTestResults(results, map[string]interface{}{"runtime": "gin", "port": port, "auto": true})
		return true
	}
	return false
}
