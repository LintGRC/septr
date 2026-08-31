export type DetectionSeverity = "info" | "low" | "medium" | "high" | "critical"

export type DetectionType =
  | "secret_exposure"
  | "bola"
  | "rate_limit"
  | "data_strip"
  | "input_sanitize"
  | "ssrf"
  | "prompt_injection"
  | "missing_auth"
  | "business_logic_tamper"
  | "cross_tenant_leak"
  | "ai_rate_limit"
  | "security_headers"
  | "system"

export interface DetectionEvent {
  type: DetectionType
  severity: DetectionSeverity
  patternId: string
  description: string
  route?: string
  method?: string
  statusCode?: number
  timestamp: number
  location?: string
  pattern?: string
  /** When false the event is advisory/telemetry-only and must NOT trigger
   *  value redaction in stripSensitiveData. */
  redactable?: boolean
}

export interface RateLimitConfig {
  max: number
  windowMs: number
}

export type FieldConstraint =
  | { field: string; constraint: { type: "readonly" } }
  | { field: string; constraint: { type: "range"; min?: number; max?: number } }
  | { field: string; constraint: { type: "enum"; values: (string | number)[] } }

export interface SeptrConfig {
  apiKey?: string
  projectId?: string
  strictMode?: boolean
  secrets?: boolean
  bola?: boolean
  rateLimit?: boolean
  inputSanitize?: boolean
  ssrf?: boolean
  promptInjection?: boolean
  aiRateLimit?: boolean
  tamper?: boolean
  stripFields?: string[]
  telemetry?: boolean
  telemetryUrl?: string
  /** Poll the Septr backend for live config (strictMode, engine toggles). Default: on when apiKey is set. */
  remoteConfig?: boolean
  /** Remote-config poll interval in ms. Default: 60_000. */
  configPollMs?: number
  selfTest?: boolean
  rateLimitConfig?: RateLimitConfig
  sensitivePatterns?: string[]
  fieldConstraints?: FieldConstraint[]
  tenantAware?: TenantAwareConfig
  /** Set automatically by adapters; reported to the backend as the runtime. */
  framework?: string
  /** Route templates (e.g. `/api/users/:userId`) for BOLA detection in
   * frameworks where the matched route pattern isn't exposed (Next.js Edge).
   * Without these, BOLA falls back to presence-based flagging on raw paths. */
  bolaRouteTemplates?: string[]
}

export interface TenantAwareConfig {
  tenantColumn: string
  jwtClaim: string
  blockOnMismatch?: boolean
}

export interface BlockDetails {
  type: DetectionType
  severity: DetectionSeverity
  location?: string
  pattern?: string
  owasp: string
  cwe: string
  description: string
  remediation: string
}

export interface TelemetryPayload {
  events: Omit<DetectionEvent, "timestamp">[]
  projectId: string
  packageName: string
  packageVersion: string
  environment: string
  schemaVersion: string
  framework?: string
}

export interface RateLimitEntry {
  count: number
  windowStart: number
}
