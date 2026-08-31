import type { DetectionEvent, DetectionSeverity } from "./types"

type SecretPattern = [
  id: string,
  regex: RegExp,
  description: string,
  severity: DetectionSeverity,
  verify?: (raw: string) => boolean,
  redactable?: boolean,
]

const SECRET_PATTERNS: SecretPattern[] = [
  ["openai", /sk-proj-[A-Za-z0-9_-]{20,}/g, "OpenAI API key", "high"],
  ["openai_legacy", /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, "OpenAI legacy key", "high"],
  ["openai_svc", /sk-svcacct-[A-Za-z0-9_-]{20,}/g, "OpenAI service account key", "high"],
  ["openai_admin", /sk-admin-[A-Za-z0-9_-]{20,}/g, "OpenAI admin key", "critical"],
  ["anthropic", /sk-ant-api03-[A-Za-z0-9_-]{20,}/g, "Anthropic API key", "high"],
  ["stripe_live", /sk_live_[A-Za-z0-9]{20,}/g, "Stripe live secret key", "high"],
  ["stripe_test", /sk_test_[A-Za-z0-9]{20,}/g, "Stripe test secret key", "medium"],
  ["stripe_restricted", /rk_live_[A-Za-z0-9]{20,}/g, "Stripe restricted key", "high"],
  ["aws_access", /AKIA[0-9A-Z]{16}/g, "AWS access key ID", "high"],
  ["aws_session", /ASIA[0-9A-Z]{16}/g, "AWS session token key ID", "high"],
  ["aws_secret", /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g, "AWS secret access key", "high", awsSecretLike],
  ["github_pat", /ghp_[A-Za-z0-9]{36}/g, "GitHub personal access token", "high"],
  ["github_fine_grained", /github_pat_[A-Za-z0-9_]{20,}/g, "GitHub fine-grained token", "high"],
  ["github_oauth", /gho_[A-Za-z0-9]{36}/g, "GitHub OAuth token", "high"],
  ["github_app", /(?:ghu|ghs)_[A-Za-z0-9]{36}/g, "GitHub app token", "high"],
  ["slack_bot", /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, "Slack bot token", "high"],
  ["slack_user", /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/g, "Slack user token", "high"],
  ["slack_webhook", /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/g, "Slack webhook URL", "high"],
  ["google_api", /AIza[0-9A-Za-z_-]{35}/g, "Google API key (browser public)", "low", undefined, false],
  ["google_client_secret", /GOCSPX-[A-Za-z0-9_-]{20,}/g, "Google OAuth client secret", "high"],
  ["sendgrid", /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, "SendGrid API key", "high"],
  ["twilio", /SK[0-9a-fA-F]{32}/g, "Twilio API key", "high"],
  ["shopify", /sh(?:pat|pss)_[0-9a-fA-F]{32}/g, "Shopify access token", "high"],
  ["mailchimp", /[0-9a-f]{32}-us[0-9]{1,2}/g, "Mailchimp API key", "medium"],
  ["discord_bot", /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g, "Discord bot token", "high"],
  ["azure_storage", /AccountKey=[A-Za-z0-9+/=]{88}/g, "Azure Storage account key", "high"],
  ["npm_token", /npm_[A-Za-z0-9]{36}/g, "npm access token", "high"],
  ["supabase_service_role", /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, "Supabase service_role key", "critical", jwtHasRole("service_role")],
  ["supabase_anon", /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, "Supabase anon key (public)", "low", jwtHasRole("anon"), false],
  ["generic_jwt", /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, "JWT token", "medium", notSupabaseAnon],
  ["private_key", /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g, "Private key", "critical"],
  ["database_uri", /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s]+:[^\s]+@[^\s]+/g, "Database URI with credentials", "high"],
]

function base64UrlDecode(str: string): string {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/")
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
  return atob(padded)
}

function awsSecretLike(text: string): boolean {
  if (text.length !== 40) return false
  let upper = 0
  let lower = 0
  let digits = 0
  for (const c of text) {
    if (c >= "A" && c <= "Z") upper++
    else if (c >= "a" && c <= "z") lower++
    else if (c >= "0" && c <= "9") digits++
  }
  return upper >= 4 && lower >= 4 && digits >= 1
}

function jwtHasRole(role: string): (token: string) => boolean {
  return (token: string) => {
    try {
      const parts = token.split(".")
      if (parts.length !== 3) return false
      const payload = JSON.parse(base64UrlDecode(parts[1]))
      return typeof payload === "object" && payload !== null && payload.role === role
    } catch {
      return false
    }
  }
}

/** Return true when the JWT is NOT a Supabase anon key (anon JWTs are
 *  public-by-design; the role claim is "anon"). */
function notSupabaseAnon(token: string): boolean {
  try {
    const parts = token.split(".")
    if (parts.length !== 3) return true
    const payload = JSON.parse(base64UrlDecode(parts[1]))
    return !(typeof payload === "object" && payload !== null && payload.role === "anon")
  } catch {
    return true
  }
}

export const DEFAULT_SENSITIVE_KEYS = [
  "password",
  "password_hash",
  "passwordHash",
  "secret",
  "secret_key",
  "secretKey",
  "api_key",
  "apiKey",
  "private_key",
  "privateKey",
  "stripe_secret",
  "stripeSecret",
  "ssn",
  "credit_card",
  "creditCard",
  "token",
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "authorization",
]

// ── keyword + entropy detection (advisory) ──

const ENTROPY_ASSIGN_RE =
  /["']?(?:apiKey|api_key|apiSecret|api_secret|secret|secretKey|secret_key|clientSecret|client_secret|token|accessToken|access_token|refreshToken|refresh_token|password|privateKey|private_key|bearerToken|authToken)["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']/g
const ENTROPY_THRESHOLD = 3.5
const PURE_HEX_DASH_RE = /^[0-9a-fA-F\-]+$/

function charClasses(value: string): number {
  let classes = 0
  if (/[a-z]/.test(value)) classes++
  if (/[A-Z]/.test(value)) classes++
  if (/[0-9]/.test(value)) classes++
  if (/[+/=_.-]/.test(value)) classes++
  return classes
}

function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / value.length
    if (p > 0) entropy -= p * Math.log2(p)
  }
  return entropy
}

function matchesSpecificPattern(value: string): boolean {
  for (const [, regex] of SECRET_PATTERNS) {
    const pattern = new RegExp(regex.source, regex.flags)
    if (pattern.test(value)) return true
  }
  return false
}

/** Known-public, publishable key prefixes — these are safe for client use and
 *  should never trigger the high-entropy advisory detector. */
const PUBLISHABLE_PREFIXES = ["pk_live_", "pk_test_", "pk_prod_", "pk.", "phc_", "phx_"]

function isPublishableKey(value: string): boolean {
  return PUBLISHABLE_PREFIXES.some((p) => value.startsWith(p))
}

/** Advisory detection: high-entropy values assigned to secret-like keys.
 * Never used for redaction — telemetry only. Values already matched by a
 * specific pattern are skipped. */
export function detectHighEntropySecrets(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const pattern = new RegExp(ENTROPY_ASSIGN_RE.source, ENTROPY_ASSIGN_RE.flags)
  let match = pattern.exec(input)

  while (match !== null) {
    const value = match[1]
    if (value.length <= 128 && charClasses(value) >= 3 && !PURE_HEX_DASH_RE.test(value) && !matchesSpecificPattern(value) && !isPublishableKey(value) && shannonEntropy(value) >= ENTROPY_THRESHOLD) {
      events.push({
        type: "secret_exposure",
        severity: "medium",
        patternId: "secret_high_entropy",
        description: "High-entropy value assigned to a secret-like key (possible API key or token)",
        statusCode: 200,
        timestamp: Date.now(),
      })
    }
    match = pattern.exec(input)
  }

  return events
}

/** Scan a string for known secret patterns (API keys, tokens, credentials). Returns zero or more detections. */
export function detectSecrets(input: string, customPatterns?: string[]): DetectionEvent[] {
  const events: DetectionEvent[] = []

  for (const [id, regex, description, severity, verify, redactable] of SECRET_PATTERNS) {
    const pattern = new RegExp(regex.source, regex.flags)
    let match = pattern.exec(input)

    while (match !== null) {
      if (!verify || verify(match[0])) {
        events.push({
          type: "secret_exposure",
          severity,
          patternId: `secret_${id}`,
          description,
          statusCode: 200,
          timestamp: Date.now(),
          redactable: redactable === false ? false : undefined,
        })
      }

      match = pattern.exec(input)
    }
  }

  for (const patternStr of customPatterns ?? []) {
    try {
      const regex = new RegExp(patternStr, "g")
      let match = regex.exec(input)

      while (match !== null) {
        events.push({
          type: "secret_exposure",
          severity: "high",
          patternId: "secret_custom",
          description: "Custom pattern match detected",
          statusCode: 200,
          timestamp: Date.now(),
        })

        match = regex.exec(input)
      }
    } catch {
      // skip invalid regex
    }
  }

  return events
}

/** Check if a key name matches a sensitive field that should be redacted from responses. */
export function shouldStripKey(key: string, customFields?: string[]): boolean {
  if (!key) return false
  const normalized = key.toLowerCase().replace(/[_-]/g, "")
  const allSensitive = customFields !== undefined ? customFields : DEFAULT_SENSITIVE_KEYS

  return allSensitive.some((field) => {
    const normalizedField = field.toLowerCase().replace(/[_-]/g, "")
    return normalized === normalizedField
  })
}
