import type { DetectionType, DetectionEvent, BlockDetails } from "./types"

export interface DetectionLabels {
  owasp: string
  cwe: string
  remediation: string
}

const LABELS: Record<DetectionType, DetectionLabels> = {
  bola: {
    owasp: "A01:2021 - Broken Access Control",
    cwe: "CWE-285",
    remediation: "Use authorization middleware that verifies the authenticated user owns the requested resource. Never trust client-supplied IDs without server-side verification.",
  },
  secret_exposure: {
    owasp: "A07:2021 - Identification and Authentication Failures",
    cwe: "CWE-798",
    remediation: "Remove secrets from code and responses. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, Vault). Rotate any exposed credentials immediately.",
  },
  rate_limit: {
    owasp: "A04:2023 - Insecure Design",
    cwe: "CWE-799",
    remediation: "Add rate limiting middleware with sensible limits per IP or user. Use a sliding window or token bucket algorithm. Set stricter limits on auth endpoints.",
  },
  data_strip: {
    owasp: "A04:2021 - Insecure Design",
    cwe: "CWE-200",
    remediation: "Remove sensitive fields at the database/query layer before serialization. Runtime stripping is a safety net, not a fix. Use SELECT with explicit column lists.",
  },
  input_sanitize: {
    owasp: "A03:2021 - Injection",
    cwe: "CWE-79",
    remediation: "Use parameterized queries for SQL. Use templating engines that auto-escape for XSS. Never concatenate user input into queries or HTML.",
  },
  ssrf: {
    owasp: "A10:2021 - Server-Side Request Forgery",
    cwe: "CWE-918",
    remediation: "Validate and allowlist URLs before fetching. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x). Use a network-level firewall.",
  },
  prompt_injection: {
    owasp: "LLM01:2025 - Prompt Injection",
    cwe: "CWE-840",
    remediation: "Validate and sanitize user input before passing to LLMs. Use system prompts with clear role boundaries. Implement output filtering and input length limits.",
  },
  missing_auth: {
    owasp: "A07:2021 - Identification and Authentication Failures",
    cwe: "CWE-306",
    remediation: "Add authentication middleware to all non-public routes. Use JWT verification or session-based auth. Maintain an allowlist of public routes.",
  },
  business_logic_tamper: {
    owasp: "A04:2021 - Insecure Design",
    cwe: "CWE-840",
    remediation: "Enforce business rules server-side. Validate all field constraints (ranges, enums, read-only flags) before processing. Never trust client-side validation alone.",
  },
  cross_tenant_leak: {
    owasp: "A01:2021 - Broken Access Control",
    cwe: "CWE-285",
    remediation: "Apply row-level security (RLS) policies filtered by tenant ID. Verify JWT tenant claims match the requested resource before returning data.",
  },
  security_headers: {
    owasp: "A05:2021 - Security Misconfiguration",
    cwe: "CWE-693",
    remediation: "Add missing security headers (CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy) via middleware or platform settings.",
  },
  system: {
    owasp: "",
    cwe: "",
    remediation: "",
  },
  ai_rate_limit: {
    owasp: "LLM08:2025 - Excessive Agency",
    cwe: "CWE-799",
    remediation: "Implement retry logic with exponential backoff for AI API calls. Monitor usage quotas and set up alerts before hitting rate limits. Consider caching AI responses when appropriate.",
  },
}

export function getDetectionLabels(type: DetectionType): DetectionLabels {
  return LABELS[type] ?? { owasp: "", cwe: "", remediation: "" }
}

export function buildBlockDetails(ev: DetectionEvent): BlockDetails {
  const labels = getDetectionLabels(ev.type)
  return {
    type: ev.type,
    severity: ev.severity,
    location: ev.location ?? ev.route,
    pattern: ev.pattern ?? ev.patternId,
    owasp: labels.owasp,
    cwe: labels.cwe,
    description: ev.description,
    remediation: labels.remediation,
  }
}
