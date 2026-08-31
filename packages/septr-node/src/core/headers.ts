import type { DetectionEvent } from "./types"

const SECURITY_HEADER_CHECKS: [string, string, "medium" | "low"][] = [
  ["Content-Security-Policy", "Content-Security-Policy header missing", "medium"],
  ["Strict-Transport-Security", "Strict-Transport-Security (HSTS) header missing", "medium"],
  ["X-Content-Type-Options", "X-Content-Type-Options header missing", "medium"],
  ["X-Frame-Options", "X-Frame-Options header missing", "medium"],
  ["Referrer-Policy", "Referrer-Policy header missing", "low"],
]

/** Advisory: report responses missing standard security headers.
 * Detection-only — Septr never injects headers (values like CSP are app-specific). */
export function detectMissingSecurityHeaders(
  headers: Headers | Record<string, string | string[] | undefined> | Map<string, string>,
): DetectionEvent[] {
  const present = new Set<string>()

  if (headers instanceof Headers) {
    headers.forEach((_, key) => present.add(key.toLowerCase()))
  } else if (headers instanceof Map) {
    for (const key of headers.keys()) present.add(key.toLowerCase())
  } else {
    for (const key of Object.keys(headers)) present.add(key.toLowerCase())
  }

  const events: DetectionEvent[] = []
  for (const [name, description, severity] of SECURITY_HEADER_CHECKS) {
    if (!present.has(name.toLowerCase())) {
      events.push({
        type: "security_headers",
        severity,
        patternId: "missing_security_header",
        description,
        statusCode: 200,
        timestamp: Date.now(),
      })
    }
  }
  return events
}
