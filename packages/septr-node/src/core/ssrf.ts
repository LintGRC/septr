import type { DetectionEvent } from "./types"

/**
 * SSRF (Server-Side Request Forgery) detection patterns.
 *
 * Scans input strings for URLs or IP addresses that resolve to internal/private
 * networks, cloud metadata endpoints, or dangerous protocols. Designed as a
 * heuristic guard — does not replace network-level controls.
 *
 * Detection is metadata-only: it inspects string patterns, not actual DNS resolution.
 */
const SSRF_PATTERNS: [RegExp, string][] = [
  [/127\.0\.0\.\d+/g, "Loopback address (127.0.0.x)"],
  [/127\.0\.\d{1,3}\.\d{1,3}/g, "Loopback range (127.x.x.x)"],
  [/\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "Private network (10.x.x.x)"],
  [/\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b/g, "Private network (172.16-31.x.x)"],
  [/\b192\.168\.\d{1,3}\.\d{1,3}\b/g, "Private network (192.168.x.x)"],
  [/\b0\.0\.0\.0\b/g, "Unspecified address (0.0.0.0)"],
  [/\b169\.254\.169\.254\b/g, "Cloud metadata endpoint (169.254.169.254)"],
  [/metadata\.google\.internal/gi, "GCP metadata endpoint"],
  [/localhost/gi, "localhost URL"],
  [/file:\/\//gi, "Local file access (file://)"],
  [/gopher:\/\//gi, "Gopher protocol (potential SSRF vector)"],
  [/192\.0\.2\.\d+/g, "TEST-NET address (192.0.2.x)"],
  [/198\.51\.100\.\d+/g, "TEST-NET-2 address (198.51.100.x)"],
  [/203\.0\.113\.\d+/g, "TEST-NET-3 address (203.0.113.x)"],
]

/**
 * Scan a string for SSRF indicators (internal IPs, cloud metadata, dangerous protocols).
 * Returns one detection per unique pattern match.
 */
export function detectSSRF(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const seen = new Set<string>()

  for (const [regex, description] of SSRF_PATTERNS) {
    const pattern = new RegExp(regex.source, regex.flags)

    if (pattern.test(input)) {
      const patternId = `ssrf_${description.split(" ")[0].toLowerCase()}`

      if (!seen.has(patternId)) {
        seen.add(patternId)
        events.push({
          type: "ssrf",
          severity: description.includes("metadata") || description.includes("cloud") ? "critical" : "high",
          patternId,
          description,
          statusCode: 200,
          timestamp: Date.now(),
        })
      }
    }
  }

  return events
}
