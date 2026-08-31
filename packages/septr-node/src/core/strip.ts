import { shouldStripKey, detectSecrets, detectHighEntropySecrets, DEFAULT_SENSITIVE_KEYS } from "./secrets"
import type { DetectionEvent } from "./types"

/** Safety limits to prevent unbounded recursive walks on large payloads. */
const MAX_DEPTH = 5
const MAX_ARRAY_ITEMS = 1000
const MAX_STRING_LENGTH = 10_000

/** Recursively walk a response payload, redacting sensitive field values (by key name or embedded secret patterns). Returns the cleaned object and detection events. */
export function stripSensitiveData(
  obj: unknown,
  customFields?: string[],
): { cleaned: unknown; detections: DetectionEvent[] } {
  const detections: DetectionEvent[] = []
  const allSensitive = customFields ? [...DEFAULT_SENSITIVE_KEYS, ...customFields] : undefined

  function clean(value: unknown, depth = 0): unknown {
    if (depth > MAX_DEPTH) return value
    if (value === null || value === undefined) return value

    if (typeof value === "string") {
      if (value.length > MAX_STRING_LENGTH) return value
      const specific = detectSecrets(value)
      const entropy = detectHighEntropySecrets(value)
      if (specific.length > 0 || entropy.length > 0) {
        detections.push(...specific, ...entropy)
        // Only confirmed, redactable patterns trigger value redaction.
        // Advisory matches (e.g. Google API browser keys, Supabase anon)
        // are telemetry-only — redacting them would mangle legitimate data.
        const redactable = specific.filter((e) => e.redactable !== false)
        if (redactable.length > 0) {
          return "[REDACTED]"
        }
      }
      return value
    }

    if (Array.isArray(value)) {
      const limit = Math.min(value.length, MAX_ARRAY_ITEMS)
      const sliced = value.slice(0, limit)
      return sliced.map((item) => clean(item, depth + 1))
    }

    if (typeof value === "object") {
      const cleaned: Record<string, unknown> = {}

      for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
        if (shouldStripKey(key, allSensitive)) {
          detections.push({
            type: "data_strip",
            severity: "medium",
            patternId: "strip_field",
            description: `Field \`${key}\` stripped from response`,
            statusCode: 200,
            timestamp: Date.now(),
          })
          cleaned[key] = "[REDACTED]"
        } else {
          cleaned[key] = clean(val, depth + 1)
        }
      }

      return cleaned
    }

    return value
  }

  const cleaned = clean(obj)
  return { cleaned, detections }
}
