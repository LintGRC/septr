/**
 * Map CLI patternIds to canonical backend check_ids, names, and severities
 * for attach/reconcile.
 *
 * The dashboard scanner (backend/scanner/checks.py) is the canonical source
 * for url_scan incidents: it matches findings by (check_id, name), so a CLI
 * attach must send the *same* pair or it duplicates the incident instead of
 * updating it. Names/severities below mirror backend/scanner/checks.py.
 */
import { readFileSync } from "fs"
import { findChecksFile } from "./resolve-checks"

const ATTACH_MAP: Record<string, string> = JSON.parse(
  readFileSync(findChecksFile("attach-map.json"), "utf-8"),
)

const CANONICAL: Record<string, { name: string; severity: string }> = JSON.parse(
  readFileSync(findChecksFile("canonical-checks.json"), "utf-8"),
)

export interface CanonicalFinding {
  checkId: string
  /** Canonical incident name when the check has one (matches the web scanner). */
  name?: string
  /** Canonical severity when the check has one. */
  severity?: string
}

export function canonicalFinding(patternId: string, path?: string): CanonicalFinding {
  if (patternId === "missing_header") {
    // Already canonical: the URL probe emits web-scanner labels/severities.
    return { checkId: "missing_header" }
  }
  if (patternId.startsWith("probe_")) {
    return { checkId: path?.includes(".env") ? "exposed_env" : "exposed_file" }
  }
  const checkId =
    ATTACH_MAP[patternId] ??
    (patternId.startsWith("secret_") ? patternId.slice("secret_".length) : patternId)
  const canonical = CANONICAL[checkId]
  return { checkId, name: canonical?.name, severity: canonical?.severity }
}

export function canonicalCheckId(patternId: string, path?: string): string {
  return canonicalFinding(patternId, path).checkId
}
