/**
 * Map CLI patternIds to canonical backend check_ids for attach/reconcile.
 */
import { readFileSync } from "fs"
import { findChecksFile } from "./resolve-checks"

const ATTACH_MAP: Record<string, string> = JSON.parse(
  readFileSync(findChecksFile("attach-map.json"), "utf-8"),
)

export function canonicalCheckId(patternId: string, path?: string): string {
  if (patternId.startsWith("probe_")) {
    return path?.includes(".env") ? "exposed_env" : "exposed_file"
  }
  if (ATTACH_MAP[patternId]) return ATTACH_MAP[patternId]
  if (patternId.startsWith("secret_")) {
    const bare = patternId.slice("secret_".length)
    return ATTACH_MAP[patternId] ?? bare
  }
  return patternId
}
