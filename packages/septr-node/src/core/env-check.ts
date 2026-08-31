import * as fs from "fs"
import * as path from "path"

let warned = false

const SILENCE_VALUES = new Set(["1", "true", "yes"])
const KEY_RE = /^(septr_live_|vs_live_)([0-9a-fA-F-]{36})_([0-9a-fA-F]{32})$/

/** Mask an API key for display, keeping the embedded project id visible
 *  (the id is what identifies the *wrong* project in a misrouting scenario). */
export function maskKey(key: string): string {
  const m = KEY_RE.exec(key)
  if (m) {
    return `${m[1]}${m[2].slice(0, 4)}…${m[2].slice(-4)}_${m[3].slice(0, 2)}…${m[3].slice(-4)}`
  }
  if (key.length <= 12) return "***"
  return `${key.slice(0, 8)}…${key.slice(-4)}`
}

/** Best-effort parse of KEY=VALUE from a .env file (no deps). */
export function readDotenvKey(file: string, keyName: string): string | undefined {
  let content: string
  try {
    content = fs.readFileSync(file, "utf8")
  } catch {
    return undefined
  }
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    const eq = line.indexOf("=")
    if (eq < 0) continue
    if (line.slice(0, eq).trim() !== keyName) continue
    let value = line.slice(eq + 1).trim()
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) {
      value = value.slice(1, -1)
    }
    return value
  }
  return undefined
}

/** Likely locations for the app's .env file, nearest first. */
export function envDotenvCandidates(cwd?: string): string[] {
  const base = cwd ?? process.cwd()
  const candidates = [path.join(base, ".env"), path.join(base, "..", ".env")]
  try {
    for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        candidates.push(path.join(base, entry.name, ".env"))
      }
    }
  } catch {
    // cwd unreadable — fall through with the basics
  }
  return candidates
}

/** Return warning lines when the process env key differs from the key in a
 *  discovered local .env file. Fires at most once per process. */
export function checkEnvVsDotenv(
  envKey: string | undefined,
  keyName = "SEPTR_API_KEY",
  candidates?: string[],
): string[] {
  if (warned || !envKey) return []
  const silence = process.env.SEPTR_SILENCE_ENV_WARNING
  if (silence && SILENCE_VALUES.has(silence.trim().toLowerCase())) return []
  for (const file of candidates ?? envDotenvCandidates()) {
    const local = readDotenvKey(file, keyName)
    if (local && local !== envKey) {
      warned = true
      return [
        `⚠️  [septr] WARNING: the ${keyName} in this process environment (${maskKey(envKey)}) does not match the one in ${file} (${maskKey(local)}). Telemetry may be routing to the wrong project. Check for ${keyName} exported by your shell or launch script — it overrides the app's .env file.`,
      ]
    }
  }
  return []
}

/** Print the env-vs-.env mismatch warning to stderr (once). */
export function warnEnvVsDotenv(envKey: string | undefined, candidates?: string[]): void {
  for (const line of checkEnvVsDotenv(envKey, "SEPTR_API_KEY", candidates)) {
    console.error(line)
  }
}

/** Reset the once-per-process guard (test helper). */
export function resetEnvCheck(): void {
  warned = false
}
