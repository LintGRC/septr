import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative, sep } from "node:path"
import { detectSecrets } from "./secrets"
import { detectSQLi, detectXSS } from "./sanitize"
import { detectSSRF } from "./ssrf"
import { extractImportSpecifiers, checkHallucinatedPackages } from "./hallucinated"
import type { DetectionEvent } from "./types"

/** Directories never scanned — vendored/generated/build trees. */
const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", ".next", ".nuxt", ".output", "build",
  "__pycache__", ".venv", "venv", "vendor", ".cache", ".pytest_cache",
  ".turbo", ".nx",
])

/** Go module cache layout: parent dir `pkg` + entry `mod` at any depth —
 *  vendored dependency trees. The corpus studies showed private-key
 *  testdata under pkg/mod is pure false positives, so it is pruned the
 *  same way node_modules is. */
function isGoModCache(parentDir: string, entry: string): boolean {
  return entry === "mod" && parentDir.split(sep).pop() === "pkg"
}

const MAX_FILE_BYTES = 4 * 1024 * 1024

const TEXT_EXT = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml",
  ".toml", ".md", ".txt", ".html", ".htm", ".css", ".sql", ".py", ".rb",
  ".go", ".rs", ".sh", ".properties", ".cfg", ".ini", ".conf",
  ".tsbuildinfo", ".env", ".local",
])

function isTextish(name: string): boolean {
  const base = name.slice(name.lastIndexOf("."))
  if (TEXT_EXT.has(base)) return true
  return name === ".env" || name.startsWith(".env.")
}

export interface ScanFinding {
  patternId: string
  engine: string
  severity: string
  description: string
  file: string
  preview: string
}

export interface Hygiene {
  gitignoreMissing: boolean
  envCommitted: boolean
  giantFiles: string[]
  curlPipe: boolean
}

export interface ScanResult {
  files: number
  findings: ScanFinding[]
  hygiene: Hygiene
  specifiers?: string[]
}

function redact(value: string): string {
  if (value.length <= 20) return "••••"
  return `${value.slice(0, 12)}…${value.length} chars`
}

function toFindings(events: DetectionEvent[], engine: string, file: string): ScanFinding[] {
  return events.map((e) => ({
    patternId: e.patternId,
    engine,
    severity: e.severity,
    description: e.description,
    file,
    preview: redact(e.pattern || e.description || ""),
  }))
}

export function scanFile(text: string, file: string): ScanFinding[] {
  const out: ScanFinding[] = []
  out.push(...toFindings(detectSecrets(text), "secrets", file))
  out.push(...toFindings(detectSQLi(text), "sanitize", file))
  out.push(...toFindings(detectXSS(text), "sanitize", file))
  out.push(...toFindings(detectSSRF(text), "ssrf", file))
  return out
}

export function scanDir(root: string): ScanResult {
  const findings: ScanFinding[] = []
  const hygiene: Hygiene = {
    gitignoreMissing: false,
    envCommitted: false,
    giantFiles: [],
    curlPipe: false,
  }
  let files = 0
  let rootGitignore = false
  const allSpecifiers: string[] = []
  const seenSpecs = new Set<string>()

  const walk = (dir: string): void => {
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const entry of entries) {
      const full = join(dir, entry)
      if (dir === root && entry === ".gitignore") {
        rootGitignore = true
        continue
      }
      if (entry.startsWith(".") && entry !== ".env" && !entry.startsWith(".env.")) {
        continue
      }
      let st: ReturnType<typeof statSync>
      try {
        st = statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        if (IGNORE_DIRS.has(entry)) continue
        if (isGoModCache(dir, entry)) continue
        walk(full)
        continue
      }
      const rel = relative(root, full)
      if (st.size > MAX_FILE_BYTES) {
        hygiene.giantFiles.push(rel)
        continue
      }
      if (entry === ".env" || entry.startsWith(".env.")) hygiene.envCommitted = true
      if (!isTextish(entry)) continue
      let text: string
      try {
        text = readFileSync(full, "utf-8")
      } catch {
        continue
      }
      files += 1
      if (!hygiene.curlPipe && /curl[^\n]*\|\s*(ba)?sh/i.test(text)) {
        hygiene.curlPipe = true
      }
      findings.push(...scanFile(text, rel))
      for (const spec of extractImportSpecifiers(text)) {
        if (!seenSpecs.has(spec)) {
          seenSpecs.add(spec)
          allSpecifiers.push(spec)
        }
      }
    }
  }

  walk(root)
  hygiene.gitignoreMissing = !rootGitignore
  return { files, findings, hygiene, specifiers: allSpecifiers }
}

/** Like scanDir, but also checks import specifiers against the npm registry
 *  for hallucinated packages. Returns a promise. */
export async function scanDirAsync(root: string): Promise<ScanResult> {
  const result = scanDir(root)
  const hallucinated = await checkHallucinatedPackages(result.specifiers ?? [])
  for (const f of hallucinated) {
    f.file = "(import analysis)"
    result.findings.push(f)
  }
  return result
}
