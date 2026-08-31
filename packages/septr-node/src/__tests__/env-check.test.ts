import { afterEach, describe, expect, it, vi } from "vitest"
import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import {
  checkEnvVsDotenv,
  envDotenvCandidates,
  maskKey,
  readDotenvKey,
  resetEnvCheck,
  warnEnvVsDotenv,
} from "../core/env-check"

afterEach(() => {
  resetEnvCheck()
  delete process.env.SEPTR_SILENCE_ENV_WARNING
  vi.restoreAllMocks()
})

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "septr-env-check-"))
}

const KEY_A = "septr_live_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_ffffffffffffffffffffffffffffffff"
const KEY_B = "septr_live_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb_0123456789abcdef0123456789abcdef"

describe("env-check", () => {
  it("masks keys keeping the project id visible", () => {
    expect(maskKey("short")).toBe("***")
    expect(maskKey(KEY_A)).toBe("septr_live_aaaa…aaaa_ff…ffff")
    expect(maskKey(KEY_B)).toBe("septr_live_bbbb…bbbb_01…cdef")
  })

  it("parses quoted and plain values from .env files", () => {
    const dir = tmpDir()
    const env = path.join(dir, ".env")
    fs.writeFileSync(env, '# comment\nSEPTR_API_KEY="septr_live_aaaa"\nSEPTR_TELEMETRY_URL=\'http://x\'\n')
    expect(readDotenvKey(env, "SEPTR_API_KEY")).toBe("septr_live_aaaa")
    expect(readDotenvKey(env, "SEPTR_TELEMETRY_URL")).toBe("http://x")
    expect(readDotenvKey(env, "MISSING")).toBeUndefined()
    expect(readDotenvKey(path.join(dir, "nope.env"), "SEPTR_API_KEY")).toBeUndefined()
  })

  it("discovers cwd, parent and child .env locations", () => {
    const dir = tmpDir()
    fs.mkdirSync(path.join(dir, "sub"))
    const candidates = envDotenvCandidates(dir)
    expect(candidates).toContain(path.join(dir, ".env"))
    expect(candidates).toContain(path.join(dir, "..", ".env"))
    expect(candidates).toContain(path.join(dir, "sub", ".env"))
  })

  it("warns once when env key differs from the local .env key", () => {
    const dir = tmpDir()
    const env = path.join(dir, ".env")
    fs.writeFileSync(env, `SEPTR_API_KEY="${KEY_B}"\n`)
    const first = checkEnvVsDotenv(KEY_A, "SEPTR_API_KEY", [env])
    expect(first).toHaveLength(1)
    expect(first[0]).toContain("bbbb…bbbb")
    expect(first[0]).toContain("aaaa…aaaa")
    expect(first[0]).not.toContain("ffffffffffffffffffffffffffffffff")
    expect(checkEnvVsDotenv(KEY_A, "SEPTR_API_KEY", [env])).toEqual([])
  })

  it("is silent when the env key matches the local .env key", () => {
    const dir = tmpDir()
    const env = path.join(dir, ".env")
    fs.writeFileSync(env, `SEPTR_API_KEY="${KEY_B}"\n`)
    expect(checkEnvVsDotenv(KEY_B, "SEPTR_API_KEY", [env])).toEqual([])
  })

  it("is silent when no .env file exists", () => {
    expect(checkEnvVsDotenv(KEY_A, "SEPTR_API_KEY", [path.join(tmpDir(), ".env")])).toEqual([])
  })

  it("respects SEPTR_SILENCE_ENV_WARNING", () => {
    process.env.SEPTR_SILENCE_ENV_WARNING = "1"
    const dir = tmpDir()
    const env = path.join(dir, ".env")
    fs.writeFileSync(env, `SEPTR_API_KEY="${KEY_B}"\n`)
    expect(checkEnvVsDotenv(KEY_A, "SEPTR_API_KEY", [env])).toEqual([])
  })

  it("prints the warning to stderr via warnEnvVsDotenv", () => {
    const dir = tmpDir()
    const env = path.join(dir, ".env")
    fs.writeFileSync(env, `SEPTR_API_KEY="${KEY_B}"\n`)
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {})
    warnEnvVsDotenv(KEY_A, [env])
    expect(errorSpy).toHaveBeenCalledOnce()
    expect(String(errorSpy.mock.calls[0][0])).toContain("[septr] WARNING")
  })
})
