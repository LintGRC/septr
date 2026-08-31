import { describe, it, expect, vi, beforeEach } from "vitest"
import { extractImportSpecifiers, checkHallucinatedPackages, clearHallucinatedCache } from "../core/hallucinated"

describe("extractImportSpecifiers", () => {
  beforeEach(() => clearHallucinatedCache())

  it("extracts import from statements", () => {
    const text = `import React from "react"; import { useState } from "react-dom";`
    const specs = extractImportSpecifiers(text)
    expect(specs).toEqual(["react", "react-dom"])
  })

  it("extracts export from statements", () => {
    const text = `export { foo } from "lodash";`
    expect(extractImportSpecifiers(text)).toEqual(["lodash"])
  })

  it("extracts require calls", () => {
    const text = `const express = require("express");`
    const specs = extractImportSpecifiers(text)
    expect(specs).toContain("express")
  })

  it("skips try/catch-guarded requires", () => {
    const text = `try { require("optional-dep") } catch(e) {} const x = require("real-dep");`
    const specs = extractImportSpecifiers(text)
    expect(specs).not.toContain("optional-dep")
    expect(specs).toContain("real-dep")
  })

  it("skips relative paths", () => {
    const text = `import foo from "./local"; import bar from "../utils";`
    expect(extractImportSpecifiers(text)).toEqual([])
  })

  it("skips node builtins", () => {
    const text = `import path from "path"; import fs from "fs";`
    expect(extractImportSpecifiers(text)).toEqual([])
  })

  it("skips node: prefixed builtins", () => {
    const text = `import { join } from "node:path";`
    expect(extractImportSpecifiers(text)).toEqual([])
  })

  it("skips asset suffixes", () => {
    const text = `import "./styles.css"; import logo from "./logo.svg";`
    expect(extractImportSpecifiers(text)).toEqual([])
  })

  it("handles scoped packages", () => {
    const text = `import { something } from "@ai/react-utils";`
    expect(extractImportSpecifiers(text)).toEqual(["@ai/react-utils"])
  })

  it("deduplicates imports", () => {
    const text = `import a from "react"; import b from "react";`
    expect(extractImportSpecifiers(text)).toEqual(["react"])
  })

  it("skips property-access requires", () => {
    const text = `t.require("something"); window.require("other");`
    expect(extractImportSpecifiers(text)).toEqual([])
  })
})

describe("checkHallucinatedPackages", () => {
  beforeEach(() => clearHallucinatedCache())

  it("flags a package that 404s on npm", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 404 }) as any
    try {
      const findings = await checkHallucinatedPackages(["@fake/nonexistent-pkg-xyz"])
      expect(findings.length).toBe(1)
      expect(findings[0].patternId).toBe("hallucinated_package")
      expect(findings[0].preview).toBe("@fake/nonexistent-pkg-xyz")
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it("does not flag a package that exists", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 200 }) as any
    try {
      const findings = await checkHallucinatedPackages(["react"])
      expect(findings.length).toBe(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it("does not flag on network errors (fail-safe)", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error")) as any
    try {
      const findings = await checkHallucinatedPackages(["some-pkg"])
      expect(findings.length).toBe(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it("caps at 60 packages", async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue({ status: 404 }) as any
    try {
      const names = Array.from({ length: 100 }, (_, i) => `fake-pkg-${i}`)
      const findings = await checkHallucinatedPackages(names)
      expect(findings.length).toBe(60)
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
