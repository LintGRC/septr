import { readFileSync } from "node:fs"
import { defineConfig } from "tsup"

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8")) as {
  version?: string
}

export default defineConfig({
  define: {
    __SEPTR_VERSION__: JSON.stringify(pkg.version || "0.1.0"),
  },
  entry: {
    "core/index": "src/core/index.ts",
    "core/scan": "src/core/scan.ts",
    "core/probe": "src/core/probe.ts",
    "adapters/express": "src/adapters/express.ts",
    "adapters/nextjs": "src/adapters/nextjs.ts",
    "adapters/hono": "src/adapters/hono.ts",
    "adapters/fastify": "src/adapters/fastify.ts",
    "cli": "src/cli.ts",
  },
  format: ["esm"],
  dts: true,
  clean: true,
  target: "es2022",
  outDir: "dist",
  splitting: false,
})
