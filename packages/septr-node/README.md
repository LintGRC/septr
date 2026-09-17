# septr — runtime security middleware for Node.js

Protects Express, Next.js, Hono, and Fastify apps at runtime: secrets
leaking in responses, BOLA/IDOR, missing auth, business-logic tampering,
PII, prompt injection, SSRF, and missing rate limits. Auto-verified against
the Septr backend, with per-engine SOC 2 evidence for your dashboard.

## Install

```bash
npm install septr
```

Add your key to `.env`:

```
SEPTR_API_KEY=septr_live_...
```

Telemetry and auto-verification are **on by default** whenever
`SEPTR_API_KEY` is set. Set `telemetry: false` to run detection only
locally.

## Express

```js
import { createSeptr } from "septr/express"

app.use(createSeptr({ apiKey: process.env.SEPTR_API_KEY }))
```

## Next.js

Create `middleware.ts` (or `src/middleware.ts`) at the project root:

```ts
import { createSeptr } from "septr/nextjs"

export const middleware = createSeptr({ apiKey: process.env.SEPTR_API_KEY })

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
```

## Hono

```ts
import { createSeptr } from "septr/hono"

app.use("*", createSeptr({ apiKey: process.env.SEPTR_API_KEY }))
```

## Fastify

```ts
import { createSeptr } from "septr/fastify"

const shield = createSeptr({ apiKey: process.env.SEPTR_API_KEY })
fastify.addHook("onRequest", shield.onRequest)
fastify.addHook("preHandler", shield.preHandler)
fastify.addHook("preSerialization", shield.preSerialization)
```

## Config

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | string | env `SEPTR_API_KEY` | Backend API key |
| `telemetry` | boolean | `true` | Send detections to the dashboard |
| `telemetryUrl` | string | `https://app.septr.dev/v1/events` | Telemetry endpoint |
| `projectId` | string | derived from key | Project id; auto-read from `septr_live_*` keys |
| `strictMode` | boolean | `false` | Block instead of detect |
| `secrets` | boolean | `true` | Secret/PII detection + response scrubbing |
| `bola` | boolean | `true` | BOLA/IDOR detection |
| `rateLimit` | boolean | `true` | Per-route rate limiting |
| `inputSanitize` | boolean | `true` | SQLi/XSS/NoSQLi sanitization |
| `ssrf` | boolean | `true` | SSRF heuristics |
| `promptInjection` | boolean | `true` | Prompt-injection shielding |
| `aiRateLimit` | boolean | `true` | Rate limiting for AI endpoints |
| `tamper` | boolean | `true` | Business-logic tamper detection |
| `missingAuth` | boolean | `true` | Missing-auth detection |
| `stripFields` | string[] | `[]` | Fields to strip from responses |
| `maxResponseScanBytes` | number | `1000000` | Max response size scanned (chars); larger responses stream through unscanned |
| `maxRequestInspectBytes` | number | `256000` | Max request body inspected (chars); larger bodies stream through untouched |
| `engineFailureThreshold` | number | `3` | Consecutive engine failures before the breaker skips that engine |
| `engineBudgetMs` | number | `50` | Per-engine time budget; slower calls count as failures |
| `disabled` | boolean | `false` | Emergency bypass — pass every request through untouched |
| `securityHeaders` | boolean | `true` | Report responses missing security headers |
| `remoteConfig` | boolean | `true` | Poll backend for live config |

## Source scanning (CLI)

```bash
npx septr scan .            # scan the current directory
npx septr scan . --json    # machine-readable findings
npx septr scan . --exclude "src/__tests__/**"   # skip paths (repeatable)
```

Exclude paths with a committed `.septrignore` file (gitignore-style patterns, anchored to the directory it lives in; nested files are honored when scanning a parent directory) — exclusions are explicit and auditable. Test fixture payloads (`__tests__/benchmark/**`, `*-payloads.*`, `fixtures/**`, at any depth) are skipped by default; everything else, including tests, is scanned. The summary line separates files scanned, files ignored by rules, and entries skipped entirely (dependency/build dirs, hidden files, non-source files).

## Deployed-app scanning (CLI)

```bash
npx septr scan https://your-app.example.com
```

Probes a deployed app for exposed secrets, sensitive paths, and missing security headers. Fetches up to 30 JS bundles from `<script src>` tags and scans them for leaked keys. Checks `/package.json` and `/requirements.txt` for secrets. Reports missing HSTS, CSP, and clickjack protection headers.

## Environment variables

- `SEPTR_API_KEY` — your project key
- `SEPTR_SILENCE_ENV_WARNING` — set to `1` to silence the fail-loud
  missing-key warning
- `SEPTR_REMOTE_CONFIG=false` — disable remote config polling

Telemetry endpoint overrides go in config (`telemetryUrl`), not an env var.

## License

MIT
