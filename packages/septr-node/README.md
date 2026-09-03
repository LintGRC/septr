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

## Express

```js
import { createSeptr } from "septr"

app.use(createSeptr({ apiKey: process.env.SEPTR_API_KEY }))
```

## Next.js

Create `middleware.ts` (or `src/middleware.ts`) at the project root:

```ts
import { createSeptr } from "septr"

export default createSeptr({ apiKey: process.env.SEPTR_API_KEY })

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
```

## Hono

```ts
import { createSeptr } from "septr"

app.use("*", createSeptr({ apiKey: process.env.SEPTR_API_KEY }))
```

## Fastify

```ts
import { createSeptr } from "septr"

const shield = createSeptr({ apiKey: process.env.SEPTR_API_KEY })
fastify.addHook("onRequest", shield.onRequest)
fastify.addHook("preHandler", shield.preHandler)
fastify.addHook("preSerialization", shield.preSerialization)
```

## Config

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | string | env `SEPTR_API_KEY` | Backend API key |
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
| `telemetryUrl` | string | `https://api.septr.com/v1/events` | Telemetry endpoint |
| `remoteConfig` | boolean | `true` | Poll backend for live config |

## Source scanning (CLI)

```bash
npx septr scan .            # scan the current directory
npx septr scan . --json    # machine-readable findings
npx septr scan . --exclude "src/__tests__/**"   # skip paths (repeatable)
```

Exclude paths with a committed `.septrignore` file (gitignore-style patterns) in your project root — exclusions are explicit and auditable. Test fixture payloads (`__tests__/benchmark/**`, `*-payloads.*`, `fixtures/**`) are skipped by default; everything else, including tests, is scanned.

## Environment variables

- `SEPTR_API_KEY` — your project key
- `SEPTR_SILENCE_ENV_WARNING` — set to `1` to silence the fail-loud
  missing-key warning
- `SEPTR_REMOTE_CONFIG=false` — disable remote config polling

## License

MIT
