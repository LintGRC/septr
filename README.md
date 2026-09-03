# septr — runtime security for AI-generated apps

[![npm version](https://img.shields.io/npm/v/septr?color=3d7dd8&label=npm)](https://www.npmjs.com/package/septr)
[![PyPI version](https://img.shields.io/pypi/v/septr?color=3d7dd8&label=pypi)](https://pypi.org/project/septr/)
[![License: MIT](https://img.shields.io/badge/license-MIT-3d7dd8)](LICENSE)

Septr is an open-source security layer for AI-generated apps. It scans deployed apps for exposed secrets, missing security headers, vulnerable dependencies, and exposed files — then protects the runtime with in-process middleware.

**Every AI app leaks something. Yours doesn't have to.**

- **Scan** — URL probe of a deployed app: leaked API keys, `.env` exposure, missing headers, known-vulnerable frontend libraries, exposed admin routes.
- **Protect** — runtime middleware that detects and (optionally) blocks secret leaks, BOLA/IDOR, missing auth, business-logic tampering, PII in responses, prompt injection, SSRF, and missing rate limits.
- **Monitor** — dashboard with security score, threat log, and per-engine evidence.

Try it free: **[septr.dev](https://septr.dev)** · Docs: **[septr.dev/docs.html](https://septr.dev/docs.html)**

## Supported frameworks

| Language | Frameworks | Install |
|---|---|---|
| Node.js | Express, Next.js, Hono, Fastify | `npm install septr` |
| Python | FastAPI, Flask | `pip install septr` |
| Go | Gin, net/http | `go get github.com/lintgrc/septr/packages/septr-go` |

## Quick start (Express)

```bash
npm install septr
```

Add your key to `.env`:

```
SEPTR_API_KEY=septr_live_...
```

```js
import { createSeptr } from "septr"

app.use(createSeptr({ apiKey: process.env.SEPTR_API_KEY }))
```

That's it. Septr verifies the connection on your app's first request and starts protecting every route.

## Quick start (FastAPI)

```bash
pip install septr
```

```python
from fastapi import FastAPI
from septr.adapters.fastapi import SeptrASGIMiddleware
import os

app = FastAPI()

app.add_middleware(
    SeptrASGIMiddleware,
    api_key=os.getenv("SEPTR_API_KEY")
)
```

## Detection engines

- **Secret/PII leak** — 22 patterns for API keys, tokens, credentials in responses; auto-scrubs with `[REDACTED]`
- **BOLA/IDOR** — JWT claims vs. route params
- **SQLi / XSS / NoSQLi** — input sanitization
- **SSRF** — heuristics on outbound URLs
- **Prompt injection** — 24 jailbreak patterns for AI endpoints
- **Missing auth** — unauthenticated route detection
- **Business-logic tampering** — request mutation detection
- **Rate limiting** — 60/min general, 10/min auth, 5/min AI
- **Missing security headers** — detection and injection
- **Cross-tenant leaks** — multi-tenant isolation checks

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | string | env `SEPTR_API_KEY` | Your project API key |
| `strictMode` | boolean | `false` | Block requests instead of detecting |
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

## Fail-open guarantee

If Septr ever throws, it logs the error and passes the request through. Your app never goes down because of its bodyguard.

## Repo layout

- `packages/septr-node` — Node.js middleware + CLI (published to npm)
- `packages/septr-python` — Python middleware (published to PyPI)
- `packages/septr-go` — Go middleware
- `packages/septr-checks` — shared detection rules (JSON)

## License

MIT