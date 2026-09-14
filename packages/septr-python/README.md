# septr — runtime security middleware for Python

Protects FastAPI and Flask apps at runtime: secrets leaking in responses,
BOLA/IDOR, missing auth, business-logic tampering, PII, prompt injection,
SSRF, and missing rate limits. Auto-verified against the Septr backend,
with per-engine SOC 2 evidence for your dashboard.

## Install

```bash
pip install septr
```

Add your key to `.env`:

```
SEPTR_API_KEY=septr_live_...
```

Telemetry, heartbeat, and auto-verification are **on by default** whenever
`SEPTR_API_KEY` is set. Set `"telemetry": False` to run detection only
locally.

## FastAPI

```python
from fastapi import FastAPI
from septr import create_septr
import os

app = FastAPI()

create_septr(app, {
    "apiKey": os.getenv("SEPTR_API_KEY"),
})
```

(`from septr.adapters.fastapi import create_septr` works too.)

## Flask

```python
from flask import Flask
from septr import create_septr_flask
import os

app = Flask(__name__)
# ... your routes ...
create_septr_flask(app, {"apiKey": os.getenv("SEPTR_API_KEY")})
```

(`from septr.adapters.flask import create_septr` works too.)

## Config

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | str | env `SEPTR_API_KEY` | Backend API key |
| `telemetry` | bool | `True` | Send detections + heartbeat to the dashboard |
| `telemetry_url` | str | `https://app.septr.dev/v1/events` | Telemetry endpoint |
| `projectId` | str | derived from key | Project id; auto-read from `septr_live_*` keys |
| `strictMode` | bool | `False` | Block instead of detect |
| `secrets` | bool | `True` | Secret/PII detection + response scrubbing |
| `bola` | bool | `True` | BOLA/IDOR detection |
| `rateLimit` | bool | `True` | Per-route rate limiting |
| `inputSanitize` | bool | `True` | SQLi/XSS/NoSQLi sanitization |
| `ssrf` | bool | `True` | SSRF heuristics |
| `promptInjection` | bool | `True` | Prompt-injection shielding |
| `aiRateLimit` | bool | `True` | Rate limiting for AI endpoints |
| `tamper` | bool | `True` | Business-logic tamper detection |
| `missingAuth` | bool | `True` | Missing-auth detection |
| `publicRoutes` | list[str] | `[]` | Path prefixes treated as public (e.g. `["/api/v1/feed"]`) |
| `publicRoutesExact` | list[str] | `[]` | Exact paths treated as public (e.g. `["/"]`) |
| `stripFields` | list[str] | `[]` | Fields to strip from responses |
| `maxResponseScanBytes` | int | `262144` | Max response size scanned (bytes); larger responses stream through unscanned |
| `maxRequestInspectBytes` | int | `262144` | Max request body inspected (bytes); larger bodies stream through untouched |
| `engineFailureThreshold` | int | `3` | Consecutive engine failures before the breaker skips that engine |
| `engineBudgetMs` | float | `50.0` | Per-engine time budget; slower calls count as failures |
| `disabled` | bool | `False` | Emergency bypass — pass every request through untouched |
| `securityHeaders` | bool | `True` | Report responses missing security headers (disable when another layer manages them) |

## Environment variables

- `SEPTR_API_KEY` — your project key
- `SEPTR_TELEMETRY_URL` — override the telemetry endpoint
  (e.g. `http://127.0.0.1:8000/v1/events` for a local backend)
- `SEPTR_HEARTBEAT_INTERVAL_MS` — heartbeat cadence in ms (default `60000`;
  set `0` to disable heartbeats)
- `SEPTR_ENV` — environment label sent with events (default `production`)
- `SEPTR_SILENCE_ENV_WARNING` — set to `1` to silence the fail-loud
  missing-key warning
- `SEPTR_DISABLED=true` — emergency bypass: pass every request through
  untouched (no scanning, no blocking) while the SDK stays installed

## License

MIT
