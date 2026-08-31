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

## FastAPI

```python
from fastapi import FastAPI
from septr.adapters.fastapi import SeptrASGIMiddleware
import os

app = FastAPI()

app.add_middleware(
    SeptrASGIMiddleware,
    api_key=os.getenv("SEPTR_API_KEY"),
)
```

## Flask

```python
from flask import Flask
from septr.adapters.flask import SeptrFlask
import os

app = Flask(__name__)
# ... your routes ...
app.wsgi_app = SeptrFlask(app.wsgi_app, {"apiKey": os.getenv("SEPTR_API_KEY")})
```

## Config

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | str | env `SEPTR_API_KEY` | Backend API key |
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
| `stripFields` | list[str] | `[]` | Fields to strip from responses |
| `telemetry_url` | str | `https://api.septr.com/v1/events` | Telemetry endpoint |

## Environment variables

- `SEPTR_API_KEY` — your project key
- `SEPTR_SILENCE_ENV_WARNING` — set to `1` to silence the fail-loud
  missing-key warning

## License

MIT
