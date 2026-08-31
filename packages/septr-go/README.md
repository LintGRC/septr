# septr — runtime security middleware for Go

Protects `net/http` and Gin apps at runtime: secrets leaking in responses,
BOLA/IDOR, missing auth, business-logic tampering, PII, prompt injection,
SSRF, and missing rate limits. Auto-verified against the Septr backend,
with per-engine SOC 2 evidence for your dashboard.

## Install

```bash
go get github.com/algebra4344/septr-go
```

Add your key to `.env`:

```
SEPTR_API_KEY=septr_live_...
```

## net/http

```go
import (
    "net/http"
    "os"
    septr "github.com/algebra4344/septr-go"
)

shield := septr.NewNetHTTP(&septr.Config{
    APIKey: os.Getenv("SEPTR_API_KEY"),
})
http.ListenAndServe(":8080", shield.Wrap(mux))
```

## Gin

```go
import (
    "github.com/gin-gonic/gin"
    "os"
    septr "github.com/algebra4344/septr-go"
)

r := gin.Default()
r.Use(septr.NewGin(&septr.Config{
    APIKey: os.Getenv("SEPTR_API_KEY"),
}).Handler())
```

## Config

| Field | Type | Default | Description |
|---|---|---|---|
| `APIKey` | string | env `SEPTR_API_KEY` | Backend API key |
| `StrictMode` | bool | `false` | Block instead of detect |
| `Secrets` | *bool | `true` | Secret/PII detection + response scrubbing |
| `BOLA` | *bool | `true` | BOLA/IDOR detection |
| `RateLimit` | *bool | `true` | Per-route rate limiting |
| `InputSanitize` | *bool | `true` | SQLi/XSS/NoSQLi sanitization |
| `SSRF` | *bool | `true` | SSRF heuristics |
| `PromptInjection` | *bool | `true` | Prompt-injection shielding |
| `MissingAuth` | *bool | `true` | Missing-auth detection |
| `Tamper` | *bool | `true` | Business-logic tamper detection |
| `AIRateLimit` | *bool | `true` | Rate limiting for AI endpoints |
| `StripFields` | []string | `[]` | Fields to strip from responses |
| `TelemetryURL` | string | `https://api.septr.com/v1/events` | Telemetry endpoint |

## Environment variables

- `SEPTR_API_KEY` — your project key
- `SEPTR_SILENCE_ENV_WARNING` — set to `1` to silence the fail-loud
  missing-key warning
- `SEPTR_REMOTE_CONFIG=false` — disable remote config polling

## License

MIT
