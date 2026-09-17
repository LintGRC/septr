## 0.1.25 — 2026-09-17

### Fixed — CLI
- **Reporting failures were invisible.** `septr test` / `septr audit` printed
  `Done!` even when the backend rejected the results (expired key, wrong URL)
  — the reporter swallowed every error. It now prints `Results reported.` or
  a warning with the reason, e.g.
  `HTTP 401 from https://app.septr.dev — check the API key`.
- **`test` / `audit` defaulted to a local backend.** `--api-url` defaulted to
  `http://localhost:8000` (the dev stack), so results from real machines went
  nowhere. Default is now `https://app.septr.dev`, matching `scan --attach`.
- **`septr --version` was stuck at 0.1.0.** The CLI hardcoded the string while
  the build already injects the real version; top-level `septr --version` also
  failed with `Unknown command`. Both now print the package version.
- **The SQL injection probe never ran.** It was defined as a GET with a JSON
  body, which `fetch` rejects — every run reported `sqli: FAIL` regardless of
  the target. The payload now travels in the query string.
- **404/405 counted as protection.** `septr test` treated any 4xx/5xx as
  blocked, so a missing route produced a false `PASS`. Missing routes are now
  `SKIPPED` (inconclusive) and excluded from the pass count; the command exits
  1 only on real failures.
- **Debug-mode check flagged SPAs.** Any HTML response on `/__septr_debug`
  (a catch-all route) was reported as a HIGH exposed debug endpoint. HTML
  responses now pass; only non-HTML responses fail.

### Changed — CLI
- **`--key` is optional for `test` and `audit`.** Checks run locally and print
  results without a key; providing one records them in the dashboard.
- **`audit` score ignores checks that couldn't run.** DB checks without
  `--db-url` (or without `psql`) are labeled `[NOT RUN]` and excluded from the
  score instead of counting as failures — a clean app no longer caps at ~58%
  (grade F) because optional input was missing.

# Changelog

## 0.1.24

### Fixed
- **Response scanning could block the host app.** The FastAPI adapter scanned
  every JSON response body synchronously on the event loop — full JSON parse,
  six regex passes (`detect_ai_rate_limit`), and a full-tree secret walk. On
  multi-megabyte payloads (10–25 MB reports) this froze the entire app. All
  adapters now:
  - skip response scanning for bodies over `maxResponseScanBytes`
    (default 256 KB; Node keeps its 1 MB default),
  - stream oversized responses through without buffering them
    (Flask / Go gin / Go net/http), and
  - run AI rate-limit patterns only when the body contains a cheap
    rate/quota marker (`429` / `rate` / `quota`).
- **Flask consumed the request body.** Reading `wsgi.input` for inspection
  left the stream empty for the app, so every POST with a body failed
  (Flask returned 400). The body is now restored for the app.
- **Legacy heartbeat formats could surface as incidents.** Heartbeats are now
  recognized in every SDK format and only stamp liveness.
- **Go telemetry could block the request path.** `Emit` flushed inline when
  the buffer filled; it now signals a background flusher.

### Added
- **Fail-open pipeline guards.** Every detection engine runs behind a guard
  that catches exceptions, enforces a per-call time budget
  (`engineBudgetMs`, default 50), and trips a per-engine circuit breaker
  (`engineFailureThreshold`, default 3). A tripped engine is skipped for the
  process and reported once as a `engine_degraded` system event instead of
  failing every request.
- **Top-level fail-open wrappers** in every adapter: any unexpected middleware
  error passes the request through untouched.
- **`SEPTR_DISABLED=true`** (or `disabled: true` in config) emergency kill
  switch — bypasses all scanning while the SDK stays installed.
- **`maxRequestInspectBytes`** (default 256 KB): larger request bodies are not
  inspected and stream through untouched, so uploads can never stall the app.
- **`securityHeaders: false`** turns off the missing-security-headers advisory
  for apps that manage headers in their own middleware or at an edge proxy
  (the SDK intercepts responses before inner header middleware runs, which
  otherwise reports false gaps).
- **Engine health visibility**: the dashboard flags SDK versions older than
  0.1.24 and shows disabled engines as coverage gaps with restore guidance.

### Tests
- Python: fail-open, circuit breaker, kill switch, request/response caps,
  Flask body passthrough (`tests/test_safety.py`, adapter suites).
- Go: guard, kill switch, bounded request read, streaming response cap,
  non-blocking telemetry (`safety_test.go`, adapter suites).
- Node: guard, kill switch, fail-open across adapters
  (`src/__tests__/safety.test.ts`).
