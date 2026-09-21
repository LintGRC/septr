## 0.1.30 — 2026-09-21

### Fixed — `septr scan`
- **`.septrignore` metacharacters are literal now.** A pattern like
  `data[1].ts` was compiled as a regex — it silently mis-matched (`[1]`
  became a character class) and an unbalanced pattern such as `b(roken`
  crashed the whole scan with an invalid RegExp.
- **`**/` matches zero or more directories anywhere in the pattern**, not
  just at the start. Nested ignore files (whose patterns are re-anchored to
  the directory that declares them) now silence the intended paths, e.g.
  `**/benchmark/**` in `packages/web/.septrignore` also covers
  `packages/web/benchmark/**`.
- A trailing `/` matches the directory and everything under it, and no
  longer a same-named file.

## 0.1.29 — 2026-09-17

### Fixed — `septr scan <url>` noise
- **Injection engines no longer run on fetched remote content.** The SQLi/
  XSS/SSRF detectors target attacker-controlled input; running them on a
  site's own HTML/JS flagged every `<script src>` tag as `xss_script_tag`
  and ordinary strings as injection attempts. URL-mode scanning of pages,
  bundles, probe responses and manifests is now secrets-only, matching the
  dashboard scanner's bundle checks. Local directory scans are unchanged
  (full engine set).

## 0.1.28 — 2026-09-17

### Fixed — scan ↔ dashboard reconcile
- **CLI-attached findings now merge with dashboard incidents.** Findings sent
  by `--attach` used the local engine's names, so the same issue (e.g. an
  exposed Stripe key) appeared twice on a project — once from a web scan and
  once from the CLI — and the CLI's copy could not update the web's. Attach
  payloads now use the web scanner's canonical `check_id`, name, and severity
  for shared checks, and the same naming for probe files
  (`Sensitive file exposed: /.env`, `Live secret exposed in /.env`).
- **Header findings are per-header.** URL mode now reports one finding per
  missing header — `HSTS header missing`, `Content-Security-Policy header
  missing`, `X-Content-Type-Options header missing`, `X-Frame-Options header
  missing`, `Referrer-Policy header missing` — matching the web scanner so
  each class reconciles independently. `Referrer-Policy` is newly checked.
- CLI attaches are add-only server-side now: a CLI scan no longer marks
  incidents "fixed" for checks it doesn't cover (OSV, GraphQL, CORS,
  hallucinated packages). Resolution happens on the next web re-scan.

## 0.1.27 — 2026-09-17

### Added — `septr scan <url>`
- **JS bundle scanning.** The CLI URL mode now fetches up to 30 `<script src>` bundles (10 MB cap each) and runs the secret/injection engines on them — the same leak detection the web app applies to frontend JavaScript.
- **Manifest scanning.** Fetches `/package.json` and `/requirements.txt` and scans them for accidentally committed keys or tokens.
- **Security header checks.** Missing HSTS, CSP, X-Frame-Options, and X-Content-Type-Options are now reported as findings in URL mode (previously only checked by `septr audit`).

## 0.1.26 — 2026-09-17

### Fixed — `septr scan`
- **Vibe-code file types were silently skipped.** `.vue`, `.svelte`, `.astro`,
  `.mdx`, `.prisma`, `Dockerfile`, `Makefile`, `.php`, `.java`, `.kt`, `.cs`,
  `.scss`, `.graphql`, `.tf`, `.ps1` and more were never scanned, so a leaked
  secret in one of them still printed `0 finding(s)`. All are scanned now,
  along with hidden credential files (`.npmrc`, `.pypirc`, `.netrc`,
  `.htpasswd`, `.git-credentials`, `.envrc`, `.flaskenv`).
- **Default ignores did not match at the scan root.** `fixtures/**`,
  `*-payloads.*` and `__tests__/benchmark/**` were only ignored when nested,
  so scanning a project root flagged its own test payloads. A leading `**/`
  now matches zero or more directories.
- **Nested `.septrignore` files were invisible to parent-directory scans.**
  They now apply to their own subtree (re-anchored to the scan root), so a
  monorepo scan respects the exclusions committed in vendored packages, and
  the Python/Go/catalog packages in this repo now ship their own.
- **The summary hid what was skipped.** `septr scan` now prints
  `skipped: N dependency/build dir(s), N hidden, N non-source file(s)` and
  `--json` exposes `skipped: { dirs, hidden, nonText }`, so the scanned-file
  count can be reconciled with the project.

## 0.1.25 — 2026-09-17

### Fixed — CLI
- **Reporting failures were invisible.** `septr test` / `septr audit` printed
  `Done!` even when the backend rejected the results (expired key, wrong URL)
  — the reporter swallowed every error. It now prints `Results reported.` or
  a warning with the reason, e.g.
  `HTTP 401 from https://app.septr.dev — check the API key`.
- **`test` / `audit` defaulted to a local backend.** `--api-url` pointed at the
  local dev server, so results from real machines went nowhere. Default is now
  `https://app.septr.dev`, matching `scan --attach`.
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
