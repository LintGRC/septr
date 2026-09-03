# Security Policy

## Supported Versions

We actively support the latest published version of Septr (currently 0.1.x).

## Reporting a Vulnerability

We take the security of Septr seriously. If you believe you have found a security vulnerability, please report it responsibly.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them via email to: **security@septr.dev**

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you've identified

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Scope

Septr is a **detection-only** tool. It does not modify, block, or filter network requests (unless strict mode is enabled). The security surface is limited to:

- The npm/PyPI package (supply chain)
- The CLI scanner (`npx septr scan`)
- The dashboard (app.septr.dev)
- The telemetry ingestion API

## Integrity Verification

Septr publishes provenance-attested builds on npm. Verify with:

```bash
npm audit signatures
npm view septr homepage repository
```

The public source code is at: [github.com/LintGRC/septr](https://github.com/LintGRC/septr)

## Dependencies

Septr's runtime dependencies are pinned and audited:

- `express`/`next`/`hono`/`fastify` (peer — framework-provided)
- No native modules, no network calls at runtime (telemetry is async and non-blocking)

## License

Septr is released under the [MIT License](LICENSE).
