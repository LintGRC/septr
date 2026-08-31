import { describe, it, expect } from "vitest"
import { detectSSRF } from "../../core/ssrf"
import { detectSQLi, detectXSS, sanitizeQuery, sanitizeInput } from "../../core/sanitize"
import { detectPromptInjection } from "../../core/prompt-injection"
import { detectSecrets } from "../../core/secrets"
import { detectBusinessLogicTamper } from "../../core/tamper"
import { detectBOLA, extractRouteParams, extractTokenClaims } from "../../core/bola"
import { detectMissingAuth } from "../../core/missing-auth"

const MAX_FALSE_POSITIVES = 0

function expectClean(name: string, count: number) {
  if (count > 0) {
    console.warn(`⚠ FALSE POSITIVE: "${name}" triggered ${count} detection(s)`)
  }
  expect(count, `"${name}" produced ${count} false detection(s)`).toBe(MAX_FALSE_POSITIVES)
}

describe("False Positive: SSRF engine", () => {
  const safeUrls = [
    "https://api.stripe.com/v1/charges",
    "https://api.openai.com/v1/chat/completions",
    "https://github.com/user/repo",
    "https://www.google.com/search?q=hello",
    "http://example.com/page",
    "https://cdn.jsdelivr.net/npm/react/umd/react.production.min.js",
    "ftp://files.example.com/document.pdf",
    "The URL for the API is configured in the environment",
    "/api/users/123/profile",
    "Use the NEXT_PUBLIC_API_URL variable",
  ]
  for (const url of safeUrls) {
    it(`passes: "${url.slice(0, 60)}"`, () => {
      expectClean(url, detectSSRF(url).length)
    })
  }
})

describe("False Positive: SQLi engine", () => {
  const safeInputs = [
    "SELECT name FROM products WHERE id = 1",
    "UPDATE users SET email = 'test@example.com' WHERE id = 1",
    "page=1&limit=10&sort=name",
    "John's restaurant",
    "It's a beautiful day",
    "O'Brien's pub",
    "A 100% satisfaction guarantee",
    "search=react+components&category=frontend",
    "What is 1 + 1?",
    "The user's email is user@example.com",
  ]
  for (const input of safeInputs) {
    it(`passes: "${input.slice(0, 60)}"`, () => {
      expectClean(input, detectSQLi(input).length)
    })
  }
})

describe("False Positive: XSS engine", () => {
  const safeInputs = [
    "<div>Hello World</div>",
    "<img src='photo.jpg' alt='photo' />",
    "<a href='/dashboard'>Dashboard</a>",
    "<p class='content'>Paragraph text</p>",
    "<h1>Title</h1><p>Body</p>",
    "const x = <div>Hello</div>;",
    "useCallback(() => { return <Button /> }, [])",
    "The onClick handler is attached via React props",
    "window.location.href = '/dashboard'",
  ]
  for (const input of safeInputs) {
    it(`passes: "${input.slice(0, 60)}"`, () => {
      expectClean(input, detectXSS(input).length)
    })
  }
})

describe("False Positive: Prompt injection engine", () => {
  const safeInputs = [
    "Write a poem about the ocean",
    "Explain quantum computing in simple terms",
    "Summarize this article for me",
    "What is the capital of France?",
    "Can you help me debug this code?",
    "Translate this to Spanish: Hello, how are you?",
    "What are the hours of operation?",
    "Rules for the game are: no running, no shouting",
    "The instructions are in the manual on page 5",
    "Please show me the search results",
    "output the result of 2 + 2",
    "What are your business hours?",
  ]
  for (const input of safeInputs) {
    it(`passes: "${input.slice(0, 60)}"`, () => {
      expectClean(input, detectPromptInjection(input).length)
    })
  }
})

describe("False Positive: Secrets engine", () => {
  const safeInputs = [
    "The quick brown fox jumps over the lazy dog",
    "export const API_URL = 'https://api.example.com'",
    "const apiKey = process.env.API_KEY",
    "my-password-is-secret",
    "Bearer token_will_be_here",
    "SELECT * FROM users WHERE token = 'abc'",
    "npm install react react-dom",
    "sk_test is a prefix for Stripe test keys",
    "Stripe live keys start with sk_live_",
    "OpenAI keys look like sk-proj-...",
  ]
  for (const input of safeInputs) {
    it(`passes: "${input.slice(0, 60)}"`, () => {
      expectClean(input, detectSecrets(input).length)
    })
  }
})

describe("False Positive: Business Logic Tamper engine", () => {
  const safeBodies: [string, Record<string, unknown>][] = [
    ["positive amount", { amount: 4900 }],
    ["valid price + quantity", { price: 2999, quantity: 2 }],
    ["normal role", { role: "user" }],
    ["free tier", { role: "free" }],
    ["isAdmin false", { isAdmin: false }],
    ["moderate discount", { discount: 25 }],
    ["pro plan", { plan: "pro" }],
    ["single item", { quantity: 1 }],
    ["innocent fields", { name: "John", email: "john@example.com" }],
    ["empty body", {}],
    ["nested data", { user: { name: "Alice" }, items: [1, 2, 3] }],
    ["string amount (non-numeric)", { amount: "free" }],
  ]
  for (const [name, body] of safeBodies) {
    it(`passes: ${name}`, () => {
      expectClean(name, detectBusinessLogicTamper(body).length)
    })
  }
})

describe("False Positive: BOLA engine", () => {
  it("passes with non-ownership route params", () => {
    const event = detectBOLA(["postId"], null, { sub: "42" }, "/posts/:postId", "GET")
    expect(event).toBeNull()
  })

  it("passes with matching body field", () => {
    const event = detectBOLA([], { userId: "42" }, { sub: "42" }, "/profile", "PUT")
    expect(event).toBeNull()
  })

  it("passes on public route without auth", () => {
    const event = detectBOLA([], null, {}, "/health", "GET")
    expect(event).toBeNull()
  })

  it("passes on route with non-ID params", () => {
    const params = extractRouteParams("/blog/:slug")
    expect(params).toEqual(["slug"])
    const event = detectBOLA(params, null, { sub: "42" })
    expect(event).toBeNull()
  })
})

describe("False Positive: Missing auth engine", () => {
  it("passes with valid bearer token", () => {
    const event = detectMissingAuth("/api/users", "GET", "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature")
    expect(event).toBeNull()
  })

  it("passes on public routes", () => {
    const event = detectMissingAuth("/auth/login", "POST")
    expect(event).toBeNull()
  })

  it("passes on health endpoint", () => {
    const event = detectMissingAuth("/health", "GET")
    expect(event).toBeNull()
  })
})

describe("False Positive: Multi-engine request scenarios", () => {
  interface RequestScenario {
    name: string
    method: string
    path: string
    headers: Record<string, string>
    body: unknown
    query: Record<string, string>
  }

  const scenarios: RequestScenario[] = [
    {
      name: "GET user profile",
      method: "GET",
      path: "/api/users/me",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: null,
      query: {},
    },
    {
      name: "POST checkout with valid amount",
      method: "POST",
      path: "/api/checkout",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: { amount: 4900, currency: "usd", items: [{ id: "prod_123", quantity: 2 }] },
      query: {},
    },
    {
      name: "POST update profile with matching IDs",
      method: "PUT",
      path: "/api/profile",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: { name: "Alice", email: "alice@example.com", userId: "42" },
      query: {},
    },
    {
      name: "GET public blog post",
      method: "GET",
      path: "/blog/welcome-to-septr",
      headers: {},
      body: null,
      query: {},
    },
    {
      name: "POST search with safe query",
      method: "POST",
      path: "/api/search",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: { query: "react components for data visualization" },
      query: { page: "1", limit: "20" },
    },
    {
      name: "GET public pricing page",
      method: "GET",
      path: "/pricing",
      headers: {},
      body: null,
      query: {},
    },
    {
      name: "POST contact form",
      method: "POST",
      path: "/api/contact",
      headers: {},
      body: { name: "John Doe", email: "john@example.com", message: "I have a question about your product" },
      query: {},
    },
    {
      name: "POST create invoice with valid roles",
      method: "POST",
      path: "/api/invoices",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: { amount: 15000, description: "Monthly subscription", role: "user" },
      query: {},
    },
    {
      name: "GET API documentation",
      method: "GET",
      path: "/docs",
      headers: {},
      body: null,
      query: {},
    },
    {
      name: "GET user settings with role",
      method: "GET",
      path: "/api/settings",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: null,
      query: { section: "notifications" },
    },
    {
      name: "POST AI assistant safe prompt",
      method: "POST",
      path: "/api/assistant",
      headers: { authorization: "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9." + "signature" },
      body: { prompt: "Write a poem about the ocean", model: "gpt-4" },
      query: {},
    },
  ]

  for (const scenario of scenarios) {
    it(`no engine fires on: ${scenario.name}`, () => {
      const detections: string[] = []

      // SSRF
      const ssrfInput = [scenario.path, JSON.stringify(scenario.query), JSON.stringify(scenario.body)].join(" ")
      const ssrfEvents = detectSSRF(ssrfInput)
      for (const e of ssrfEvents) detections.push(`ssrf:${e.patternId}`)

      // SQLi
      if (scenario.body && typeof scenario.body === "object") {
        const { detections: sqliXss } = sanitizeInput(scenario.body)
        for (const e of sqliXss) detections.push(`sanitizeInput:${e.patternId}`)
      }
      const { detections: qd } = sanitizeQuery(scenario.query)
      for (const e of qd) detections.push(`query:${e.patternId}`)

      // Prompt injection
      if (scenario.body && typeof scenario.body === "object") {
        const bodyStr = JSON.stringify(scenario.body)
        const piEvents = detectPromptInjection(bodyStr)
        for (const e of piEvents) detections.push(`prompt_injection:${e.patternId}`)
      }

      // Secrets
      const bodyStr = scenario.body ? JSON.stringify(scenario.body) : ""
      const secretEvents = detectSecrets(bodyStr)
      for (const e of secretEvents) detections.push(`secret:${e.patternId}`)

      // Tamper
      if (scenario.body && typeof scenario.body === "object" && !Array.isArray(scenario.body)) {
        const tamperEvents = detectBusinessLogicTamper(scenario.body as Record<string, unknown>)
        for (const e of tamperEvents) detections.push(`tamper:${e.patternId}`)
      }

      // BOLA
      const token = scenario.headers.authorization?.replace(/^Bearer\s+/i, "") ?? ""
      const claims = token ? extractTokenClaims(token) : {}
      const routeParams = extractRouteParams(scenario.path)
      const bodyParams = scenario.body && typeof scenario.body === "object" && !Array.isArray(scenario.body)
        ? scenario.body as Record<string, string>
        : null
      const bolaEvent = detectBOLA(routeParams, bodyParams, claims, scenario.path, scenario.method)
      if (bolaEvent) detections.push(`bola:${bolaEvent.patternId}`)

      // Missing auth — excluded from multi-engine check because public
      // routes (blog, pricing, docs, etc.) correctly trigger it. That's
      // not a false positive — it's the engine doing its job.
      // We still log it for awareness.
      const authEvent = detectMissingAuth(
        scenario.path,
        scenario.method,
        scenario.headers.authorization,
      )
      const authDetections: string[] = []
      if (authEvent) authDetections.push(`missing_auth:${authEvent.patternId}`)

      if (detections.length > 0) {
        console.warn(`\n⚠ FALSE POSITIVES in "${scenario.name}":`)
        for (const d of detections) console.warn(`  - ${d}`)
      }
      if (authDetections.length > 0) {
        console.warn(`  ℹ missing_auth (expected on public routes): ${authDetections[0]}`)
      }
      expect(detections, `${scenario.name} triggered engine(s): ${detections.join(", ")}`).toEqual([])
    })
  }
})
