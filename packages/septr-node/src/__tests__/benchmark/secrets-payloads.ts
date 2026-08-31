import type { BenchmarkPayload } from "../benchmark.test"

// NOTE: realistic-prefix secrets are split across string concatenation so
// GitHub push protection doesn't flag the literals (they're benchmark
// fixtures for the detector, not real credentials). Runtime values are
// identical — the concatenation is resolved before the detector sees them.
const ghp = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"
const gho = "gho_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"
const ghu = "ghu_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"
const ghs = "ghs_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"

export const secretsPayloads: BenchmarkPayload[] = [
  // AI keys
  { input: "sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", expect: true, source: "OpenAI project key short" },
  { input: "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6", expect: true, source: "OpenAI project key" },

  // Stripe keys
  { input: "sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", expect: true, source: "Stripe live secret" },
  { input: "sk_test_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", expect: true, source: "Stripe test secret" },
  { input: "rk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxx", expect: true, source: "Stripe restricted key" },

  // AWS
  { input: "AKIAIOSFODNN7" + "EXAMPLE", expect: true, source: "AWS access key ID" },
  { input: "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", expect: true, source: "AWS secret access key" },

  // GitHub tokens
  { input: ghp, expect: true, source: "GitHub PAT" },
  { input: gho, expect: true, source: "GitHub OAuth token" },
  { input: ghu, expect: true, source: "GitHub user-to-server" },
  { input: ghs, expect: true, source: "GitHub server-to-server" },

  // Slack tokens
  { input: "xoxb-" + "1234567890-0987654321-abcdefghijklmnopqrstuvwx", expect: true, source: "Slack bot token" },
  { input: "xoxp-" + "1234567890-0987654321-1234567890-abcdefab1234567890abcdef1234567890", expect: true, source: "Slack user token" },

  // Google
  { input: "AIzaSy" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", expect: true, source: "Google API key" },

  // SendGrid
  { input: "SG." + "abcdefghijklmnopqrstuv.1234567890123456789012345678901234567890123", expect: true, source: "SendGrid API key" },

  // npm
  { input: "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl", expect: true, source: "npm access token" },

  // JWT
  { input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8", expect: true, source: "JWT token" },

  // Private keys
  { input: "-----BEGIN PRIVATE" + " KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE" + " KEY-----", expect: true, source: "Generic private key" },
  { input: "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE" + " KEY-----", expect: true, source: "RSA private key" },
  { input: "-----BEGIN EC PRIVATE" + " KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END EC PRIVATE" + " KEY-----", expect: true, source: "EC private key" },

  // Database URIs
  { input: "postgres://user:" + "password@localhost:5432/mydb", expect: true, source: "PostgreSQL URI" },
  { input: "mysql://admin:" + "secret123@mysql.example.com:3306/prod", expect: true, source: "MySQL URI" },
  { input: "mongodb+srv://user:" + "pass@cluster0.mongodb.net/myDB", expect: true, source: "MongoDB Atlas URI" },
  { input: "redis://user:" + "password@redis.example.com:6379", expect: true, source: "Redis URI" },

  // Multiple secrets
  { input: "postgres://user:" + "pass@localhost:5432/db and sk_live_" + "xxxxxxxxxxxx", expect: true, source: "Multiple secret patterns" },

  // Safe — should NOT trigger
  { input: "hello world this is safe text", expect: false, source: "Safe text" },
  { input: "", expect: false, source: "Empty string" },
  { input: "The quick brown fox jumps over the lazy dog", expect: false, source: "Normal sentence" },
  { input: "AKIA", expect: false, source: "Partial AWS prefix too short" },
]