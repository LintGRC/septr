import type { BenchmarkPayload } from "../benchmark.test"

export const ssrfPayloads: BenchmarkPayload[] = [
  // Loopback addresses
  { input: "http://127.0.0.1/admin", expect: true, source: "IPv4 loopback basic" },
  { input: "http://127.0.0.1:8080/", expect: true, source: "IPv4 loopback with port" },
  { input: "http://127.0.0.2/secret", expect: true, source: "IPv4 loopback variant" },
  { input: "http://127.0.1.2/", expect: true, source: "Loopback range 127.0.x.x" },

  // Private networks
  { input: "http://10.0.0.1/internal", expect: true, source: "Private 10.0.0.1" },
  { input: "http://10.10.10.10/admin", expect: true, source: "Private 10.x.x.x range" },
  { input: "http://172.16.0.1/api", expect: true, source: "Private 172.16.0.1" },
  { input: "http://172.31.255.255/config", expect: true, source: "Private 172.31.x.x" },
  { input: "http://172.20.0.50/", expect: true, source: "Private 172.20.x.x" },
  { input: "http://192.168.1.100/data", expect: true, source: "Private 192.168.x.x" },
  { input: "http://192.168.0.1/admin", expect: true, source: "Private 192.168.0.1" },

  // Unspecified
  { input: "http://0.0.0.0/secret", expect: true, source: "Unspecified address" },

  // Cloud metadata endpoints
  { input: "http://169.254." + "169.254/latest/meta-data/", expect: true, source: "AWS metadata endpoint" },
  { input: "http://169.254." + "169.254/", expect: true, source: "AWS metadata bare" },
  { input: "http://metadata.google." + "internal/computeMetadata/v1/", expect: true, source: "GCP metadata endpoint" },
  { input: "http://metadata.google." + "internal/", expect: true, source: "GCP metadata domain" },

  // localhost
  { input: "http://localhost:3000/admin", expect: true, source: "localhost with port" },
  { input: "http://localhost/", expect: true, source: "localhost bare" },
  { input: "http://localhost:5432/", expect: true, source: "localhost postgres port" },

  // Dangerous protocols
  { input: "file:///etc/passwd", expect: true, source: "File protocol" },
  { input: "file:///proc/self/environ", expect: true, source: "File protocol env" },
  { input: "gopher://127.0.0.1:6379/", expect: true, source: "Gopher to Redis" },
  { input: "gopher://localhost:8080/", expect: true, source: "Gopher localhost" },

  // TEST-NET addresses
  { input: "http://192.0.2.1/scan", expect: true, source: "TEST-NET 192.0.2.x" },
  { input: "http://198.51.100.10/", expect: true, source: "TEST-NET-2 198.51.100.x" },
  { input: "http://203.0.113.50/admin", expect: true, source: "TEST-NET-3 203.0.113.x" },

  // Multiple patterns in one
  { input: "http://10.0.0.1 AND http://localhost:3000", expect: true, source: "Multiple SSRF patterns" },

  // Safe — should NOT trigger
  { input: "https://api.stripe.com/charges", expect: false, source: "Safe public API URL" },
  { input: "https://8.8.8.8/dns-query", expect: false, source: "Safe public DNS IP" },
  { input: "https://www.google.com/", expect: false, source: "Safe public domain" },
  { input: "hello world this is safe", expect: false, source: "Safe random text" },
  { input: "", expect: false, source: "Empty string" },
  { input: "https://api.example.com/v1/users", expect: false, source: "Safe example.com API" },
]
