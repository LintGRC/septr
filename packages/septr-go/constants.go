package septr

const selfTestPath = "/__septr_ping"

// defaultMaxResponseScanBytes caps response-body scanning. Response scanning
// is a backstop for small error/data payloads; multi-MB responses (reports,
// exports) are skipped unless the operator raises maxResponseScanBytes —
// scanning them on every request burns CPU and, in the Python SDKs, froze
// the event loop.
const defaultMaxResponseScanBytes = 256 * 1024

var authRoutePrefixes = []string{"/auth", "/login", "/checkout", "/register"}

func isAuthRoute(path string) bool {
	for _, prefix := range authRoutePrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
