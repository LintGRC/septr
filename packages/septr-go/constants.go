package septr

const selfTestPath = "/__septr_ping"

var authRoutePrefixes = []string{"/auth", "/login", "/checkout", "/register"}

func isAuthRoute(path string) bool {
	for _, prefix := range authRoutePrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
