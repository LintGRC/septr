package septr

import (
	"strings"
)

func getNestedValue(obj map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = obj
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
		if current == nil {
			return nil
		}
	}
	return current
}

func extractTenantFromJwt(claims map[string]string, jwtClaim string) string {
	if claims == nil {
		return ""
	}
	if val, ok := claims[jwtClaim]; ok {
		return val
	}
	return ""
}

type TenantLeak struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func detectCrossTenantLeaks(expectedTenantID string, body interface{}, tenantColumn string) []TenantLeak {
	var leaks []TenantLeak

	var scan func(obj interface{}, path string)
	scan = func(obj interface{}, path string) {
		if obj == nil {
			return
		}

		switch v := obj.(type) {
		case map[string]interface{}:
			for key, val := range v {
				currentPath := path
				if currentPath == "" {
					currentPath = key
				} else {
					currentPath = currentPath + "." + key
				}

				if key == tenantColumn && val != nil {
					valStr := toString(val)
					if valStr != expectedTenantID {
						leaks = append(leaks, TenantLeak{Path: currentPath, Value: val})
					}
					continue
				}

				switch vt := val.(type) {
				case map[string]interface{}, []interface{}:
					scan(vt, currentPath)
				}
			}

		case []interface{}:
			for i, item := range v {
				scan(item, path+"["+toString(i)+"]")
			}
		}
	}

	scan(body, "")
	return leaks
}

func createTenantCheckResponse(tenantID string, body interface{}, config TenantAwareConfig) (bool, []TenantLeak) {
	leaks := detectCrossTenantLeaks(tenantID, body, config.TenantColumn)
	if len(leaks) > 0 && config.BlockOnMismatch {
		return true, leaks
	}
	return false, leaks
}
