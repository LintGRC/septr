package septr

func stripSensitiveData(obj interface{}, customFields ...[]string) (interface{}, []DetectionEvent) {
	var detections []DetectionEvent
	var clean func(interface{}) interface{}
	clean = func(value interface{}) interface{} {
		if value == nil {
			return nil
		}
		switch v := value.(type) {
		case string:
			specific := detectSecrets(v)
			entropy := DetectHighEntropySecrets(v)
			if len(specific) > 0 || len(entropy) > 0 {
				detections = append(detections, specific...)
				detections = append(detections, entropy...)
				// Redact when at least one specific detection is redactable.
				// Advisory-only patterns (e.g. public API keys) skip redaction
				// but must not suppress redaction of real secrets alongside them.
				foundRedactable := false
				for _, s := range specific {
					if s.Redactable == nil || *s.Redactable {
						foundRedactable = true
						break
					}
				}
				if foundRedactable {
					return "[REDACTED]"
				}
			}
			return v
		case []interface{}:
			result := make([]interface{}, len(v))
			for i, item := range v {
				result[i] = clean(item)
			}
			return result
		case map[string]interface{}:
			result := make(map[string]interface{})
			for key, val := range v {
				if shouldStripKey(key, customFields...) {
					detections = append(detections, DetectionEvent{
						Type: "data_strip", Severity: "medium",
						PatternID: "strip_field",
						Description: "Field `" + key + "` stripped from response",
						StatusCode: 200, Timestamp: nowMs(),
					})
					result[key] = "[REDACTED]"
				} else {
					result[key] = clean(val)
				}
			}
			return result
		default:
			return value
		}
	}
	return clean(obj), detections
}
