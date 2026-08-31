import time
from typing import Any, Optional
from .secrets import detect_secrets, detect_high_entropy_secrets, should_strip_key, DetectionEvent


def strip_sensitive_data(
    obj: Any,
    custom_fields: Optional[list[str]] = None,
) -> tuple[Any, list[DetectionEvent]]:
    detections: list[DetectionEvent] = []

    def clean(value: Any) -> Any:
        nonlocal detections
        if value is None:
            return value
        if isinstance(value, str):
            specific = detect_secrets(value)
            entropy = detect_high_entropy_secrets(value)
            if specific or entropy:
                detections.extend(specific)
                detections.extend(entropy)
                # Redact when at least one specific detection is redactable.
                # Advisory-only patterns (e.g. public API keys) skip redaction
                # but must not suppress redaction of real secrets alongside them.
                if any(d.redactable is not False for d in specific):
                    return "[REDACTED]"
            return value
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            cleaned: dict[str, Any] = {}
            for key, val in value.items():
                if should_strip_key(key, custom_fields):
                    detections.append(DetectionEvent(
                        type="data_strip", severity="medium",
                        patternId="strip_field",
                        description=f"Field `{key}` stripped from response",
                        statusCode=200,
                        timestamp=time.time() * 1000,
                    ))
                    cleaned[key] = "[REDACTED]"
                else:
                    cleaned[key] = clean(val)
            return cleaned
        return value

    return clean(obj), detections
