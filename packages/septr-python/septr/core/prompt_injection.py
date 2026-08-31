import re
import time
from .secrets import DetectionEvent

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE), "Instruction override", "critical"),
    (re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE), "Full instruction override", "critical"),
    (re.compile(r"forget\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "Instruction reset", "critical"),
    (re.compile(r"(?:system|sys)\s*prompt\s*:", re.IGNORECASE), "System prompt override", "critical"),
    (re.compile(r"you\s+are\s+now\s+(?:a|an|the)", re.IGNORECASE), "Role assignment", "high"),
    (re.compile(r"pretend\s+(?:you\s+are|to\s+be)\s+", re.IGNORECASE), "Role impersonation", "high"),
    (re.compile(r"act\s+as\s+(?:a|an|the|if)", re.IGNORECASE), "Behavioral override", "high"),
    (re.compile(r"new\s+(?:instructions|role)\s*:", re.IGNORECASE), "New instructions injection", "critical"),
    (re.compile(r"from\s+now\s+on[,.\s]+(?:you|your|the)", re.IGNORECASE), "Behavioral redirect", "high"),
    (re.compile(r"output\s+this\s+exact\s+text", re.IGNORECASE), "Output injection", "critical"),
    (re.compile(r"base64\s+decode\s+(?:and|&)\s+execute", re.IGNORECASE), "Encoded execution", "critical"),
    (re.compile(r"DAN\s+mode", re.IGNORECASE), "DAN jailbreak", "critical"),
    (re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE), "DAN jailbreak variant", "critical"),
    (re.compile(r"\[INST\]|\[\/INST\]", re.IGNORECASE), "Llama instruction injection", "critical"),
    (re.compile(r"<<SYS>>|<<\/SYS>>", re.IGNORECASE), "Llama system injection", "critical"),
    (re.compile(r"reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt)", re.IGNORECASE), "System prompt extraction", "critical"),
    (re.compile(r"output\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)", re.IGNORECASE), "System prompt extraction", "critical"),
    (re.compile(r"show\s+me\s+your\s+(?:system\s+)?(?:prompt|rules|instructions)", re.IGNORECASE), "System prompt extraction", "critical"),
    (re.compile(r"what\s+are\s+your\s+(?:rules|instructions|guidelines|constraints)", re.IGNORECASE), "System prompt leakage probe", "high"),
    (re.compile(r"print\s+(?:your|the)\s+(?:system\s+)?prompt", re.IGNORECASE), "System prompt extraction", "critical"),
    (re.compile(r"run\s+this\s+command", re.IGNORECASE), "Tool-call manipulation", "critical"),
    (re.compile(r"execute\s+(?:this|the\s+following)", re.IGNORECASE), "Tool-call execution attempt", "critical"),
    (re.compile(r"call\s+function\s*[\(\{]", re.IGNORECASE), "Function call injection", "critical"),
    (re.compile(r"invoke\s+tool", re.IGNORECASE), "Tool invocation attempt", "critical"),
]


def detect_prompt_injection(input_str: str) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    seen: set[str] = set()
    now = time.time() * 1000

    for regex, description, severity in PROMPT_INJECTION_PATTERNS:
        if regex.search(input_str):
            pattern_id = f"prompt_injection_{description.lower().replace(' ', '_').replace('-', '_')}"
            if pattern_id not in seen:
                seen.add(pattern_id)
                events.append(DetectionEvent(
                    type="prompt_injection",
                    severity=severity,
                    patternId=pattern_id,
                    description=description,
                    statusCode=200,
                    timestamp=now,
                ))

    return events
