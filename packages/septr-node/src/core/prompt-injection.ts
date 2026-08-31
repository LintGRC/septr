import type { DetectionEvent } from "./types"

/**
 * Prompt injection detection patterns.
 *
 * Scans input strings for common LLM jailbreak and prompt manipulation techniques.
 * Designed as a heuristic guard — sophisticated attacks may bypass these patterns.
 *
 * Targets: user-supplied text that may be passed to language models in AI-powered apps.
 */
const PROMPT_INJECTION_PATTERNS: [RegExp, string, DetectionSeverity][] = [
  [/ignore\s+previous\s+instructions/gi, "Instruction override", "critical"],
  [/ignore\s+all\s+previous\s+instructions/gi, "Full instruction override", "critical"],
  [/forget\s+(all\s+)?previous\s+instructions/gi, "Instruction reset", "critical"],
  [/(?:system|sys)\s*prompt\s*:/gi, "System prompt override", "critical"],
  [/you\s+are\s+now\s+(?:a|an|the)/gi, "Role assignment", "high"],
  [/pretend\s+(?:you\s+are|to\s+be)\s+/gi, "Role impersonation", "high"],
  [/act\s+as\s+(?:a|an|the|if)\b/gi, "Behavioral override", "high"],
  [/new\s+(?:instructions|role)\s*:/gi, "New instructions injection", "critical"],
  [/from\s+now\s+on[,.\s]+(?:you|your|the)/gi, "Behavioral redirect", "high"],
  [/output\s+this\s+exact\s+text/gi, "Output injection", "critical"],
  [/base64\s+decode\s+(?:and|&)\s+execute/gi, "Encoded execution", "critical"],
  [/DAN\s+mode/gi, "DAN jailbreak", "critical"],
  [/\bdo\s+anything\s+now\b/gi, "DAN jailbreak variant", "critical"],
  [/\[INST\]|\[\/INST\]/gi, "Llama instruction injection", "critical"],
  [/<<SYS>>|<<\/SYS>>/gi, "Llama system injection", "critical"],
  // LLM07: System Prompt Leakage
  [/reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt)/gi, "System prompt extraction", "critical"],
  [/output\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)/gi, "System prompt extraction", "critical"],
  [/show\s+me\s+your\s+(?:system\s+)?(?:prompt|rules|instructions)/gi, "System prompt extraction", "critical"],
  [/what\s+are\s+your\s+(?:rules|instructions|guidelines|constraints)/gi, "System prompt leakage probe", "high"],
  [/print\s+(?:your|the)\s+(?:system\s+)?prompt/gi, "System prompt extraction", "critical"],
  // LLM06: Excessive Agency / Tool-Call Manipulation
  [/run\s+this\s+command/gi, "Tool-call manipulation", "critical"],
  [/execute\s+(?:this|the\s+following)/gi, "Tool-call execution attempt", "critical"],
  [/call\s+function\s*[\(\{]/gi, "Function call injection", "critical"],
  [/invoke\s+tool/gi, "Tool invocation attempt", "critical"],
]

type DetectionSeverity = "info" | "low" | "medium" | "high" | "critical"

/**
 * Scan a string for prompt injection patterns (LLM jailbreaks, instruction overrides).
 * Returns one detection per unique pattern match.
 */
export function detectPromptInjection(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const seen = new Set<string>()

  for (const [regex, description, severity] of PROMPT_INJECTION_PATTERNS) {
    const pattern = new RegExp(regex.source, regex.flags)

    if (pattern.test(input)) {
      const patternId = `prompt_injection_${description.toLowerCase().replace(/[\s-]+/g, "_")}`

      if (!seen.has(patternId)) {
        seen.add(patternId)
        events.push({
          type: "prompt_injection",
          severity,
          patternId,
          description,
          statusCode: 200,
          timestamp: Date.now(),
        })
      }
    }
  }

  return events
}
