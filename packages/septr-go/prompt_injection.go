package septr

import (
	"regexp"
	"strings"
)

var promptInjectionPatterns = []struct {
	id          string
	pattern     *regexp.Regexp
	description string
	severity    string
}{
	{id: "prompt_injection_instruction_override", pattern: regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?previous\s+instructions`), description: "Instruction override", severity: "critical"},
	{id: "prompt_injection_instruction_reset", pattern: regexp.MustCompile(`(?i)forget\s+(?:all\s+)?previous\s+instructions`), description: "Instruction reset", severity: "critical"},
	{id: "prompt_injection_system_prompt_override", pattern: regexp.MustCompile(`(?i)(?:system|sys)\s*prompt\s*:`), description: "System prompt override", severity: "critical"},
	{id: "prompt_injection_role_assignment", pattern: regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a|an|the)`), description: "Role assignment", severity: "high"},
	{id: "prompt_injection_role_impersonation", pattern: regexp.MustCompile(`(?i)pretend\s+(?:you\s+are|to\s+be)\s+`), description: "Role impersonation", severity: "high"},
	{id: "prompt_injection_behavioral_override", pattern: regexp.MustCompile(`(?i)act\s+as\s+(?:a|an|the|if)\b`), description: "Behavioral override", severity: "high"},
	{id: "prompt_injection_new_instructions", pattern: regexp.MustCompile(`(?i)new\s+(?:instructions|role)\s*:`), description: "New instructions injection", severity: "critical"},
	{id: "prompt_injection_behavioral_redirect", pattern: regexp.MustCompile(`(?i)from\s+now\s+on[,.\s]+(?:you|your|the)`), description: "Behavioral redirect", severity: "high"},
	{id: "prompt_injection_output_injection", pattern: regexp.MustCompile(`(?i)output\s+this\s+exact\s+text`), description: "Output injection", severity: "critical"},
	{id: "prompt_injection_encoded_execution", pattern: regexp.MustCompile(`(?i)base64\s+decode\s+(?:and|&)\s+execute`), description: "Encoded execution", severity: "critical"},
	{id: "prompt_injection_dan_mode", pattern: regexp.MustCompile(`(?i)DAN\s+mode`), description: "DAN jailbreak", severity: "critical"},
	{id: "prompt_injection_dan_variant", pattern: regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`), description: "DAN jailbreak variant", severity: "critical"},
	{id: "prompt_injection_llama_inst", pattern: regexp.MustCompile(`(?i)\[INST\]|\[\/INST\]`), description: "Llama instruction injection", severity: "critical"},
	{id: "prompt_injection_llama_sys", pattern: regexp.MustCompile(`(?i)<<SYS>>|<<\/SYS>>`), description: "Llama system injection", severity: "critical"},
	{id: "prompt_injection_prompt_extraction_reveal", pattern: regexp.MustCompile(`(?i)reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt)`), description: "System prompt extraction", severity: "critical"},
	{id: "prompt_injection_prompt_extraction_output", pattern: regexp.MustCompile(`(?i)output\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)`), description: "System prompt extraction", severity: "critical"},
	{id: "prompt_injection_prompt_extraction_show", pattern: regexp.MustCompile(`(?i)show\s+me\s+your\s+(?:system\s+)?(?:prompt|rules|instructions)`), description: "System prompt extraction", severity: "critical"},
	{id: "prompt_injection_prompt_leakage_probe", pattern: regexp.MustCompile(`(?i)what\s+are\s+your\s+(?:rules|instructions|guidelines|constraints)`), description: "System prompt leakage probe", severity: "high"},
	{id: "prompt_injection_prompt_extraction_print", pattern: regexp.MustCompile(`(?i)print\s+(?:your|the)\s+(?:system\s+)?prompt`), description: "System prompt extraction", severity: "critical"},
	{id: "prompt_injection_tool_call_command", pattern: regexp.MustCompile(`(?i)run\s+this\s+command`), description: "Tool-call manipulation", severity: "critical"},
	{id: "prompt_injection_tool_call_execute", pattern: regexp.MustCompile(`(?i)execute\s+(?:this|the\s+following)`), description: "Tool-call execution attempt", severity: "critical"},
	{id: "prompt_injection_function_call", pattern: regexp.MustCompile(`(?i)call\s+function\s*[\(\{]`), description: "Function call injection", severity: "critical"},
	{id: "prompt_injection_tool_invoke", pattern: regexp.MustCompile(`(?i)invoke\s+tool`), description: "Tool invocation attempt", severity: "critical"},
}

func detectPromptInjection(input string) []DetectionEvent {
	seen := make(map[string]bool)
	var events []DetectionEvent
	for _, sp := range promptInjectionPatterns {
		if sp.pattern.MatchString(input) {
			if !seen[sp.id] {
				seen[sp.id] = true
				patternID := "prompt_injection_" + strings.ReplaceAll(strings.ReplaceAll(sp.description, " ", "_"), "-", "_")
				patternID = strings.ToLower(patternID)
				events = append(events, DetectionEvent{
					Type:        "prompt_injection",
					Severity:    sp.severity,
					PatternID:   patternID,
					Description: sp.description,
					Timestamp:   nowMs(),
				})
			}
		}
	}
	return events
}
