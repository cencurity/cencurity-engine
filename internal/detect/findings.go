package detect

import "strings"

// Confidence describes how strongly a finding is supported.
type Confidence string

const (
	// ConfidenceLow marks weak heuristic support.
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium marks moderate heuristic support.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh marks strong heuristic support.
	ConfidenceHigh Confidence = "high"
)

// Finding is a normalized CAST result over generated code.
type Finding struct {
	RuleID      string
	Kind        string
	Category    string
	Severity    string
	Confidence  Confidence
	Action      string
	Evidence    string
	Context     ContentContext
	Start       int
	End         int
	Language    Language
	Framework   string
}

// BuildFindings converts raw detections into normalized findings.
func BuildFindings(detections []Detection, context ContentContext, source string) []Finding {
	findings := make([]Finding, 0, len(detections))
	for _, detection := range detections {
		findings = append(findings, Finding{
			RuleID:     detection.RuleID,
			Kind:       findingKind(detection.RuleID, detection.Category),
			Category:   detection.Category,
			Severity:   detection.Severity,
			Confidence: confidenceFor(detection.Severity, context),
			Action:     detectionAction(detection),
			Evidence:   evidenceSlice(source, detection.Start, detection.End),
			Context:    context,
			Start:      detection.Start,
			End:        detection.End,
			Language:   LanguageUnknown,
		})
	}
	return findings
}

// FindingsToDetections converts findings back into the current policy input model.
func FindingsToDetections(findings []Finding) []Detection {
	results := make([]Detection, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.RuleID + ":" + finding.Evidence
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, Detection{
			RuleID:   finding.RuleID,
			Category: finding.Category,
			Severity: finding.Severity,
			Action:   finding.Action,
			Match:    finding.Evidence,
			Start:    finding.Start,
			End:      finding.End,
		})
	}
	return results
}

// BestFinding returns the strongest finding for logging and explanation.
func BestFinding(findings []Finding) Finding {
	best := Finding{}
	for _, finding := range findings {
		if findingScore(finding) > findingScore(best) {
			best = finding
		}
	}
	return best
}

func findingKind(ruleID, category string) string {
	switch {
	case strings.Contains(ruleID, "sqli"):
		return "sql_injection"
	case strings.Contains(ruleID, "xss"):
		return "xss"
	case strings.Contains(ruleID, "csrf"):
		return "csrf"
	case strings.Contains(ruleID, "ssrf"):
		return "ssrf"
	case strings.Contains(ruleID, "path-traversal"):
		return "path_traversal"
	case strings.Contains(ruleID, "auth"):
		return "auth_misuse"
	case strings.Contains(ruleID, "business-logic"):
		return "business_logic"
	case strings.Contains(ruleID, "framework"):
		return "framework_misuse"
	case category == "secret":
		return "secret_exposure"
	case category == "dangerous-code":
		return "dangerous_execution"
	default:
		return category
	}
}


func detectionAction(detection Detection) string {
	if detection.Action != "" {
		return detection.Action
	}
	return actionForCategory(detection.Category)
}

func actionForCategory(category string) string {
	if category == "secret" {
		return "redact"
	}
	return "block"
}

func confidenceFor(severity string, context ContentContext) Confidence {
	switch severity {
	case "critical", "high":
		if context == ContentContextCodeBlock {
			return ConfidenceHigh
		}
		return ConfidenceMedium
	case "medium":
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func findingScore(finding Finding) int {
	severityScore := 0
	switch finding.Severity {
	case "critical":
		severityScore = 40
	case "high":
		severityScore = 30
	case "medium":
		severityScore = 20
	case "low":
		severityScore = 10
	}
	confidenceScore := 0
	switch finding.Confidence {
	case ConfidenceHigh:
		confidenceScore = 3
	case ConfidenceMedium:
		confidenceScore = 2
	case ConfidenceLow:
		confidenceScore = 1
	}
	return severityScore + confidenceScore
}

func evidenceSlice(source string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(source) {
		end = len(source)
	}
	if start >= end || source == "" {
		trimmed := strings.TrimSpace(source)
		if len(trimmed) > 80 {
			return trimmed[:80]
		}
		return trimmed
	}
	evidence := strings.TrimSpace(source[start:end])
	if len(evidence) > 120 {
		return evidence[:120]
	}
	return evidence
}
