package detect

// FrameworkAnalyzer evaluates generated code against framework-aware profiles.
type FrameworkAnalyzer struct {
	profiles []frameworkProfile
}

// NewFrameworkAnalyzer creates a framework-aware analyzer aligned to major Semgrep-covered ecosystems.
func NewFrameworkAnalyzer() *FrameworkAnalyzer {
	return &FrameworkAnalyzer{profiles: frameworkProfiles()}
}

// Analyze returns framework-specific findings for matching profiles.
func (a *FrameworkAnalyzer) Analyze(unit string, context ContentContext) []Finding {
	if unit == "" || context == ContentContextPlain {
		return nil
	}
	findings := make([]Finding, 0, 4)
	seen := make(map[string]struct{})
	for _, profile := range a.profiles {
		if !matchesProfile(profile, unit) {
			continue
		}
		for _, rule := range profile.Rules {
			location := rule.Pattern.FindStringIndex(unit)
			if len(location) != 2 {
				continue
			}
			finding := Finding{
				RuleID:     rule.RuleID,
				Kind:       rule.Kind,
				Category:   rule.Category,
				Severity:   rule.Severity,
				Confidence: ConfidenceHigh,
				Action:     rule.Action,
				Evidence:   evidenceSlice(unit, location[0], location[1]),
				Context:    context,
				Start:      location[0],
				End:        location[1],
				Language:   profile.Language,
				Framework:  profile.Name,
			}
			appendFrameworkFinding(&findings, seen, finding)
		}
	}
	return findings
}

func matchesProfile(profile frameworkProfile, unit string) bool {
	for _, indicator := range profile.Indicators {
		if indicator.MatchString(unit) {
			return true
		}
	}
	return false
}

func appendFrameworkFinding(target *[]Finding, seen map[string]struct{}, finding Finding) {
	key := finding.RuleID + ":" + finding.Evidence
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*target = append(*target, finding)
}
