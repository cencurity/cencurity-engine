package detect

import "regexp"

var taintedAssignmentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)([a-z_][a-z0-9_]*)\s*[:=]+\s*request\.(args|get_json|form|query_params|query|params|body)`),
	regexp.MustCompile(`(?im)([a-z_][a-z0-9_]*)\s*[:=]+\s*req\.(query|params|body)`),
	regexp.MustCompile(`(?im)([a-z_][a-z0-9_]*)\s*[:=]+\s*r\.URL\.Query\(\)\.Get\(`),
}

// CodeAnalyzer evaluates accumulated code units for higher-level CAST findings.
type CodeAnalyzer struct {
	frameworks *FrameworkAnalyzer
}

// NewCodeAnalyzer creates a code-unit analyzer.
func NewCodeAnalyzer() *CodeAnalyzer {
	return &CodeAnalyzer{frameworks: NewFrameworkAnalyzer()}
}

// AnalyzeCodeUnit finds source-sink style issues in accumulated generated code.
func (a *CodeAnalyzer) AnalyzeCodeUnit(unit string, context ContentContext) []Finding {
	if unit == "" || context == ContentContextPlain {
		return nil
	}
	findings := make([]Finding, 0, 4)
	seen := make(map[string]struct{})
	for _, finding := range a.frameworks.Analyze(unit, context) {
		appendCodeFinding(&findings, seen, finding)
	}
	for _, variable := range taintedVariables(unit) {
		appendCodeFinding(&findings, seen, variableSinkFinding(unit, variable, context, `(?is)(db\.(Query|Exec)|execute|query)\([^\n]{0,220}(select|update|delete|insert)[^\n]{0,220}(\+\s*%s|%s\s*\+|%s\)|fmt\.Sprintf[^\n]{0,120}%s)`, "cast.sqli.source-sink", "app-vulnerability", "high", "sql_injection"))
		appendCodeFinding(&findings, seen, variableSinkFinding(unit, variable, context, `(?is)(requests\.(get|post)|http\.Get|axios\.get|fetch|urlopen)\([^\n]{0,160}%s`, "cast.ssrf.source-sink", "app-vulnerability", "high", "ssrf"))
		appendCodeFinding(&findings, seen, variableSinkFinding(unit, variable, context, `(?is)(os\.(Open|ReadFile)|ioutil\.ReadFile|filepath\.Join|open\(|send_file|sendFile)\([^\n]{0,160}%s`, "cast.path-traversal.source-sink", "app-vulnerability", "high", "path_traversal"))
		appendCodeFinding(&findings, seen, variableSinkFinding(unit, variable, context, `(?is)(innerHTML\s*=|dangerouslySetInnerHTML[^\n]{0,80}|v-html=)[^\n]{0,160}%s`, "cast.xss.source-sink", "app-vulnerability", "high", "xss"))
	}
	return findings
}

func taintedVariables(unit string) []string {
	seen := make(map[string]struct{})
	results := make([]string, 0, 4)
	for _, pattern := range taintedAssignmentPatterns {
		matches := pattern.FindAllStringSubmatch(unit, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			name := match[1]
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			results = append(results, name)
		}
	}
	return results
}

func variableSinkFinding(unit, variable string, context ContentContext, template, ruleID, category, severity, kind string) Finding {
	pattern := regexp.MustCompile(regexp.QuoteMeta(""))
	_ = pattern
	compiled := regexp.MustCompile(replaceVar(template, regexp.QuoteMeta(variable)))
	location := compiled.FindStringIndex(unit)
	if len(location) != 2 {
		return Finding{}
	}
	return Finding{
		RuleID:     ruleID,
		Kind:       kind,
		Category:   category,
		Severity:   severity,
		Confidence: ConfidenceHigh,
		Action:     "block",
		Evidence:   evidenceSlice(unit, location[0], location[1]),
		Context:    context,
		Start:      location[0],
		End:        location[1],
		Language:   detectLanguage(unit),
	}
}

func replaceVar(template, variable string) string {
	result := template
	for regexp.MustCompile(`%s`).MatchString(result) {
		result = regexp.MustCompile(`%s`).ReplaceAllString(result, variable)
	}
	return result
}

func appendCodeFinding(target *[]Finding, seen map[string]struct{}, finding Finding) {
	if finding.RuleID == "" {
		return
	}
	key := finding.RuleID + ":" + finding.Evidence
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*target = append(*target, finding)
}

func detectLanguage(unit string) Language {
	for _, profile := range frameworkProfiles() {
		if matchesProfile(profile, unit) {
			return profile.Language
		}
	}
	return LanguageUnknown
}
