package detect

import "regexp"

// Language identifies a generated-code language family.
type Language string

const (
	LanguageUnknown    Language = "unknown"
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageJava       Language = "java"
	LanguageJSON       Language = "json"
	LanguageYAML       Language = "yaml"
)

type profileTier string

const (
	TierDeep      profileTier = "deep"
	TierMedium    profileTier = "medium"
	TierUniversal profileTier = "universal"
	TierLight     profileTier = "light"
)

type frameworkProfile struct {
	Name       string
	Language   Language
	Tier       profileTier
	Indicators []*regexp.Regexp
	Rules      []frameworkRule
}

type frameworkRule struct {
	RuleID   string
	Kind     string
	Category string
	Severity string
	Action   string
	Pattern  *regexp.Regexp
}

func frameworkProfiles() []frameworkProfile {
	return []frameworkProfile{
		expressProfile(),
		pythonFastAPIProfile(),
		reactProfile(),
		nextJSProfile(),
		pythonDjangoProfile(),
		pythonFlaskProfile(),
		langChainProfile(),
		langGraphProfile(),
		universalJSONProfile(),
		universalYAMLProfile(),
		vueProfile(),
		tailwindProfile(),
		pandasProfile(),
		numpyProfile(),
		tensorFlowProfile(),
		pyTorchProfile(),
		springProfile(),
	}
}

func makeRule(ruleID, kind, category, severity, action, pattern string) frameworkRule {
	return frameworkRule{RuleID: ruleID, Kind: kind, Category: category, Severity: severity, Action: action, Pattern: regexp.MustCompile(pattern)}
}
