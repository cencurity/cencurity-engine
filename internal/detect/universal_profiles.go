package detect

import "regexp"

func universalJSONProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "json-config",
		Language: LanguageJSON,
		Tier:     TierUniversal,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)\{.*["'](api[_-]?key|token|secret|password|command|run|script)["']\s*:`)},
		Rules: []frameworkRule{
			makeRule("cast.json.secret.inline", "secret_exposure", "secret", "high", "redact", `(?is)["'](api[_-]?key|token|secret|password|client_secret|access_key)["']\s*:\s*["'][^"'\n]{8,}["']`),
			makeRule("cast.json.command.download-exec", "dangerous_execution", "dangerous-code", "high", "block", `(?is)["'](command|cmd|run|script)["']\s*:\s*["'][^"'\n]*(curl|wget|powershell|bash|sh)[^"'\n]*(\||-enc|frombase64string)`),
			makeRule("cast.json.command.encoded", "dangerous_execution", "dangerous-code", "high", "block", `(?is)["'](command|cmd|run|script|payload)["']\s*:\s*["'][^"'\n]*(base64\s+-d|frombase64string|powershell\s+-enc)`),
		},
	}
}

func universalYAMLProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "yaml-config",
		Language: LanguageYAML,
		Tier:     TierUniversal,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?im)^(api[_-]?key|token|secret|password|command|run|script)\s*:`)},
		Rules: []frameworkRule{
			makeRule("cast.yaml.secret.inline", "secret_exposure", "secret", "high", "redact", `(?im)^(api[_-]?key|token|secret|password|client_secret|access_key)\s*:\s*['"]?[^\s#'"\n]{8,}`),
			makeRule("cast.yaml.command.download-exec", "dangerous_execution", "dangerous-code", "high", "block", `(?is)(^|\n)\s*(run|command|script)\s*:\s*['"]?[^\n]*(curl|wget|powershell|bash|sh)[^\n]*(\||-enc|frombase64string)`),
			makeRule("cast.yaml.command.encoded", "dangerous_execution", "dangerous-code", "high", "block", `(?is)(^|\n)\s*(run|command|script|payload)\s*:\s*['"]?[^\n]*(base64\s+-d|frombase64string|powershell\s+-enc)`),
		},
	}
}
