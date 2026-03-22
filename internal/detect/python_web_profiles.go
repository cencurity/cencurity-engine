package detect

import "regexp"

func pythonFlaskProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "flask",
		Language: LanguagePython,
		Tier:     TierMedium,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from\s+flask\s+import|Flask\(__name__\)|request\.(args|form|json)|render_template_string|session\[`)},
		Rules: []frameworkRule{
			makeRule("cast.flask.sqli", "sql_injection", "app-vulnerability", "high", "block", `(?is)request\.(args|form|json).{0,120}\n.{0,220}(db\.(Query|Exec)|execute|query)\(.{0,220}(select|update|delete|insert)`),
			makeRule("cast.flask.xss", "xss", "app-vulnerability", "high", "block", `(?is)render_template_string\(.{0,220}request\.(args|form|json)`),
			makeRule("cast.flask.ssrf", "ssrf", "app-vulnerability", "high", "block", `(?is)(target|url)\s*=\s*request\.(args|form|json).{0,140}\n.{0,220}(requests\.(get|post)|httpx\.(get|post|request))\((target|url)`),
			makeRule("cast.flask.path-traversal", "path_traversal", "app-vulnerability", "high", "block", `(?is)(path|filename)\s*=\s*request\.(args|form|json).{0,140}\n.{0,220}(open|send_file|os\.Open)\((path|filename)`),
			makeRule("cast.flask.auth.user-from-header", "auth_misuse", "auth-misuse", "high", "block", `(?is)(g\.user|current_user|user)\s*=\s*request\.headers\.get\(`),
			makeRule("cast.flask.auth.jwt-verify-disabled", "auth_misuse", "auth-misuse", "high", "block", `(?is)jwt\.decode\(.{0,220}verify_signature.{0,20}False`),
			makeRule("cast.flask.session.user-from-input", "framework_misuse", "framework-misuse", "medium", "block", `(?is)session\[['"](user|role|is_admin)['"]\]\s*=\s*request\.(args|form|get_json|json)`),
		},
	}
}

func pythonDjangoProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "django",
		Language: LanguagePython,
		Tier:     TierMedium,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from\s+django|django\.|request\.(GET|POST|headers)|csrf_exempt|request\.session`)},
		Rules: []frameworkRule{
			makeRule("cast.django.csrf-disabled", "csrf", "framework-misuse", "high", "block", `(?is)@csrf_exempt`),
			makeRule("cast.django.xss-safe-bypass", "xss", "app-vulnerability", "high", "block", `(?is)mark_safe\(.{0,180}request\.(GET|POST)`),
			makeRule("cast.django.path-traversal", "path_traversal", "app-vulnerability", "high", "block", `(?is)(path|filename)\s*=\s*request\.(GET|POST).{0,140}\n.{0,220}(open|FileResponse|os\.Open)\((path|filename)`),
			makeRule("cast.django.auth.user-from-header", "auth_misuse", "auth-misuse", "high", "block", `(?is)(request\.user|user)\s*=\s*request\.headers\.get\(`),
			makeRule("cast.django.auth.jwt-verify-disabled", "auth_misuse", "auth-misuse", "high", "block", `(?is)jwt\.decode\(.{0,220}verify_signature.{0,20}False`),
			makeRule("cast.django.session.user-from-input", "framework_misuse", "framework-misuse", "medium", "block", `(?is)request\.session\[['"](user|role|is_admin)['"]\]\s*=\s*request\.(GET|POST)`),
		},
	}
}
