package rules

func enabled(value bool) *bool {
	return &value
}

// DefaultRules returns the built-in CAST detection rules.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "secret.openai-key", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `sk[a-z0-9]{10,}`, Enabled: enabled(true)},
		{ID: "secret.xai-key", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `xai[a-z0-9]{20,}`, Enabled: enabled(true)},
		{ID: "secret.github-token", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `gh[pousr][a-z0-9]{20,}`, Enabled: enabled(true)},
		{ID: "secret.aws-access-key", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `akia[0-9a-z]{16}`, Enabled: enabled(true)},
		{ID: "secret.google-api-key", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `aiza[a-z0-9]{20,}`, Enabled: enabled(true)},
		{ID: "secret.slack-token", Category: "secret", Severity: "high", Action: "redact", Mode: "compact", Priority: 70, Pattern: `xox[baprs][a-z0-9]{10,}`, Enabled: enabled(true)},
		{ID: "secret.jwt", Category: "secret", Severity: "medium", Action: "redact", Mode: "raw", Priority: 60, Pattern: `eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9._-]{8,}\.[a-zA-Z0-9._-]{8,}`, Enabled: enabled(true)},
		{ID: "secret.named-credential", Category: "secret", Severity: "high", Action: "redact", Mode: "raw", Priority: 68, Pattern: `(?is)(api[_-]?key|token|secret|password|client_secret|access_key)\s*["':=]+\s*["'][^"'\s\n]{8,}["']`, Enabled: enabled(true)},
		{ID: "secret.private-key", Category: "secret", Severity: "critical", Action: "block", Mode: "compact", Priority: 100, Pattern: `beginprivatekey`, Enabled: enabled(true)},
		{ID: "code.eval", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 90, Pattern: `eval`, Enabled: enabled(true)},
		{ID: "code.exec", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 90, Pattern: `exec`, Enabled: enabled(true)},
		{ID: "code.os-system", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 90, Pattern: `ossystem`, Enabled: enabled(true)},
		{ID: "code.subprocess", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 90, Pattern: `subprocess(run|popen|call)`, Enabled: enabled(true)},
		{ID: "code.shell-true", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 80, Pattern: `shelltrue`, Enabled: enabled(true)},
		{ID: "code.download-exec", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 85, Pattern: `curlsh|curlbash|wgetsh|bashc|cmdexec|powershellexe|binsh`, Enabled: enabled(true)},
		{ID: "code.encoded-exec", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "compact", Priority: 85, Pattern: `base64b64decode|frombase64string|decode64|unhexlify`, Enabled: enabled(true)},
		{ID: "code.config-download-exec", Category: "dangerous-code", Severity: "high", Action: "block", Mode: "raw", Priority: 84, Pattern: `(?is)(run|command|script)\s*["':=]+\s*["'][^"'\n]*(curl|wget|powershell|bash|sh)[^"'\n]*(\||-enc|frombase64string)`, Enabled: enabled(true)},
		{ID: "vuln.sqli.concat-query", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "compact", Priority: 88, Pattern: `((select|update|delete|insert).{0,80}(where|values|set).{0,120}(request|query|params|param|input|userid|username))|((dbquery|dbexec|execute|query).{0,120}(request|query|params|param|input).{0,40}(select|update|delete|insert))`, Enabled: enabled(true)},
		{ID: "vuln.sqli.format-query", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "raw", Priority: 86, Pattern: `(?is)(SELECT|UPDATE|DELETE|INSERT)[^\n]{0,160}(\+|fmt\.Sprintf|String\.format|f"|f'|\$\{)[^\n]{0,160}(request|query|params|input|user)`, Enabled: enabled(true)},
		{ID: "vuln.xss.raw-html", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "compact", Priority: 84, Pattern: `dangerouslysetinnerhtml|innerhtml|vhtml|bypasssecuritytrusthtml|ngbindhtml|rendertemplatestring`, Enabled: enabled(true)},
		{ID: "vuln.xss.unescaped-response", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "raw", Priority: 82, Pattern: `(?is)(res\.send|Response\.Write|writer\.Write|render_template_string)[^\n]{0,160}(req\.|request\.|params|query|args|form)`, Enabled: enabled(true)},
		{ID: "vuln.csrf.disabled", Category: "framework-misuse", Severity: "high", Action: "block", Mode: "compact", Priority: 83, Pattern: `csrfexempt|csrfdisable|ignorecsrfantiforgerytoken|verifyauthenticitytokenskip|skipbeforeactionverifyauthenticitytoken|csrffalse`, Enabled: enabled(true)},
		{ID: "vuln.ssrf.user-url-fetch", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "raw", Priority: 87, Pattern: `(?is)(requests\.(get|post)|http\.Get|axios\.get|fetch|urlopen)[^\n]{0,160}(request\.|req\.|query|params|args|form|body|input|url)`, Enabled: enabled(true)},
		{ID: "vuln.path-traversal.user-path", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "raw", Priority: 87, Pattern: `(?is)(os\.(Open|ReadFile)|ioutil\.ReadFile|filepath\.Join|send_file|sendFile|open\()[^\n]{0,160}(request\.|req\.|query|params|args|form|path|filename|userInput|input)`, Enabled: enabled(true)},
		{ID: "vuln.path-traversal.dotdot", Category: "app-vulnerability", Severity: "high", Action: "block", Mode: "raw", Priority: 80, Pattern: `\.\./|\.\.\\`, Enabled: enabled(true)},
		{ID: "vuln.authz.permit-all", Category: "auth-misuse", Severity: "high", Action: "block", Mode: "compact", Priority: 82, Pattern: `permitall|allowany|skipauthorization|authorizeallrequestspermitall|authorizehttprequestsauthorizerequestanyrequestpermitall`, Enabled: enabled(true)},
		{ID: "vuln.auth.verify-disabled", Category: "auth-misuse", Severity: "high", Action: "block", Mode: "compact", Priority: 82, Pattern: `jwtdecodeverifyfalse|verifyfalse|tokenverifyfalse`, Enabled: enabled(true)},
		{ID: "vuln.framework.insecure-tls", Category: "framework-misuse", Severity: "high", Action: "block", Mode: "compact", Priority: 78, Pattern: `insecureskipverify|nodetlsrejectunauthorized0|trustallcertificates|trustallhosts`, Enabled: enabled(true)},
		{ID: "vuln.business-logic.admin-bypass", Category: "business-logic", Severity: "medium", Action: "block", Mode: "compact", Priority: 76, Pattern: `isadmintrue|roleadmin|admintrue|ifisadminortrue|ifuserroleadminortrue`, Enabled: enabled(true)},
	}
}
