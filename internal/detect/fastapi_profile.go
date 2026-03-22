package detect

import "regexp"

func pythonFastAPIProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "fastapi",
		Language: LanguagePython,
		Tier:     TierDeep,
		Indicators: []*regexp.Regexp{
			regexp.MustCompile(`(?is)from\s+fastapi\s+import|FastAPI\(|Request\)|request\.(query_params|path_params|headers|cookies)|HTMLResponse|FileResponse|Jinja2Templates|Depends\(`),
		},
		Rules: []frameworkRule{
			makeRule("cast.fastapi.sqli", "sql_injection", "app-vulnerability", "high", "block", `(?is)(sql|query)\s*=.{0,220}(request\.(query_params|path_params|headers|cookies)|await\s+request\.json\(\)).{0,220}\n.{0,220}(session\.execute|conn\.execute|db\.execute)\((sql|query)|(session\.execute|conn\.execute|db\.execute)\(.{0,260}(request\.(query_params|path_params|headers|cookies)|await\s+request\.json\(\)).{0,220}(select|update|delete|insert)`),
			makeRule("cast.fastapi.ssrf", "ssrf", "app-vulnerability", "high", "block", `(?is)(url|target|endpoint)\s*=.{0,160}(request\.(query_params|path_params|headers|cookies)|await\s+request\.json\(\)).{0,160}\n.{0,220}(requests\.(get|post)|httpx\.(get|post|request))\((url|target|endpoint)|(requests\.(get|post)|httpx\.(get|post|request))\(.{0,220}request\.(query_params|path_params|headers|cookies)`),
			makeRule("cast.fastapi.path-traversal", "path_traversal", "app-vulnerability", "high", "block", `(?is)(file_path|path|filename)\s*=.{0,180}request\.(query_params|path_params|headers|cookies).{0,180}\n.{0,220}(FileResponse|open)\((file_path|path|filename)|(FileResponse|open)\(.{0,220}request\.(query_params|path_params|headers|cookies)`),
			makeRule("cast.fastapi.xss", "xss", "app-vulnerability", "high", "block", `(?is)(html|content)\s*=\s*request\.(query_params|path_params|headers|cookies).{0,180}\n.{0,220}(HTMLResponse|TemplateResponse)\((html|content)|(HTMLResponse|TemplateResponse)\(.{0,220}request\.(query_params|path_params|headers|cookies)`),
			makeRule("cast.fastapi.auth.jwt-verify-disabled", "auth_misuse", "auth-misuse", "high", "block", `(?is)jwt\.decode\(.{0,220}verify_signature.{0,20}False`),
			makeRule("cast.fastapi.auth.user-from-header", "auth_misuse", "auth-misuse", "high", "block", `(?is)(current_user|user|principal)\s*=\s*request\.headers\.get\(`),
			makeRule("cast.fastapi.security.cors-wildcard-credentials", "framework_misuse", "framework-misuse", "high", "block", `(?is)CORSMiddleware.{0,260}allow_origins\s*=\s*\[[^\]]*\*[^\]]*\].{0,220}allow_credentials\s*=\s*True`),
		},
	}
}
