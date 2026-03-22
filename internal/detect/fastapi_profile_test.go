package detect

import "testing"

func TestFastAPIFrameworkFindings(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	tests := []struct {
		name   string
		unit   string
		ruleID string
	}{
		{
			name: "sqli query params to execute",
			unit: "```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/users')\nasync def users(request: Request):\n    sql = f\"SELECT * FROM users WHERE id = {request.query_params.get('id')}\"\n    return session.execute(sql)\n```",
			ruleID: "cast.fastapi.sqli",
		},
		{
			name: "ssrf request headers to httpx",
			unit: "```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/fetch')\nasync def fetch(request: Request):\n    target = request.headers.get('x-target-url')\n    return httpx.get(target)\n```",
			ruleID: "cast.fastapi.ssrf",
		},
		{
			name: "path traversal path params to fileresp",
			unit: "```python\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import FileResponse\napp = FastAPI()\n@app.get('/files/{name}')\nasync def files(request: Request):\n    file_path = request.path_params['name']\n    return FileResponse(file_path)\n```",
			ruleID: "cast.fastapi.path-traversal",
		},
		{
			name: "xss query params to htmlresponse",
			unit: "```python\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import HTMLResponse\napp = FastAPI()\n@app.get('/page')\nasync def page(request: Request):\n    html = request.query_params.get('html')\n    return HTMLResponse(html)\n```",
			ruleID: "cast.fastapi.xss",
		},
		{
			name: "jwt verify disabled",
			unit: "```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\nasync def current_user(request: Request):\n    token = request.headers.get('authorization')\n    return jwt.decode(token, options={'verify_signature': False})\n```",
			ruleID: "cast.fastapi.auth.jwt-verify-disabled",
		},
		{
			name: "user from header",
			unit: "```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\nasync def current_user(request: Request):\n    user = request.headers.get('x-user')\n    return user\n```",
			ruleID: "cast.fastapi.auth.user-from-header",
		},
		{
			name: "cors wildcard credentials",
			unit: "```python\nfrom fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\napp.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n```",
			ruleID: "cast.fastapi.security.cors-wildcard-credentials",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzer.Analyze(test.unit, ContentContextCodeBlock)
			assertFrameworkFinding(t, findings, test.ruleID, LanguagePython, "fastapi")
			for _, finding := range findings {
				if finding.RuleID == test.ruleID {
					if finding.Evidence == "" {
						t.Fatal("expected evidence")
					}
					return
				}
			}
		})
	}
}
