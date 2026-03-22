package stream

import (
	"strings"
	"testing"

	"cencurity-engine/internal/observability"
)

func TestInterceptorBlocksFastAPIAccumulatedFindings(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
	}{
		{
			name: "fastapi sqli",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/users')\nasync def users(request: Request):\n    sql = f\"SELECT * FROM users WHERE id = {request.query_params.get('id')}\"\n",
				"    return session.execute(sql)\n```",
			},
		},
		{
			name: "fastapi ssrf",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/fetch')\nasync def fetch(request: Request):\n    target = request.headers.get('x-target-url')\n",
				"    return httpx.get(target)\n```",
			},
		},
		{
			name: "fastapi path traversal",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import FileResponse\napp = FastAPI()\n@app.get('/files/{name}')\nasync def files(request: Request):\n",
				"    return FileResponse(request.path_params['name'])\n```",
			},
		},
		{
			name: "fastapi xss",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import HTMLResponse\napp = FastAPI()\n@app.get('/page')\nasync def page(request: Request):\n",
				"    return HTMLResponse(request.query_params.get('html'))\n```",
			},
		},
		{
			name: "fastapi jwt verify disabled",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\nasync def current_user(request: Request):\n    token = request.headers.get('authorization')\n",
				"    return jwt.decode(token, options={'verify_signature': False})\n```",
			},
		},
		{
			name: "fastapi user from header",
			parts: []string{
				"```python\nfrom fastapi import FastAPI, Request\napp = FastAPI()\nasync def current_user(request: Request):\n",
				"    user = request.headers.get('x-user')\n    return user\n```",
			},
		},
		{
			name: "fastapi cors wildcard credentials",
			parts: []string{
				"```python\nfrom fastapi import FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp = FastAPI()\n",
				"app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n```",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interceptor := newTestInterceptor(t)
			writer := newFlushRecorder()
			cancelled := false
			var payload strings.Builder
			for _, part := range test.parts {
				payload.WriteString("data: {\"choices\":[{\"delta\":{\"content\":")
				payload.WriteString(quoteJSONString(part))
				payload.WriteString("}}]}\n\n")
			}
			logger := observability.NewLogger("error")
			if err := interceptor.Stream(writer, strings.NewReader(payload.String()), func() { cancelled = true }, RequestMeta{RequestID: test.name, Vendor: "test", Model: "test-model"}, logger); err != nil {
				t.Fatalf("Stream() error = %v", err)
			}
			if !cancelled {
				t.Fatal("expected cancel to be called")
			}
			if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
				t.Fatalf("expected block output, got %s", writer.buffer.String())
			}
		})
	}
}

func quoteJSONString(value string) string {
	value = strings.ReplaceAll(value, `\\`, `\\\\`)
	value = strings.ReplaceAll(value, `"`, `\\"`)
	value = strings.ReplaceAll(value, "\n", `\\n`)
	return `"` + value + `"`
}
