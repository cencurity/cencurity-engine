package detect

import "testing"

func TestNextJSFrameworkFindings(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	tests := []struct {
		name   string
		unit   string
		ruleID string
	}{
		{
			name: "server action auth from cookie",
			unit: "```ts\n'use server'\nimport { cookies } from 'next/headers'\nexport async function promote() {\n  if (cookies().get('admin')?.value === 'true') return { ok: true }\n}\n```",
			ruleID: "cast.nextjs.server-action.auth-from-input",
		},
		{
			name: "server action redirect from form input",
			unit: "```ts\n'use server'\nimport { redirect } from 'next/navigation'\nexport async function go(formData: FormData) {\n  const target = formData.get('next')\n  redirect(target as string)\n}\n```",
			ruleID: "cast.nextjs.server-action.redirect-from-input",
		},
		{
			name: "route direct fetch from header",
			unit: "```ts\nimport { headers } from 'next/headers'\nexport async function GET() {\n  return fetch(headers().get('x-target') as string)\n}\n```",
			ruleID: "cast.nextjs.route.fetch-direct-input",
		},
		{
			name: "client token exposure",
			unit: "```tsx\nexport default function Page({ searchParams }) {\n  localStorage.setItem('token', searchParams.token)\n  return null\n}\n```",
			ruleID: "cast.nextjs.client-token-exposure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzer.Analyze(test.unit, ContentContextCodeBlock)
			assertFrameworkFinding(t, findings, test.ruleID, LanguageTypeScript, "nextjs")
		})
	}
}
