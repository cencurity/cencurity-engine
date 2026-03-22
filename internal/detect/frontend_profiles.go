package detect

import "regexp"

func reactProfile() frameworkProfile {
return frameworkProfile{
Name:     "react",
Language: LanguageJavaScript,
Tier:     TierMedium,
Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from ['"]react['"]|function\s+[A-Z][A-Za-z0-9_]*\(|dangerouslySetInnerHTML|useSearchParams|router\.query|localStorage`)},
Rules: []frameworkRule{
makeRule("cast.react.xss", "xss", "app-vulnerability", "high", "block", `(?is)dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^\n]{0,160}(props\.|location\.|searchParams|router\.query|params)`),
makeRule("cast.react.fetch.user-url", "ssrf", "app-vulnerability", "medium", "block", `(?is)(fetch|axios\.(get|post|request))\(.{0,220}(props\.|location\.|window\.location|searchParams|router\.query|params)`),
makeRule("cast.react.token-storage", "framework_misuse", "framework-misuse", "medium", "block", `(?is)(localStorage|sessionStorage)\.setItem\([^\n]{0,120}['"](token|apiKey|apikey|secret)['"][^\n]{0,180}(props\.|location\.|searchParams|router\.query|params)`),
makeRule("cast.react.public-env-secret", "framework_misuse", "framework-misuse", "medium", "block", `(?is)process\.env\.(REACT_APP|VITE)_[A-Z0-9_]*(SECRET|TOKEN|KEY)`),
},
}
}

func nextJSProfile() frameworkProfile {
return frameworkProfile{
Name:     "nextjs",
Language: LanguageTypeScript,
Tier:     TierDeep,
Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from ['"]next/|NextRequest|searchParams|useSearchParams|router\.query|req\.nextUrl|cookies\(|headers\(|NEXT_PUBLIC_|['"]use server['"]|redirect\(|permanentRedirect\(`)},
Rules: []frameworkRule{
makeRule("cast.nextjs.xss", "xss", "app-vulnerability", "high", "block", `(?is)dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^\n]{0,160}(searchParams|router\.query|params)`),
makeRule("cast.nextjs.fetch.user-url", "ssrf", "app-vulnerability", "medium", "block", `(?is)(const|let)\s+(url|target)\s*=\s*(searchParams|get\(|req\.nextUrl\.searchParams|headers\(\)\.get|cookies\(\)\.get).{0,180}\n.{0,240}(fetch|axios\.(get|post|request))\((url|target)`),
makeRule("cast.nextjs.route.auth-from-input", "auth_misuse", "auth-misuse", "high", "block", `(?is)export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\(.{0,260}(searchParams\.get\(['"](admin|user|role|auth)['"]\)|headers\(\)\.get\(['"]x-(user|role|admin)['"]\)|cookies\(\)\.get\(['"](user|role|admin)['"]\))`),
makeRule("cast.nextjs.server-action.auth-from-input", "auth_misuse", "auth-misuse", "high", "block", `(?is)['"]use server['"].{0,260}(cookies\(\)\.get\(['"](role|admin|user|auth)['"]\)|headers\(\)\.get\(['"]x-(role|admin|user|auth)['"]\)|formData\.get\(['"](role|admin|user|auth)['"]\))`),
makeRule("cast.nextjs.server-action.redirect-from-input", "auth_misuse", "auth-misuse", "high", "block", `(?is)['"]use server['"].{0,260}(const|let)\s+(target|destination|url)\s*=\s*(formData\.get\(|searchParams\.get\(|headers\(\)\.get\(|cookies\(\)\.get\().{0,220}\n.{0,220}(redirect|permanentRedirect)\((target|destination|url)(\s+as\s+string)?`),
makeRule("cast.nextjs.route.fetch-direct-input", "ssrf", "app-vulnerability", "high", "block", `(?is)export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\(.{0,260}(fetch|axios\.(get|post|request))\(.{0,220}(searchParams\.get\(|headers\(\)\.get\(|cookies\(\)\.get\()`),
makeRule("cast.nextjs.client-token-exposure", "framework_misuse", "framework-misuse", "high", "block", `(?is)(localStorage|sessionStorage)\.setItem\([^\n]{0,120}['"](token|secret|apiKey|apikey)['"][^\n]{0,220}(searchParams|router\.query|params|headers\(\)|cookies\(\))`),
makeRule("cast.nextjs.public-env-secret", "framework_misuse", "framework-misuse", "medium", "block", `(?is)process\.env\.NEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|KEY)`),
},
}
}

func vueProfile() frameworkProfile {
return frameworkProfile{
Name:     "vue",
Language: LanguageJavaScript,
Tier:     TierLight,
Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)from ['"]vue['"]|createApp\(|<template>|v-html|useRoute\(`)},
Rules: []frameworkRule{
makeRule("cast.vue.xss", "xss", "app-vulnerability", "medium", "block", `(?is)v-html\s*=\s*['"][^'"]*(route\.query|props\.|useRoute\(\)\.query|window\.location)`),
},
}
}

func tailwindProfile() frameworkProfile {
return frameworkProfile{
Name:     "tailwind",
Language: LanguageTypeScript,
Tier:     TierLight,
Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)tailwind\.config|safelist\s*:|@tailwind|theme\s*:`)},
Rules: []frameworkRule{
makeRule("cast.tailwind.safelist.user-controlled", "framework_misuse", "framework-misuse", "medium", "block", `(?is)safelist\s*:\s*(process\.env|req\.(query|body|params)|searchParams|route\.query)`),
makeRule("cast.tailwind.content.user-controlled", "framework_misuse", "framework-misuse", "low", "block", `(?is)content\s*:\s*(process\.env|req\.(query|body|params))`),
},
}
}
