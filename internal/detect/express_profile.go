package detect

import "regexp"

func expressProfile() frameworkProfile {
	return frameworkProfile{
		Name:     "express",
		Language: LanguageJavaScript,
		Tier:     TierDeep,
		Indicators: []*regexp.Regexp{regexp.MustCompile(`(?is)require\(['"]express['"]\)|from ['"]express['"]|express\(\)|req\.(query|body|params|headers|cookies)|res\.(send|json|render)|express-session|cookie-session|jsonwebtoken|jwt\.|passport\.|passport-|req\.isAuthenticated|sequelize\.|prisma\.|knex\.|multer`)},
		Rules: []frameworkRule{
			makeRule("cast.express.sqli", "sql_injection", "app-vulnerability", "high", "block", `(?is)(const|let|var)\s+sql\s*=\s*['"`+"`"+`].{0,200}(select|update|delete|insert).{0,200}req\.(query|body|params|headers|cookies).{0,200}\n.{0,220}(query|execute|sequelize\.query|prisma\.[a-z]+Raw|knex\.raw)\(sql|(query|execute|sequelize\.query|prisma\.[a-z]+Raw|knex\.raw)\(.{0,260}(select|update|delete|insert).{0,260}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.xss", "xss", "app-vulnerability", "high", "block", `(?is)res\.(send|end|write|render)\(.{0,200}req\.(query|body|params|headers|cookies)|(const|let|var)\s+html\s*=\s*req\.(query|body|params|headers|cookies).{0,160}\n.{0,200}res\.(send|render)\(html`),
			makeRule("cast.express.ssrf", "ssrf", "app-vulnerability", "high", "block", `(?is)(const|let|var)\s+(url|target|endpoint)\s*=\s*req\.(query|body|params|headers|cookies).{0,220}\n.{0,240}(fetch|axios\.(get|post|request)|http\.(get|request)|https\.(get|request)|got|needle)\((url|target|endpoint)|(fetch|axios\.(get|post|request)|http\.(get|request)|https\.(get|request)|got|needle)\(.{0,220}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.path-traversal", "path_traversal", "app-vulnerability", "high", "block", `(?is)(((fs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync)|res\.sendFile|path\.join)\(.{0,220}req\.(query|body|params|headers|cookies))|((const|let|var)\s+(path|filename|filePath|targetPath)\s*=\s*req\.(query|body|params|headers|cookies).{0,180}\n.{0,240}(fs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync)|res\.sendFile|path\.join)\((path|filename|filePath|targetPath)))`),
			makeRule("cast.express.auth.header-admin", "auth_misuse", "auth-misuse", "high", "block", `(?is)if\s*\(\s*req\.headers\[['"]x-admin['"]\]\s*([!=]==?|\?\?)\s*['"]true['"]`),
			makeRule("cast.express.auth.cookie-admin", "auth_misuse", "auth-misuse", "high", "block", `(?is)if\s*\(\s*(req\.cookies\.(admin|role)|req\.cookies\[['"](admin|role)['"]\])`),
			makeRule("cast.express.auth.jwt-decode", "auth_misuse", "auth-misuse", "high", "block", `(?is)req\.user\s*=\s*jwt\.decode\(.{0,200}(req\.(headers|cookies|query|body)|authorization)`),
			makeRule("cast.express.auth.middleware-next-without-verify", "auth_misuse", "auth-misuse", "high", "block", `(?is)app\.(use|get|post|put|patch|delete)\(.{0,240}\(req,\s*res,\s*next\).{0,260}req\.user\s*=\s*jwt\.decode\(.{0,260}next\(`),
			makeRule("cast.express.auth.role-from-header", "auth_misuse", "auth-misuse", "high", "block", `(?is)req\.user\.(role|isAdmin)\s*=\s*req\.(headers|cookies|query|body)`),
			makeRule("cast.express.passport.user-from-input", "auth_misuse", "auth-misuse", "high", "block", `(?is)passport\.authenticate\([^)]+\).{0,220}req\.user\s*=\s*(jwt\.decode\(.{0,120}req\.(headers|cookies|query|body)|req\.(headers|cookies|query|body))`),
			makeRule("cast.express.passport.login-from-input", "auth_misuse", "auth-misuse", "high", "block", `(?is)req\.login\(.{0,200}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.passport.strategy-payload-trust", "auth_misuse", "auth-misuse", "high", "block", `(?is)passport\.use\(.{0,260}(JwtStrategy|LocalStrategy|Strategy).{0,260}done\(null,\s*(payload|req\.(body|query|params|headers|cookies))`),
			makeRule("cast.express.passport.serialize-whole-user", "framework_misuse", "framework-misuse", "high", "block", `(?is)passport\.serializeUser\(.{0,220}done\(null,\s*user\s*\)`),
			makeRule("cast.express.passport.deserialize-trust", "framework_misuse", "framework-misuse", "high", "block", `(?is)passport\.deserializeUser\(.{0,240}done\(null,\s*(serialized(User)?|payload|tokenPayload|sessionUser)\s*\)`),
			makeRule("cast.express.auth.role-guard-bypass", "auth_misuse", "auth-misuse", "high", "block", `(?is)if\s*\([^\n]{0,200}(req\.(user|session)\.(role|isAdmin)|req\.isAuthenticated\(\))[^\n]{0,120}\|\|[^\n]{0,160}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.auth.custom-next-bypass", "auth_misuse", "auth-misuse", "high", "block", `(?is)(function|const|let)\s+\w*(auth|guard|authorize)\w*\s*=?.{0,120}\(req,\s*res,\s*next\).{0,220}if\s*\([^\n]{0,160}req\.(query|body|params|headers|cookies)[^\n]{0,120}\)\s*\{?\s*next\(`),
			makeRule("cast.express.auth.isauthenticated-bypass", "auth_misuse", "auth-misuse", "high", "block", `(?is)if\s*\(\s*!?req\.isAuthenticated\(\)\s*(\|\||&&).{0,160}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.auth.skip-jwt-verify", "auth_misuse", "auth-misuse", "high", "block", `(?is)jwt\.verify\([^\n]{0,200}(ignoreExpiration\s*:\s*true|complete\s*:\s*true)`),
			makeRule("cast.express.session.insecure-config", "framework_misuse", "framework-misuse", "high", "block", `(?is)(express-session|cookie-session|session)\([^\n]{0,260}(saveUninitialized\s*:\s*true|secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['"]none['"]|secret\s*:\s*['"][^'"]+['"])`),
			makeRule("cast.express.session.user-controlled-cookie", "framework_misuse", "framework-misuse", "high", "block", `(?is)res\.cookie\([^\n]{0,120}(session|token|auth)[^\n]{0,160}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.session.user-controlled-session", "framework_misuse", "framework-misuse", "high", "block", `(?is)req\.session\.(user|role|isAdmin|token)\s*=\s*req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.session.guard-bypass", "framework_misuse", "framework-misuse", "high", "block", `(?is)if\s*\([^\n]{0,160}req\.session\.(user|role|isAdmin)[^\n]{0,120}\|\|[^\n]{0,160}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.session.user-from-body", "framework_misuse", "framework-misuse", "high", "block", `(?is)req\.session\.user\s*=\s*req\.(body|query|params|headers|cookies)`),
			makeRule("cast.express.sequelize.literal", "sql_injection", "app-vulnerability", "high", "block", `(?is)sequelize\.literal\(.{0,220}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.prisma.raw-unsafe", "sql_injection", "app-vulnerability", "high", "block", `(?is)prisma\.\$(queryRawUnsafe|executeRawUnsafe)\(.{0,260}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.knex.raw", "sql_injection", "app-vulnerability", "high", "block", `(?is)knex\.raw\(.{0,260}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.upload.user-path", "path_traversal", "app-vulnerability", "high", "block", `(?is)multer\.diskStorage\(.{0,260}destination\s*:\s*\([^\n]{0,120}req\.(query|body|params|headers|cookies)`),
			makeRule("cast.express.upload.originalname", "path_traversal", "app-vulnerability", "high", "block", `(?is)(cb\(|filename\s*:)\s*[^\n]{0,160}file\.originalname`),
		},
	}
}
