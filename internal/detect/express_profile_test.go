package detect

import "testing"

func TestExpressFrameworkFindings(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	tests := []struct {
		name   string
		unit   string
		ruleID string
	}{
		{
			name: "sqli req query to db",
			unit: "```js\nconst express = require('express')\napp.get('/users', (req, res) => {\n  const sql = 'SELECT * FROM users WHERE id = ' + req.query.id\n  return db.query(sql)\n})\n```",
			ruleID: "cast.express.sqli",
		},
		{
			name: "ssrf req body to axios",
			unit: "```js\nconst express = require('express')\napp.post('/fetch', (req, res) => {\n  const target = req.body.url\n  return axios.get(target)\n})\n```",
			ruleID: "cast.express.ssrf",
		},
		{
			name: "path traversal req params to fs",
			unit: "```js\nconst express = require('express')\napp.get('/file/:name', (req, res) => {\n  const filePath = req.params.name\n  return fs.readFile(filePath, () => {})\n})\n```",
			ruleID: "cast.express.path-traversal",
		},
		{
			name: "xss req cookies to res send",
			unit: "```js\nconst express = require('express')\napp.get('/hello', (req, res) => {\n  return res.send(req.cookies.html)\n})\n```",
			ruleID: "cast.express.xss",
		},
		{
			name: "header based admin auth",
			unit: "```js\nconst express = require('express')\napp.get('/admin', (req, res) => {\n  if (req.headers['x-admin'] === 'true') {\n    return res.send('ok')\n  }\n})\n```",
			ruleID: "cast.express.auth.header-admin",
		},
		{
			name: "insecure express session",
			unit: "```js\nconst session = require('express-session')\napp.use(session({ secret: 'hardcoded', saveUninitialized: true, cookie: { secure: false, httpOnly: false } }))\n```",
			ruleID: "cast.express.session.insecure-config",
		},
		{
			name: "jwt decode middleware",
			unit: "```js\nconst express = require('express')\nconst jwt = require('jsonwebtoken')\napp.use((req, res, next) => {\n  req.user = jwt.decode(req.headers.authorization)\n  next()\n})\n```",
			ruleID: "cast.express.auth.jwt-decode",
		},
		{
			name: "role from header",
			unit: "```js\nconst express = require('express')\napp.use((req, res, next) => {\n  req.user.role = req.headers['x-role']\n  next()\n})\n```",
			ruleID: "cast.express.auth.role-from-header",
		},
		{
			name: "prisma raw unsafe",
			unit: "```js\nconst express = require('express')\napp.get('/users', async (req, res) => {\n  return prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = ' + req.query.id)\n})\n```",
			ruleID: "cast.express.prisma.raw-unsafe",
		},
		{
			name: "knex raw body",
			unit: "```js\nconst express = require('express')\napp.post('/users', async (req, res) => {\n  return knex.raw('SELECT * FROM users WHERE email = ' + req.body.email)\n})\n```",
			ruleID: "cast.express.knex.raw",
		},
		{
			name: "upload originalname",
			unit: "```js\nconst multer = require('multer')\nconst storage = multer.diskStorage({\n  filename: (req, file, cb) => cb(null, file.originalname)\n})\n```",
			ruleID: "cast.express.upload.originalname",
		},
		{
			name: "passport user from input",
			unit: "```js\nconst express = require('express')\nconst passport = require('passport')\napp.get('/me', passport.authenticate('jwt', { session: false }), (req, res, next) => {\n  req.user = jwt.decode(req.headers.authorization)\n  next()\n})\n```",
			ruleID: "cast.express.passport.user-from-input",
		},
		{
			name: "passport login from body",
			unit: "```js\nconst express = require('express')\napp.post('/login', (req, res) => {\n  req.login(req.body.user)\n})\n```",
			ruleID: "cast.express.passport.login-from-input",
		},
		{
			name: "role guard bypass",
			unit: "```js\nconst express = require('express')\nfunction requireAdmin(req, res, next) {\n  if (req.user.role === 'admin' || req.query.admin === 'true') return next()\n  return res.status(403).end()\n}\n```",
			ruleID: "cast.express.auth.role-guard-bypass",
		},
		{
			name: "custom next bypass",
			unit: "```js\nconst express = require('express')\nconst authGuard = (req, res, next) => {\n  if (req.headers['x-debug-auth'] === 'true') next()\n}\n```",
			ruleID: "cast.express.auth.custom-next-bypass",
		},
		{
			name: "session guard bypass",
			unit: "```js\nconst express = require('express')\nfunction adminGuard(req, res, next) {\n  if (req.session.isAdmin || req.query.admin === 'true') return next()\n  return res.status(403).end()\n}\n```",
			ruleID: "cast.express.session.guard-bypass",
		},
		{
			name: "session user from body",
			unit: "```js\nconst express = require('express')\napp.post('/session', (req, res) => {\n  req.session.user = req.body.user\n})\n```",
			ruleID: "cast.express.session.user-from-body",
		},
		{
			name: "passport strategy payload trust",
			unit: "```js\nconst passport = require('passport')\npassport.use(new JwtStrategy(opts, (payload, done) => {\n  return done(null, payload)\n}))\n```",
			ruleID: "cast.express.passport.strategy-payload-trust",
		},
		{
			name: "passport serialize whole user",
			unit: "```js\nconst passport = require('passport')\npassport.serializeUser((user, done) => {\n  done(null, user)\n})\n```",
			ruleID: "cast.express.passport.serialize-whole-user",
		},
		{
			name: "passport deserialize trust",
			unit: "```js\nconst passport = require('passport')\npassport.deserializeUser((serializedUser, done) => {\n  done(null, serializedUser)\n})\n```",
			ruleID: "cast.express.passport.deserialize-trust",
		},
		{
			name: "isauthenticated guard bypass",
			unit: "```js\nconst express = require('express')\nfunction authGuard(req, res, next) {\n  if (req.isAuthenticated() || req.query.debug === 'true') return next()\n  return res.status(401).end()\n}\n```",
			ruleID: "cast.express.auth.isauthenticated-bypass",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzer.Analyze(test.unit, ContentContextCodeBlock)
			assertFrameworkFinding(t, findings, test.ruleID, LanguageJavaScript, "express")
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
