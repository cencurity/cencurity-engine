package stream

import (
	"strings"
	"testing"

	"cencurity-engine/internal/observability"
)

func TestInterceptorBlocksExpressAccumulatedSQLI(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\napp.get('/users', (req, res) => {\\nconst sql = 'SELECT * FROM users WHERE id = ' + req.query.id\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"return db.query(sql)\\n})\\n```\"}}]}\n\n",
	)
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-sqli", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressSSRFFromHeaders(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\napp.get('/fetch', (req, res) => {\\nconst target = req.headers['x-target-url']\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"return axios.get(target)\\n})\\n```\"}}]}\n\n",
	)
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-ssrf", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressPathTraversalFromParams(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\napp.get('/file/:name', (req, res) => {\\nconst filePath = req.params.name\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"return res.sendFile(filePath)\\n})\\n```\"}}]}\n\n",
	)
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-path", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressSessionMisuse(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst session = require('express-session')\\napp.use(session({ secret: 'hardcoded', saveUninitialized: true, cookie: { secure: false, httpOnly: false } }))\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-session", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressJWTDecodeMiddleware(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\nconst jwt = require('jsonwebtoken')\\napp.use((req, res, next) => {\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"req.user = jwt.decode(req.headers.authorization)\\nnext()\\n})\\n```\"}}]}\n\n",
	)
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-jwt", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressPrismaRawUnsafe(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\napp.get('/users', async (req, res) => {\\nreturn prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = ' + req.query.id)\\n})\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-prisma", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressUploadOriginalName(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst multer = require('multer')\\nconst storage = multer.diskStorage({ filename: (req, file, cb) => cb(null, file.originalname) })\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-upload", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressPassportUserFromInput(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\nconst passport = require('passport')\\napp.get('/me', passport.authenticate('jwt', { session: false }), (req, res, next) => {\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"req.user = jwt.decode(req.headers.authorization)\\nnext()\\n})\\n```\"}}]}\n\n",
	)
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-passport-user", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressRoleGuardBypass(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\nfunction requireAdmin(req, res, next) {\\n  if (req.user.role === 'admin' || req.query.admin === 'true') return next()\\n  return res.status(403).end()\\n}\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-role-guard", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressSessionGuardBypass(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\nfunction adminGuard(req, res, next) {\\n  if (req.session.isAdmin || req.query.admin === 'true') return next()\\n  return res.status(403).end()\\n}\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-session-guard", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressSessionUserFromBody(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\napp.post('/session', (req, res) => {\\n  req.session.user = req.body.user\\n})\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-session-body", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressPassportStrategyPayloadTrust(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst passport = require('passport')\\npassport.use(new JwtStrategy(opts, (payload, done) => {\\n  return done(null, payload)\\n}))\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-passport-strategy", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressPassportDeserializeTrust(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst passport = require('passport')\\npassport.deserializeUser((serializedUser, done) => {\\n  done(null, serializedUser)\\n})\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-passport-deserialize", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

func TestInterceptorBlocksExpressIsAuthenticatedBypass(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"```js\\nconst express = require('express')\\nfunction authGuard(req, res, next) {\\n  if (req.isAuthenticated() || req.query.debug === 'true') return next()\\n  return res.status(401).end()\\n}\\n```\"}}]}\n\n")
	logger := observability.NewLogger("error")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "express-isauthenticated", Vendor: "test", Model: "test-model"}, logger); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}
