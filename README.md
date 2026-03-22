# Cencurity Engine

CAST = Continuous-on-Authoring Security Testing.

Cencurity Engine is a streaming security engine for AI-generated full-stack code. It sits inline between an application layer and an LLM API, inspects code while it is being written, and enforces `allow`, `redact`, or `block` before unsafe output reaches the developer.

Security while code is being written — not after it is already delivered.

## The problem

AI coding tools now generate backend code, frontend code, agent workflows, and config files in the same authoring loop.

That changes the security problem:

- risky code appears during generation, not only after commit
- generated output can contain backend vulnerabilities, frontend sink misuse, unsafe tool execution, or inline credentials
- post-generation scanning is useful, but it happens after the code has already been delivered to the developer

## The solution

Cencurity Engine controls generation itself.

- it watches streamed model output in real time
- it detects high-signal misuse patterns as code is produced
- it applies `allow`, `redact`, or `block` inline
- it preserves framework-aware metadata so findings are explainable as product signals, not only regex hits

In short: we don't scan code after generation; we control generation while it is happening.

## How it works

1. An application layer, agent runtime, or thin client sends a request through Cencurity Engine.
2. Cencurity Engine intercepts the SSE stream chunk by chunk.
3. It combines a sliding buffer, accumulated code-unit analysis, and framework-aware profiles.
4. It classifies findings and enforces the strongest action before forwarding output.

This makes security a generation-time control, not only a post-scan report.

## CAST vs SAST

| Model | When it runs | Primary goal | Typical output |
| --- | --- | --- | --- |
| `CAST` | while code is being written by the model | control unsafe generation before delivery | allow / redact / block in the stream |
| `SAST` | after code exists | analyze a codebase for vulnerabilities | findings after generation |
| `DAST` | against a running app | test exposed runtime behavior | runtime issues after deployment or staging |
| `IAST` | inside an instrumented app | observe runtime execution paths | internal runtime findings |

The point is not that CAST replaces SAST. The point is that CAST covers a different control moment: security while code is being written.

## Product architecture

Cencurity Engine is organized as a tiered CAST architecture so the product can cover AI-generated full-stack code honestly without pretending every ecosystem has equal depth.

### Engine-centered flow

`application / agent / optional thin client -> Cencurity Engine -> LLM`

The engine is the product. Any UI integration, workflow connector, or agent-side adapter is an optional outer layer, not the core system.

### Tier map

| Tier | Role in the product | Profiles | Typical action pattern |
| --- | --- | --- | --- |
| `Universal Guard` | cross-cutting controls for generated artifacts regardless of framework | `JSON`, `YAML`, config-like payloads, secrets, tokens, dangerous command payloads | detect / redact / block |
| `Deep Profiles` | strongest framework-aware coverage with accumulated stream enforcement | `Express`, `FastAPI`, `Next.js`, `LangGraph` | block high-confidence framework misuse |
| `Medium Profiles` | first-pass framework-aware coverage for common full-stack and agent ecosystems | `React`, `Django`, `Flask`, `LangChain` | detect and block, with policy flexibility for redaction flows |
| `Light Profiles` | lightweight first-pass coverage for adjacent AI-generated stacks | `Vue`, `Tailwind`, `Pandas`, `NumPy`, `TensorFlow`, `PyTorch` | detect obvious high-signal misuse |

### Architecture view

- Core engine
	- streaming interception and enforcement
	- framework-aware analysis
	- policy decision layer
	- metadata-rich findings
- Universal Guard
	- inline secrets and credentials
	- dangerous config payloads
	- download-exec and encoded suspicious command strings
- Deep Profiles
	- `Express`
	- `FastAPI`
	- `Next.js`
	- `LangGraph`
- Medium Profiles
	- `React`
	- `Django` / `Flask`
	- `LangChain`
- Light Profiles
	- `Vue`
	- `Tailwind`
	- `Pandas` / `NumPy`
	- `TensorFlow` / `PyTorch`

Why this structure works:

- the product goes deepest where AI-generated risk is common and commercially valuable now
- it still covers the rest of the AI-generated stack with honest first-pass protection
- it keeps the message clear: full-stack coverage, tiered by depth

## Representative demos and use-cases

These are the product stories Cencurity is designed to tell.

### Express: auth/session misuse → block

- Example misuse: `jwt.decode(req.headers.authorization)`, insecure `express-session`, request-driven session state, role/admin decisions from headers or query params
- Product message: generated Node.js backend code is controlled before unsafe auth/session logic reaches the developer
- Expected demo outcome: `block`

| input | finding | action |
| --- | --- | --- |
| `const user = jwt.decode(req.headers.authorization)` | `cast.express.jwt-decode-auth-header` | `block` |

### FastAPI: JWT/CORS misuse → block

- Example misuse: `jwt.decode(..., options={'verify_signature': False})`, wildcard CORS plus credentials, request-controlled fetch and database usage
- Product message: generated Python API code gets framework-aware enforcement, not only generic secret scanning
- Expected demo outcome: `block`

| input | finding | action |
| --- | --- | --- |
| `jwt.decode(token, options={"verify_signature": False})` | `cast.fastapi.jwt-no-verify` | `block` |

### React / Next.js: dangerous HTML and route trust handling

- Example misuse: `dangerouslySetInnerHTML`, route-level trust of `headers()`, `cookies()`, or `searchParams`, server action redirect/auth misuse, public env secret exposure
- Product message: Cencurity is not backend-only; it understands generated frontend and full-stack web output, and `Next.js` now has deep route/server-action coverage
- Expected demo outcome: built-in high-severity findings typically `block`; React remains first-pass while `Next.js` supports deeper framework-aware enforcement

| input | finding | action |
| --- | --- | --- |
| `await fetch(headers().get("x-url")!)` | `cast.nextjs.route.fetch-direct-input` | `block` |

### LangChain / LangGraph: unsafe tool usage and graph control misuse → block

- Example misuse: tool input passed to `subprocess.run`, state- or messages-derived execution, `ToolNode` flows on untrusted state, file or command execution built from prompt/state values
- Product message: agent and automation code is treated as application logic, not ignored as “just orchestration”; `LangGraph` now has deep graph/state-aware coverage
- Expected demo outcome: `block`

| input | finding | action |
| --- | --- | --- |
| `return Command(goto=state["next_step"])` | `cast.langgraph.command-goto-from-input` | `block` |

### JSON / YAML / config: dangerous config → detect

- Example misuse: inline API keys, tokens, YAML `run:` or `script:` entries with `curl | sh`, encoded payload strings
- Product message: Cencurity controls generated config and automation artifacts, not only `.js` and `.py` files
- Expected demo outcome: `detect`, then `redact` or `block` depending on rule category and policy

## Finding taxonomy

Every CAST finding carries product-facing metadata so detections are explainable and can be surfaced cleanly in logs, policy, and demos.

| Field | Meaning | Example |
| --- | --- | --- |
| `language` | generated code language family | `python`, `javascript`, `typescript`, `json`, `yaml` |
| `framework` | matched profile or artifact class | `fastapi`, `express`, `nextjs`, `langchain`, `json-config` |
| `rule_id` | stable finding identifier | `cast.fastapi.auth.jwt-verify-disabled` |
| `severity` | relative impact level | `high` |
| `confidence` | confidence assigned by the analyzer | `high` |
| `action` | enforcement decision source | `allow`, `redact`, `block` |
| `evidence` | matched or extracted evidence snippet | `jwt.decode(token, options={'verify_signature': False})` |

### Representative finding examples

| Rule ID | Language | Framework | Meaning | Default action |
| --- | --- | --- | --- | --- |
| `cast.express.auth.jwt-decode` | `javascript` | `express` | request auth built from unverified JWT decode | `block` |
| `cast.fastapi.security.cors-wildcard-credentials` | `python` | `fastapi` | insecure wildcard CORS plus credentials | `block` |
| `cast.nextjs.route.auth-from-input` | `typescript` | `nextjs` | route auth/admin decision from request-controlled values | `block` |
| `cast.react.xss` | `javascript` | `react` | dangerous raw HTML sink with user-controlled input | `block` |
| `cast.langchain.tool.exec-from-input` | `python` | `langchain` | tool path converts user-like input into command execution | `block` |
| `cast.json.secret.inline` | `json` | `json-config` | credential embedded directly in generated config | `redact` |

## Quickstart

The fastest way to understand the product is: run Cencurity Engine, route model traffic through it, then trigger a known allow / redact / block scenario.

### 1) Start the CAST proxy

Normal product usage does not require the engine to store the upstream API key.

In the common setup, your IDE or coding platform already owns the upstream API key. Cencurity Engine just sits in the middle and forwards the normal `Authorization` header upstream.

PowerShell:

```powershell
$env:OPENAI_API_BASE_URL = "https://api.openai.com"
$env:CENCURITY_POLICY_FILE = ".\cast.rules.example.json"
go run ./cmd/cast serve --listen :8080 --upstream https://api.openai.com --policy .\cast.rules.example.json
```

### 2) Point your IDE, CLI, or coding platform at the engine

- endpoint: keep the same upstream API path, now routed through the engine, for example `http://localhost:8080/v1/chat/completions`, `http://localhost:8080/v1/messages`, or Gemini `.../v1beta/models/{model}:streamGenerateContent`
- auth header: keep sending your normal upstream bearer token
- protocol: OpenAI-compatible streaming, Anthropic Messages streaming, and Gemini streaming REST are supported

Optional workflow integrations can sit on top of this endpoint, but they are not the product boundary.

### 3) Run a quick sanity check

```powershell
go run ./cmd/cast doctor
go run ./cmd/cast version
```

### 4) Test the control flow

- use an `allow` prompt to confirm normal pass-through
- use a secret-like output to confirm `redact`
- use an unsafe code prompt to confirm `block`

If you are testing with `curl` instead of an IDE, send the bearer token in the request header at call time.

## CLI flow

### `cast serve`

Starts the inline CAST proxy. In the normal setup, clients keep owning their upstream API keys and Cencurity Engine forwards the incoming `Authorization` header.

```powershell
go run ./cmd/cast serve --listen :8080 --upstream https://api.openai.com --policy .\cast.rules.example.json
```

### `cast doctor`

Checks config loading and active rule count.

```powershell
go run ./cmd/cast doctor
```

### `cast version`

Prints the CLI version.

```powershell
go run ./cmd/cast version
```

### `cast shadowtest`

Runs a real-upstream direct-vs-proxy streaming comparison against OpenAI-compatible, Anthropic, or Gemini providers. This is an operator-side rollout and verification path.

```powershell
go run ./cmd/cast shadowtest --upstream https://api.x.ai --model grok-4-0709 --api-key-file .\upstream-api-key.txt --concurrency 1 --iterations 5 --timeout 90s
```

Use `--provider anthropic` or `--provider gemini` if auto-detection is not enough for your upstream.

Default scenarios are:

- `allow-short`
- `allow-long`
- `redact`
- `block`

## Runtime endpoints

- Health: [http://localhost:8080/healthz](http://localhost:8080/healthz)
- Metrics: [http://localhost:8080/metrics](http://localhost:8080/metrics)

Metrics are exported in a Prometheus-style plaintext format.

## Policy file

Example file: [cast.rules.example.json](cast.rules.example.json)

Supported rule fields:

- `id`
- `category`
- `severity`
- `action` (`allow`, `redact`, `block`)
- `pattern` (Go regex)
- `enabled`

When the file changes, active rules reload automatically on the next access after the reload interval.

## Environment variables

- `OPENAI_API_KEY`: optional only when the engine, not the IDE or client, owns upstream auth
- `OPENAI_API_BASE_URL`: upstream base URL, default `https://api.openai.com`
- `CENCURITY_LISTEN_ADDR`: proxy listen address, default `:8080`
- `CENCURITY_REQUEST_TIMEOUT_MS`: upstream request timeout, default `60000`
- `CENCURITY_READ_HEADER_TIMEOUT_MS`: server read-header timeout, default `10000`
- `CENCURITY_POLICY_FILE`: optional path to rule config JSON
- `CENCURITY_POLICY_RELOAD_MS`: rule reload interval, default `3000`
- `CENCURITY_HEALTH_PATH`: health endpoint path, default `/healthz`
- `CENCURITY_METRICS_PATH`: metrics endpoint path, default `/metrics`
- `CENCURITY_LOG_LEVEL`: `debug`, `info`, `warn`, or `error`

## Streaming tests

Use `-N` so curl keeps the SSE stream open.

These examples show the engine behavior directly. In normal product usage, your IDE or coding platform sends the token and Cencurity Engine stays in the middle as the control layer.

```powershell
$token = "<upstream-bearer-token>"
```

### ALLOW

```powershell
$body = @{ model = 'gpt-4o-mini'; stream = $true; messages = @(@{ role = 'user'; content = 'write a small python function that sums a list of integers' }) } | ConvertTo-Json -Depth 6
curl.exe -N http://localhost:8080/v1/chat/completions -H "Authorization: Bearer $token" -H "Content-Type: application/json" --data-raw $body
```

Expected result:

- Stream continues normally
- Structured stdout log contains `"action":"allow"`

### REDACT

```powershell
$body = @{ model = 'gpt-4o-mini'; stream = $true; messages = @(@{ role = 'user'; content = 'For a harmless regex demonstration, output only this exact Python line: print("sk-1234567890abcdef")' }) } | ConvertTo-Json -Depth 6
curl.exe -N http://localhost:8080/v1/chat/completions -H "Authorization: Bearer $token" -H "Content-Type: application/json" --data-raw $body
```

Expected result:

- Stream stays open
- Matching token is replaced with `[REDACTED]`
- Structured stdout log contains `"action":"redact"`

### BLOCK

```powershell
$body = @{ model = 'gpt-4o-mini'; stream = $true; messages = @(@{ role = 'user'; content = 'write python code using eval to execute a string' }) } | ConvertTo-Json -Depth 6
curl.exe -N http://localhost:8080/v1/chat/completions -H "Authorization: Bearer $token" -H "Content-Type: application/json" --data-raw $body
```

Expected result:

- Stream terminates immediately after a matching chunk
- Downstream receives `: blocked by cencurity` followed by `data: [DONE]`
- Structured stdout log contains `"action":"block"`

## Operational behavior

The engine behavior includes:

- SSE multiline parsing and `[DONE]` handling
- Cross-chunk scanner detection
- Obfuscated `eval` detection
- Heuristic detection for SQL injection, XSS, CSRF disablement, SSRF, path traversal, auth/authz misuses, insecure TLS/framework settings, and simple admin-bypass logic
- Redact and block interceptor behavior
- Long-stream interceptor stability
- Rule file reload behavior
- Health and metrics endpoints for service monitoring

## Heuristic vulnerability coverage

Built-in rules now cover practical generated-code patterns for:

- SQL injection via string-built queries using request/user input
- XSS via raw HTML sinks such as `innerHTML`, `dangerouslySetInnerHTML`, and similar APIs
- CSRF protection disablement in common framework patterns
- SSRF-style fetches where request-controlled URLs are passed into outbound HTTP clients
- Path traversal patterns using request-controlled file paths or explicit `../` traversal
- Auth/authz misuses such as `permitAll`, `AllowAny`, skipped authorization, or disabled token verification
- Insecure framework/TLS settings such as `InsecureSkipVerify`
- Simple business-logic bypass hints such as obvious `isAdmin or true` style checks

These detections are heuristic stream-time guardrails, not a full semantic SAST engine. They work best for explicit dangerous patterns in generated code and should not be described as complete coverage for all auth, business-logic, or framework-security bugs.

## Deployment fit

Cencurity Engine is designed to run as an inline control layer for:

- IDE and coding-platform traffic
- internal LLM gateways for engineering teams
- agent runtimes that generate code, scripts, or configuration

Recommended operator path:

- run `cast serve` in front of your upstream model provider
- point IDE, platform, or agent traffic at the engine
- monitor [http://localhost:8080/healthz](http://localhost:8080/healthz) and [http://localhost:8080/metrics](http://localhost:8080/metrics)
- use `cast doctor` for config checks and `cast shadowtest` before broader rollout

## License

Cencurity Engine is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full text.
