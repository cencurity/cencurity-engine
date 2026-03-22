# Cencurity Engine v0.1.0

## Summary

First public release of Cencurity Engine, a CAST product for AI-generated full-stack code.

CAST stands for Continuous-on-Authoring Security Testing: security control while code is being written, not only after it already exists.

## Product message

- Defines Cencurity Engine as the product: a streaming security engine for AI-generated code
- Controls AI-generated code in the stream before it reaches the developer
- Applies `allow`, `redact`, or `block` inline
- Covers full-stack generated output with a tiered architecture
- Preserves framework-aware finding metadata for explainable enforcement

## Highlights

- OpenAI-compatible inline proxy for streaming `/v1/chat/completions`
- Native Anthropic Messages and Gemini streaming support
- Engine-centered architecture: application / agent / optional thin client → Cencurity Engine → LLM
- Sliding-buffer and accumulated code-unit analysis
- Concise operator-friendly request logs for `allow`, `redact`, and `block`
- Tiered CAST profile structure:
  - Deep: Express, FastAPI, Next.js, LangGraph
  - Medium: React, Django, Flask, LangChain
  - Universal: JSON, YAML, config-like payloads, secrets, dangerous command strings
  - Light: Vue, Tailwind, Pandas, NumPy, TensorFlow, PyTorch
- Framework-aware findings with `language`, `framework`, `rule_id`, `severity`, `confidence`, `action`, and `evidence`
- Built-in actions: `allow`, `redact`, `block`
- CLI commands: `serve`, `doctor`, `version`, `shadowtest`

## Representative coverage

- Express auth/session misuse → block
- FastAPI JWT/CORS misuse → block
- React dangerous HTML → block or policy-tuned redact
- Next.js route/server-action misuse → block
- LangChain unsafe tool usage → block
- LangGraph state/tool/command misuse → block
- JSON/YAML dangerous config → detect, redact, or block

## Release verification

- `go run ./cmd/cast version`
- `go run ./cmd/cast doctor`
- `go test ./...`
- `go build ./...`

## Recommended tag

- `v0.1.0`

## License

- Apache License 2.0

## Positioning

Cencurity Engine is not a replacement for SAST.

- SAST scans code after it exists
- Cencurity Engine controls generation while code is being authored
- The product is best described as CAST for AI-generated full-stack code
