# Project Record

## Objective

Minimal WSGI LLM gateway: OpenAI-compatible chat endpoint over injected providers, hashed virtual keys, per-key model lists, rate and monthly token caps, content-free audit events.

## Scope

- Public API documented, typed, and tested.
- WSGI-compliant chat completion gateway.
- In-process rate limiting (sliding window) and monthly token quotas.
- Hashed key store persistence.

## Out-of-Scope

- TLS termination (use a reverse proxy).
- Distributed limits across multi-process or multi-host deployments.
- Denial of service attacks beyond the body byte cap.
- Prompt content policy / safety filtering.
- Server-sent events / streaming responses.
- Persistence of usage counters.
- Admin HTTP API.

## Factory run u106 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4865 | 17426 | 0 | 0 | 0.0345 |
| fix-1 | gemini-3.8-flash | no | 23685 | 473 | 0 | 45408 | 0.0229 |
| fix-2 | gemini-3.8-flash | no | 50992 | 547 | 0 | 278744 | 0.0612 |
| audit | gemini-3.1-flash-lite | no | 34634 | 222 | 0 | 32547 | 0.0098 |
| docs | gemini-3.1-flash-lite | no | 136349 | 1388 | 0 | 0 | 0.0362 |

Total: $0.1646. Prices: Anthropic list prices.
