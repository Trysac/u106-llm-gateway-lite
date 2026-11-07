# llm-gateway-lite

[![CI](https://github.com/Trysac/u106-llm-gateway-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u106-llm-gateway-lite/actions/workflows/ci.yml)

Minimal WSGI LLM gateway: OpenAI-compatible chat endpoint over injected providers, hashed virtual keys, per-key model lists, rate and monthly token caps, content-free audit events.

## Problem & Solution

Teams that share one provider account hand the real API key to every script and service, then cannot cap spend per consumer, revoke one user or see who used which model. Full gateways are heavy services with databases. This library is a small WSGI app that issues virtual keys, enforces per-key limits in process and routes requests to injected provider adapters.

## Installation

```bash
pip install llm-gateway-lite
```

## Usage Example

```python
from llm_gateway_lite import Gateway, KeyStore, FakeProvider

keys = KeyStore()
raw_key, meta = keys.issue("team-alpha", models=["mock-gpt"], rpm=60, monthly_tokens=10_000)
gateway = Gateway(keys=keys, routes={"mock-": FakeProvider()})
# gateway is ready to serve WSGI requests at /v1/chat/completions
```

## API Summary

- `KeyStore`: Manages virtual API keys. Stores keys as SHA-256 digests; plaintext tokens (`vk_` + random) are returned only upon `issue()`.
- `Gateway`: WSGI-compliant callable. Routes `POST /v1/chat/completions` requests to `ProviderPort` implementations.
- `ProviderPort`: Interface for upstream providers. Implement `complete(req: ChatRequest) -> ChatResponse`.
- Errors: `GatewayError` raised for misconfiguration (`rpm < 1`, `monthly_tokens < 1`, empty routes). Standard HTTP errors returned for auth/limits.

## Why not LiteLLM proxy?

LiteLLM proxy is a heavy-duty infrastructure tool with external database dependencies and large dependency trees. `llm-gateway-lite` is a small library (a few hundred lines of code) with no runtime dependencies (stdlib only: `wsgiref`, `hashlib`, `hmac`, `secrets`, `json`) designed for auditability and embeddability.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and implementation limits.
