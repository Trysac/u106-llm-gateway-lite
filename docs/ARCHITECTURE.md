# Architecture

`trysac-llm-gateway-lite` provides a WSGI application designed for routing, guarding, and metering chat completion requests to upstream LLM adapters.

```
[HTTP Client]
      |
      v (POST /v1/chat/completions)
[WSGI Gateway]
      |--> 1. Path & Method check (404/405)
      |--> 2. Bearer Token Authentication (401)
      |--> 3. Body Size Validation (413)
      |--> 4. JSON Payload Parsing (400)
      |--> 5. Schema Validation (400)
      |--> 6. Key Model Allowlist Check (403)
      |--> 7. Longest-Prefix Provider Route Lookup (404)
      |--> 8. Sliding-Window Rate Limit (429)
      |--> 9. Monthly Token Quota (429)
      |--> 10. Provider Port Dispatch (502 on exception)
      |--> 11. Telemetry Event & 200 OK Response
```

## KeyStore

- Virtual keys are generated with 256-bit randomness (`secrets.token_urlsafe(32)` prefixed with `vk_`).
- The plaintext is never stored or written to disk. The store retains only the SHA-256 digest.
- Verification tests presented keys against stored digests using `hmac.compare_digest` to prevent timing attacks.
- Persistence is implemented atomically via temporary file writes and atomic filesystem replacement (`os.replace`).

## Provider Port & Adapters

The `ProviderPort` protocol defines a single method:

```python
def complete(self, req: ChatRequest) -> ChatResponse: ...
```

Real provider integrations (OpenAI, Anthropic, Gemini) can be implemented via `urllib.request` or `http.client` without adding external dependencies. Refer to [docs/ADAPTERS.md](ADAPTERS.md) for reference implementations.
