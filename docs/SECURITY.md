# Security & Threat Model

## Defended

- **Plaintext Keys Never Stored or Logged**: Virtual keys are 256-bit random tokens stored only as SHA-256 digests. Plaintext keys are never persisted.
- **Constant-Time Digest Comparison**: Uses `hmac.compare_digest` for token authentication to prevent timing side channels.
- **Per-Key Model Allowlists**: Enforces model-specific access per key before any provider invocation.
- **Content-Length Validation**: Payload size is capped (`max_body_bytes`) and validated before JSON parsing.
- **Masked Upstream Exceptions**: Provider exceptions and upstream secrets are never echoed in HTTP error bodies; returns `502 Bad Gateway`.
- **Default Bind Address**: Default gateway bind is `127.0.0.1`.

## Not Defended

- **TLS Termination**: Must be run behind a reverse proxy (NGINX, Caddy).
- **Distributed Limits**: Limits are in-memory and per-process; multi-host deployments are unsupported.
- **DoI/DoS**: Volumetric attack protection beyond the body byte cap is not implemented.
- **Prompt Content Policy**: No safety or PII filtering.
- **Streaming**: Server-sent events / streaming responses are unsupported.
