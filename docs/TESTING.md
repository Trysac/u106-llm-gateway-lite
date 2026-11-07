# Testing

## Policy

- Tests exercise the public API and assert observable effects (return values, exceptions).
- Deterministic tests: no network, no actual wall clock dependencies.

## Tests

`tests/test_llm_gateway_lite.py` covers the full suite:

- **Acceptance Tests**: POST requests to `/v1/chat/completions` with the `FakeProvider`.
- **Auth Failures**: Missing `Authorization`, unknown keys, revoked keys.
- **Routing & Models**: Model allowlist and prefix-based routing.
- **Limits**: Sliding 60s rate limit (sliding window validation) and monthly quota reset.
- **Body Size**: Handling of payloads exceeding `max_body_bytes`.
- **Security**: Ensures plaintext keys or sensitive prompts are not in audit events or responses.
