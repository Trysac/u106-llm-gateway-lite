# Use standard-library WSGI architecture with SHA-256 hashed virtual keys and bounded in-memory counters

Status: accepted (generated, pending human review)

## Context

Organizations sharing LLM accounts need spend governance, model allowlisting, and key revocation without introducing heavy dependencies or complex database infrastructures.

## Decision

Implement a pure standard-library WSGI gateway storing 256-bit high-entropy virtual keys as SHA-256 hex digests. Protect authentication using constant-time comparison (hmac.compare_digest), enforce per-key rate limits with sliding 60-second deques, track monthly token quotas per calendar month, and sanitize audit telemetry.

## Consequences

The library remains zero-dependency and auditable within a single compact module. High concurrency multi-worker deployments track counters per worker process; deployments requiring distributed limits or TLS must sit behind a reverse proxy.
