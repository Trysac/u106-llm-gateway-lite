"""Minimal WSGI LLM gateway with virtual keys, rate limiting, and provider routing.

Threat model defended:
- Plaintext keys never stored or logged (keys are high-entropy 256-bit random tokens
  stored only as SHA-256 digests).
- Constant-time digest comparison using hmac.compare_digest.
- Per-key model allowlist enforcement.
- Content-Length validation and body size capped prior to parsing.
- Upstream provider exceptions and secrets never echoed in HTTP error bodies.
- Default bind address set to 127.0.0.1.

Threat model not defended:
- TLS termination (run behind a reverse proxy like NGINX or Caddy).
- Distributed limits across multi-process or multi-host deployments.
- Denial of service attacks beyond the body byte cap.
- Prompt content policy / safety filtering.
- Server-sent events / streaming responses.
"""

from __future__ import annotations

import json
import logging
import math
import os
import secrets
import tempfile
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from typing import Any, Literal, Protocol, runtime_checkable
from wsgiref.simple_server import make_server

__all__ = [
    "ChatRequest",
    "ChatResponse",
    "FakeProvider",
    "Gateway",
    "GatewayError",
    "GatewayErrorCode",
    "KeyStore",
    "Message",
    "ProviderPort",
    "VirtualKey",
    "__version__",
    "default_token",
    "serve",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

GatewayErrorCode = Literal["too_many_keys", "invalid_config", "unknown_key"]


class GatewayError(Exception):
    """Base exception raised for library misuse."""

    def __init__(self, code: GatewayErrorCode, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class Message:
    """A single chat message."""

    role: str
    content: str


@dataclass(frozen=True)
class ChatRequest:
    """An inbound chat completion request."""

    model: str
    messages: tuple[Message, ...]
    max_tokens: int


@dataclass(frozen=True)
class ChatResponse:
    """An outbound chat completion response from a provider."""

    content: str
    prompt_tokens: int
    completion_tokens: int
    finish_reason: str = "stop"


@runtime_checkable
class ProviderPort(Protocol):
    """Port interface for upstream model providers."""

    def complete(self, req: ChatRequest) -> ChatResponse:
        """Process a chat completion request."""
        ...


class FakeProvider:
    """Test double provider echoing the last user message."""

    def __init__(self, fn: Callable[[ChatRequest], ChatResponse] | None = None) -> None:
        self._fn = fn

    def complete(self, req: ChatRequest) -> ChatResponse:
        if self._fn is not None:
            return self._fn(req)
        last_user_content = ""
        for msg in reversed(req.messages):
            if msg.role == "user":
                last_user_content = msg.content
                break
        return ChatResponse(
            content=f"echo: {last_user_content}",
            prompt_tokens=1,
            completion_tokens=2,
            finish_reason="stop",
        )


@dataclass(frozen=True)
class VirtualKey:
    """A virtual API key metadata record."""

    key_id: str
    name: str
    models: tuple[str, ...]
    rpm: int
    monthly_tokens: int
    revoked: bool


def default_token() -> str:
    """Generate a high-entropy 256-bit URL-safe token prefixed with 'vk_'."""
    return "vk_" + secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


class KeyStore:
    """Store and manager for virtual API keys."""

    def __init__(
        self,
        *,
        max_keys: int = 10_000,
        token_factory: Callable[[], str] = default_token,
    ) -> None:
        if max_keys < 1:
            raise GatewayError("invalid_config", "max_keys must be >= 1")
        self._max_keys = max_keys
        self._token_factory = token_factory
        self._keys_by_digest: dict[str, VirtualKey] = {}
        self._digests_by_key_id: dict[str, str] = {}

    def issue(
        self,
        name: str,
        *,
        models: Sequence[str],
        rpm: int,
        monthly_tokens: int,
    ) -> tuple[str, VirtualKey]:
        """Issue a new virtual key. Plaintext is returned once."""
        if len(self._keys_by_digest) >= self._max_keys:
            raise GatewayError("too_many_keys", "KeyStore capacity reached")
        if rpm < 1:
            raise GatewayError("invalid_config", "rpm must be >= 1")
        if monthly_tokens < 1:
            raise GatewayError("invalid_config", "monthly_tokens must be >= 1")

        plaintext = self._token_factory()
        digest = _hash_token(plaintext)
        key_id = f"key_{digest[:12]}"
        vkey = VirtualKey(
            key_id=key_id,
            name=name,
            models=tuple(models),
            rpm=rpm,
            monthly_tokens=monthly_tokens,
            revoked=False,
        )
        self._keys_by_digest[digest] = vkey
        self._digests_by_key_id[key_id] = digest
        return plaintext, vkey

    def revoke(self, key_id: str) -> None:
        """Revoke an issued virtual key by key_id."""
        digest = self._digests_by_key_id.get(key_id)
        if digest is None:
            raise GatewayError("unknown_key", f"Key ID '{key_id}' not found")
        existing = self._keys_by_digest[digest]
        updated = VirtualKey(
            key_id=existing.key_id,
            name=existing.name,
            models=existing.models,
            rpm=existing.rpm,
            monthly_tokens=existing.monthly_tokens,
            revoked=True,
        )
        self._keys_by_digest[digest] = updated

    def authenticate(self, plaintext: str) -> VirtualKey | None:
        """Authenticate a plaintext token using constant-time hash comparison."""
        presented_digest = _hash_token(plaintext)
        matched: VirtualKey | None = None
        for digest, vkey in self._keys_by_digest.items():
            if compare_digest(presented_digest, digest):
                matched = vkey
        return matched

    def save(self, path: str | os.PathLike[str]) -> None:
        """Atomically save key records to a JSON file without plaintext secrets."""
        data = [
            {
                "digest": digest,
                "key_id": vk.key_id,
                "name": vk.name,
                "models": list(vk.models),
                "rpm": vk.rpm,
                "monthly_tokens": vk.monthly_tokens,
                "revoked": vk.revoked,
            }
            for digest, vk in self._keys_by_digest.items()
        ]
        dir_name = os.path.dirname(os.path.abspath(path))
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tmp:
            json.dump(data, tmp, indent=2)
            tmp_path = tmp.name
        os.replace(tmp_path, path)

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        *,
        max_keys: int = 10_000,
        token_factory: Callable[[], str] = default_token,
    ) -> KeyStore:
        """Load key records from a previously saved JSON file."""
        store = cls(max_keys=max_keys, token_factory=token_factory)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            if len(store._keys_by_digest) >= store._max_keys:
                raise GatewayError("too_many_keys", "KeyStore capacity reached while loading")
            vk = VirtualKey(
                key_id=item["key_id"],
                name=item["name"],
                models=tuple(item["models"]),
                rpm=int(item["rpm"]),
                monthly_tokens=int(item["monthly_tokens"]),
                revoked=bool(item["revoked"]),
            )
            digest = item["digest"]
            store._keys_by_digest[digest] = vk
            store._digests_by_key_id[vk.key_id] = digest
        return store


class Gateway:
    """WSGI LLM Gateway implementing chat completions with quotas and routing."""

    def __init__(
        self,
        keys: KeyStore,
        routes: Mapping[str, ProviderPort],
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        max_body_bytes: int = 1_048_576,
    ) -> None:
        if not routes:
            raise GatewayError("invalid_config", "routes must not be empty")
        self._keys = keys
        self._routes = dict(routes)
        self._clock = clock
        self._monotonic = monotonic
        self._on_event = on_event
        self._max_body_bytes = max_body_bytes
        self._req_counter = 0

        # In-memory tracking: key_id -> deque of timestamps within last 60s
        self._rpm_windows: dict[str, deque[float]] = {}
        # In-memory tracking: (key_id, YYYY-MM) -> token count
        self._monthly_tokens: dict[tuple[str, str], int] = {}

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterator[bytes]:
        start_mono = self._monotonic()
        status_code = 200
        key_id = ""
        model = ""
        prompt_tokens = 0
        completion_tokens = 0

        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")

        def emit_event(final_status: int) -> None:
            if self._on_event is not None:
                duration_ms = int((self._monotonic() - start_mono) * 1000)
                event = {
                    "key_id": key_id,
                    "model": model,
                    "status": final_status,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "latency_ms": duration_ms,
                }
                try:
                    self._on_event(event)
                except Exception:
                    logger.exception("Error in on_event callback")

        # 1. Method and Path routing
        if path != "/v1/chat/completions":
            status_code = 404
            emit_event(status_code)
            start_response("404 Not Found", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps({"error": {"code": "not_found", "message": "Not Found"}}).encode(
                        "utf-8"
                    )
                ]
            )

        if method != "POST":
            status_code = 405
            emit_event(status_code)
            start_response(
                "405 Method Not Allowed",
                [("Content-Type", "application/json"), ("Allow", "POST")],
            )
            return iter(
                [
                    json.dumps(
                        {"error": {"code": "method_not_allowed", "message": "Method Not Allowed"}}
                    ).encode("utf-8")
                ]
            )

        # 2. Authorization header
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            status_code = 401
            emit_event(status_code)
            start_response(
                "401 Unauthorized",
                [("Content-Type", "application/json"), ("WWW-Authenticate", "Bearer")],
            )
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "missing_key",
                                "message": "Missing or invalid Authorization header",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        token = auth_header[7:].strip()
        vkey = self._keys.authenticate(token)
        if vkey is None or vkey.revoked:
            status_code = 401
            emit_event(status_code)
            start_response(
                "401 Unauthorized",
                [("Content-Type", "application/json"), ("WWW-Authenticate", "Bearer")],
            )
            return iter(
                [
                    json.dumps(
                        {"error": {"code": "invalid_key", "message": "Invalid or revoked API key"}}
                    ).encode("utf-8")
                ]
            )

        key_id = vkey.key_id

        # 3. Content-Length and Body Size
        content_length_header = environ.get("CONTENT_LENGTH", "")
        try:
            content_length = int(content_length_header) if content_length_header else 0
        except ValueError:
            content_length = 0

        if content_length > self._max_body_bytes:
            status_code = 413
            emit_event(status_code)
            start_response("413 Payload Too Large", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "body_too_large",
                                "message": "Request body exceeds allowed limit",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        wsgi_input = environ.get("wsgi.input")
        raw_body = b"" if wsgi_input is None else wsgi_input.read(self._max_body_bytes + 1)

        if len(raw_body) > self._max_body_bytes:
            status_code = 413
            emit_event(status_code)
            start_response("413 Payload Too Large", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "body_too_large",
                                "message": "Request body exceeds allowed limit",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        # 4. JSON parsing
        try:
            body_json = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            status_code = 400
            emit_event(status_code)
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "invalid_json",
                                "message": "Invalid JSON in request body",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        # 5. Request validation shape
        if not isinstance(body_json, dict):
            status_code = 400
            emit_event(status_code)
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "invalid_request",
                                "message": "Request body must be a JSON object",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        req_model = body_json.get("model")
        req_messages = body_json.get("messages")
        req_max_tokens = body_json.get("max_tokens")

        if not isinstance(req_model, str) or not req_model:
            status_code = 400
            emit_event(status_code)
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "invalid_request",
                                "message": "Field 'model' must be a non-empty string",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        model = req_model

        if not isinstance(req_messages, list) or len(req_messages) == 0:
            status_code = 400
            emit_event(status_code)
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "invalid_request",
                                "message": "Field 'messages' must be a non-empty list",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        parsed_messages: list[Message] = []
        for msg in req_messages:
            if not isinstance(msg, dict):
                status_code = 400
                emit_event(status_code)
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return iter(
                    [
                        json.dumps(
                            {
                                "error": {
                                    "code": "invalid_request",
                                    "message": "Each message must be a JSON object",
                                }
                            }
                        ).encode("utf-8")
                    ]
                )
            role = msg.get("role")
            content = msg.get("content")
            if role not in ("system", "user", "assistant") or not isinstance(content, str):
                status_code = 400
                emit_event(status_code)
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return iter(
                    [
                        json.dumps(
                            {
                                "error": {
                                    "code": "invalid_request",
                                    "message": "Invalid message role or content",
                                }
                            }
                        ).encode("utf-8")
                    ]
                )
            parsed_messages.append(Message(role=role, content=content))

        if (
            not isinstance(req_max_tokens, int)
            or isinstance(req_max_tokens, bool)
            or not (1 <= req_max_tokens <= 100_000)
        ):
            status_code = 400
            emit_event(status_code)
            start_response("400 Bad Request", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "invalid_request",
                                "message": (
                                    "Field 'max_tokens' must be an integer between 1 and 100000"
                                ),
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        # 6. Model allowed for key
        if model not in vkey.models:
            status_code = 403
            emit_event(status_code)
            start_response("403 Forbidden", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "model_not_allowed",
                                "message": "Model is not allowed for this key",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        # 7. Route lookup: longest prefix of routes keys
        matched_provider: ProviderPort | None = None
        longest_prefix_len = -1
        for prefix, provider in self._routes.items():
            if model.startswith(prefix) and len(prefix) > longest_prefix_len:
                matched_provider = provider
                longest_prefix_len = len(prefix)

        if matched_provider is None:
            status_code = 404
            emit_event(status_code)
            start_response("404 Not Found", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {
                            "error": {
                                "code": "unknown_model",
                                "message": "No route configured for model",
                            }
                        }
                    ).encode("utf-8")
                ]
            )

        now = self._clock()

        # 8. Rate limit check (sliding 60s window per key)
        timestamps = self._rpm_windows.setdefault(key_id, deque(maxlen=vkey.rpm))
        while timestamps and timestamps[0] <= now - 60.0:
            timestamps.popleft()

        if len(timestamps) >= vkey.rpm:
            status_code = 429
            oldest = timestamps[0]
            retry_after = str(max(1, math.ceil(60.0 - (now - oldest))))
            emit_event(status_code)
            start_response(
                "429 Too Many Requests",
                [("Content-Type", "application/json"), ("Retry-After", retry_after)],
            )
            return iter(
                [
                    json.dumps(
                        {"error": {"code": "rate_limited", "message": "Rate limit exceeded"}}
                    ).encode("utf-8")
                ]
            )

        # 9. Monthly quota check
        utc_dt = datetime.fromtimestamp(now, tz=timezone.utc)
        month_key = f"{utc_dt.year:04d}-{utc_dt.month:02d}"
        used_tokens = self._monthly_tokens.get((key_id, month_key), 0)
        if used_tokens >= vkey.monthly_tokens:
            status_code = 429
            emit_event(status_code)
            start_response("429 Too Many Requests", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {"error": {"code": "quota_exceeded", "message": "Monthly quota exceeded"}}
                    ).encode("utf-8")
                ]
            )

        # 10. Provider call
        chat_req = ChatRequest(
            model=model,
            messages=tuple(parsed_messages),
            max_tokens=req_max_tokens,
        )
        try:
            resp = matched_provider.complete(chat_req)
        except Exception:
            status_code = 502
            emit_event(status_code)
            start_response("502 Bad Gateway", [("Content-Type", "application/json")])
            return iter(
                [
                    json.dumps(
                        {"error": {"code": "upstream_error", "message": "Provider call failed"}}
                    ).encode("utf-8")
                ]
            )

        # Record consumption
        timestamps.append(now)
        total_call_tokens = resp.prompt_tokens + resp.completion_tokens
        self._monthly_tokens[(key_id, month_key)] = used_tokens + total_call_tokens

        self._req_counter += 1
        call_id = f"gw-{self._req_counter}"

        prompt_tokens = resp.prompt_tokens
        completion_tokens = resp.completion_tokens
        status_code = 200
        emit_event(status_code)

        response_dict = {
            "id": call_id,
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": resp.content,
                    },
                    "finish_reason": resp.finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": resp.prompt_tokens,
                "completion_tokens": resp.completion_tokens,
                "total_tokens": total_call_tokens,
            },
        }

        start_response("200 OK", [("Content-Type", "application/json")])
        return iter([json.dumps(response_dict).encode("utf-8")])


def serve(gateway: Gateway, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the gateway with wsgiref simple_server."""
    server = make_server(host, port, gateway)
    server.serve_forever()
