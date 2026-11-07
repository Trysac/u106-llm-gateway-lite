"""Comprehensive tests for llm_gateway_lite exercising all acceptance criteria and security defenses."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from llm_gateway_lite import (
    ChatRequest,
    ChatResponse,
    FakeProvider,
    Gateway,
    GatewayError,
    KeyStore,
    default_token,
)


def _make_wsgi_env(
    method: str = "POST",
    path: str = "/v1/chat/completions",
    auth: str | None = None,
    body: str | bytes = "",
    content_length: int | None = None,
) -> dict[str, Any]:
    raw_bytes = body.encode("utf-8") if isinstance(body, str) else body
    if content_length is None:
        content_length = len(raw_bytes)
    env: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(content_length),
        "wsgi.input": io.BytesIO(raw_bytes),
    }
    if auth is not None:
        env["HTTP_AUTHORIZATION"] = auth
    return env


def _run_app(app: Gateway, env: dict[str, Any]) -> tuple[str, list[tuple[str, str]], bytes]:
    recorded_status = ""
    recorded_headers: list[tuple[str, str]] = []

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        nonlocal recorded_status, recorded_headers
        recorded_status = status
        recorded_headers = headers

    body_chunks = list(app(env, start_response))
    return recorded_status, recorded_headers, b"".join(body_chunks)


class FakeClock:
    def __init__(self, initial: float) -> None:
        self.current = initial

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def test_acceptance_1_post_chat_completions_fake_provider() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-a", models=["fake-1"], rpm=100, monthly_tokens=10_000)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()})

    req_body = json.dumps(
        {
            "model": "fake-1",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16,
        }
    )
    env = _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body)
    status, _headers, body = _run_app(gw, env)

    assert status.startswith("200")
    data = json.loads(body.decode("utf-8"))
    assert data["object"] == "chat.completion"
    assert data["choices"][0]["message"]["content"] == "echo: hi"
    assert data["usage"]["prompt_tokens"] == 1
    assert data["usage"]["completion_tokens"] == 2
    assert data["usage"]["total_tokens"] == 3


def test_acceptance_2_auth_failures() -> None:
    ks = KeyStore()
    raw_key, vkey = ks.issue("team-b", models=["fake-1"], rpm=60, monthly_tokens=10_000)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()})
    req_body = json.dumps(
        {"model": "fake-1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
    )

    # Missing Authorization header
    env_no_auth = _make_wsgi_env(auth=None, body=req_body)
    status, headers, body = _run_app(gw, env_no_auth)
    assert status.startswith("401")
    assert any(h == ("WWW-Authenticate", "Bearer") for h in headers)
    data = json.loads(body.decode("utf-8"))
    assert data["error"]["code"] == "missing_key"

    # Malformed Authorization header
    env_bad_auth = _make_wsgi_env(auth="Basic 12345", body=req_body)
    status, _, body = _run_app(gw, env_bad_auth)
    assert status.startswith("401")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "missing_key"

    # Unknown key
    env_unknown = _make_wsgi_env(auth="Bearer vk_unknown1234567890", body=req_body)
    status, _, body = _run_app(gw, env_unknown)
    assert status.startswith("401")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_key"

    # Revoked key
    ks.revoke(vkey.key_id)
    env_revoked = _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body)
    status, _, body = _run_app(gw, env_revoked)
    assert status.startswith("401")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_key"


def test_acceptance_3_model_not_allowed_and_unknown_model() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-c", models=["fake-1"], rpm=60, monthly_tokens=10_000)
    provider_called = False

    def custom_complete(req: ChatRequest) -> ChatResponse:
        nonlocal provider_called
        provider_called = True
        return ChatResponse(content="done", prompt_tokens=1, completion_tokens=1)

    gw = Gateway(keys=ks, routes={"fake-": FakeProvider(custom_complete)})

    # Model not in key's allowlist (fake-2)
    env_not_allowed = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "fake-2", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env_not_allowed)
    assert status.startswith("403")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "model_not_allowed"
    assert not provider_called

    # Key with model allowed, but no route prefix exists
    raw_key_2, _ = ks.issue("team-d", models=["other-1"], rpm=60, monthly_tokens=10_000)
    env_unknown_model = _make_wsgi_env(
        auth=f"Bearer {raw_key_2}",
        body=json.dumps(
            {"model": "other-1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env_unknown_model)
    assert status.startswith("404")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "unknown_model"
    assert not provider_called


def test_acceptance_4_rate_limiting_sliding_window() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-rate", models=["fake-1"], rpm=2, monthly_tokens=10_000)
    clock = FakeClock(1000.0)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()}, clock=clock)

    req_body = json.dumps(
        {"model": "fake-1", "messages": [{"role": "user", "content": "test"}], "max_tokens": 10}
    )

    # Request 1: 200 at 1000.0
    s1, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s1.startswith("200")

    # Request 2: 200 at 1000.0
    s2, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s2.startswith("200")

    # Request 3: 429 at 1000.0 with Retry-After: '60'
    s3, headers, body = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s3.startswith("429")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "rate_limited"
    retry_headers = [v for k, v in headers if k.lower() == "retry-after"]
    assert retry_headers == ["60"]

    # Advance clock to 1060.0 (oldest request expired)
    clock.advance(60.0)
    s4, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s4.startswith("200")


def test_acceptance_5_monthly_quota_and_reset() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-quota", models=["fake-1"], rpm=100, monthly_tokens=5)
    dt_nov = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    clock = FakeClock(dt_nov.timestamp())
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()}, clock=clock)

    req_body = json.dumps(
        {"model": "fake-1", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 10}
    )

    # Call 1: consumes 3 tokens (prompt 1 + completion 2). Current used: 3. Allowed.
    s1, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s1.startswith("200")

    # Call 2: check runs before call (used 3 < monthly 5). Consumes 3 tokens. Current used: 6. Allowed.
    s2, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s2.startswith("200")

    # Call 3: check runs before call (used 6 >= monthly 5). Quota exceeded.
    s3, _, body3 = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s3.startswith("429")
    assert json.loads(body3.decode("utf-8"))["error"]["code"] == "quota_exceeded"

    # Move clock to 2026-12-01T00:00:00Z -> quota resets for new month
    dt_dec = datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
    clock.current = dt_dec.timestamp()
    s4, _, _ = _run_app(gw, _make_wsgi_env(auth=f"Bearer {raw_key}", body=req_body))
    assert s4.startswith("200")


def test_acceptance_6_body_limits_and_validation() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-val", models=["fake-1"], rpm=100, monthly_tokens=1000)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()})

    # Body of 1_048_577 bytes returns 413 code 'body_too_large'
    large_body = b"x" * 1_048_577
    env_large = _make_wsgi_env(auth=f"Bearer {raw_key}", body=large_body)
    status, _, body = _run_app(gw, env_large)
    assert status.startswith("413")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "body_too_large"

    # Content length header exceeding limit directly
    env_large_cl = _make_wsgi_env(auth=f"Bearer {raw_key}", body=b"abc", content_length=1_048_577)
    status_cl, _, body_cl = _run_app(gw, env_large_cl)
    assert status_cl.startswith("413")
    assert json.loads(body_cl.decode("utf-8"))["error"]["code"] == "body_too_large"

    # Invalid JSON returns 400 invalid_json
    env_inv_json = _make_wsgi_env(auth=f"Bearer {raw_key}", body="{not_json: 123")
    status, _, body = _run_app(gw, env_inv_json)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_json"

    # Body without messages returns 400 invalid_request
    env_no_msg = _make_wsgi_env(
        auth=f"Bearer {raw_key}", body=json.dumps({"model": "fake-1", "max_tokens": 10})
    )
    status, _, body = _run_app(gw, env_no_msg)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"

    # Messages empty list
    env_empty_msgs = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps({"model": "fake-1", "messages": [], "max_tokens": 10}),
    )
    status, _, body = _run_app(gw, env_empty_msgs)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"

    # Non-dict top level
    env_non_dict = _make_wsgi_env(auth=f"Bearer {raw_key}", body=json.dumps([1, 2, 3]))
    status, _, body = _run_app(gw, env_non_dict)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"

    # Invalid model
    env_bad_model = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env_bad_model)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"

    # Invalid role
    env_bad_role = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "fake-1", "messages": [{"role": "tool", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env_bad_role)
    assert status.startswith("400")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"

    # Invalid max_tokens
    for bad_tokens in (0, 100_001, "10", True):
        env_bad_tokens = _make_wsgi_env(
            auth=f"Bearer {raw_key}",
            body=json.dumps(
                {
                    "model": "fake-1",
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": bad_tokens,
                }
            ),
        )
        status, _, body = _run_app(gw, env_bad_tokens)
        assert status.startswith("400")
        assert json.loads(body.decode("utf-8"))["error"]["code"] == "invalid_request"


def test_acceptance_7_upstream_error_masking() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("team-err", models=["fake-1"], rpm=100, monthly_tokens=1000)

    def failing_provider(req: ChatRequest) -> ChatResponse:
        raise RuntimeError("upstream detail sk-SENTINEL")

    gw = Gateway(keys=ks, routes={"fake-": FakeProvider(failing_provider)})
    env = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "fake-1", "messages": [{"role": "user", "content": "test"}], "max_tokens": 10}
        ),
    )
    status, _, body_bytes = _run_app(gw, env)
    assert status.startswith("502")
    body_str = body_bytes.decode("utf-8")
    assert json.loads(body_str)["error"]["code"] == "upstream_error"
    assert "sk-SENTINEL" not in body_str


def test_acceptance_8_on_event_payload() -> None:
    ks = KeyStore()
    raw_key, vkey = ks.issue("team-audit", models=["fake-1"], rpm=100, monthly_tokens=1000)
    events: list[dict[str, Any]] = []

    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()}, on_event=events.append)
    env = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {
                "model": "fake-1",
                "messages": [{"role": "user", "content": "SENTINEL-PROMPT"}],
                "max_tokens": 10,
            }
        ),
    )
    status, _, _ = _run_app(gw, env)
    assert status.startswith("200")
    assert len(events) == 1
    event = events[0]
    assert set(event.keys()) == {
        "key_id",
        "model",
        "status",
        "prompt_tokens",
        "completion_tokens",
        "latency_ms",
    }
    assert event["key_id"] == vkey.key_id
    assert event["model"] == "fake-1"
    assert event["status"] == 200
    assert event["prompt_tokens"] == 1
    assert event["completion_tokens"] == 2
    assert isinstance(event["latency_ms"], int)

    # Ensure plaintext key and prompt content are nowhere in event representation
    event_json = json.dumps(event)
    assert raw_key not in event_json
    assert "SENTINEL-PROMPT" not in event_json


def test_acceptance_9_keystore_save_load_and_max_keys(tmp_path: Any) -> None:
    ks = KeyStore(max_keys=2)
    plaintext1, vk1 = ks.issue("app1", models=["m1"], rpm=10, monthly_tokens=100)
    plaintext2, vk2 = ks.issue("app2", models=["m2"], rpm=20, monthly_tokens=200)

    # Issuing beyond max_keys raises GatewayError with code 'too_many_keys'
    with pytest.raises(GatewayError) as exc_info:
        ks.issue("app3", models=["m3"], rpm=30, monthly_tokens=300)
    assert exc_info.value.code == "too_many_keys"

    save_file = tmp_path / "keys.json"
    ks.save(save_file)

    # Check saved file content: must NOT contain plaintext keys
    saved_content = save_file.read_text(encoding="utf-8")
    assert plaintext1 not in saved_content
    assert plaintext2 not in saved_content
    assert vk1.key_id in saved_content
    assert vk2.key_id in saved_content

    # Load and test authentication
    loaded_ks = KeyStore.load(save_file, max_keys=2)
    auth1 = loaded_ks.authenticate(plaintext1)
    assert auth1 is not None
    assert auth1.key_id == vk1.key_id
    assert auth1.models == ("m1",)

    # Loading into store that exceeds max_keys raises
    with pytest.raises(GatewayError) as load_exc:
        KeyStore.load(save_file, max_keys=1)
    assert load_exc.value.code == "too_many_keys"


def test_acceptance_10_method_and_path_routing() -> None:
    ks = KeyStore()
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()})

    # GET /v1/chat/completions -> 405 with Allow: POST
    env_get = _make_wsgi_env(method="GET", path="/v1/chat/completions")
    status, headers, body = _run_app(gw, env_get)
    assert status.startswith("405")
    assert any(h == ("Allow", "POST") for h in headers)
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "method_not_allowed"

    # Other paths -> 404
    for p in ["/", "/v1/models", "/chat/completions"]:
        env_404 = _make_wsgi_env(method="POST", path=p)
        status404, _, body404 = _run_app(gw, env_404)
        assert status404.startswith("404")
        assert json.loads(body404.decode("utf-8"))["error"]["code"] == "not_found"


# --- Additional edge case & threat model tests ---


def test_defended_item_1_plaintext_never_logged_or_stored() -> None:
    ks = KeyStore()
    plaintext, vk = ks.issue("sec-1", models=["fake-1"], rpm=10, monthly_tokens=100)
    # Plaintext token starts with vk_
    assert plaintext.startswith("vk_")
    # Key ID starts with key_ and is 16 chars long (key_ + 12 hex)
    assert vk.key_id.startswith("key_")
    assert len(vk.key_id) == 16
    # Stored internal dicts do not index by plaintext
    assert plaintext not in ks._keys_by_digest
    assert plaintext not in ks._digests_by_key_id


def test_defended_item_2_constant_time_comparison() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("sec-2", models=["fake-1"], rpm=10, monthly_tokens=100)
    assert ks.authenticate(raw_key) is not None
    assert ks.authenticate(raw_key + "wrong") is None
    assert ks.authenticate("") is None


def test_defended_item_3_model_allowlist() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("sec-3", models=["gpt-4o-mini"], rpm=10, monthly_tokens=100)
    gw = Gateway(keys=ks, routes={"gpt-": FakeProvider()})

    # Request gpt-4o (not in allowlist)
    env = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env)
    assert status.startswith("403")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "model_not_allowed"


def test_defended_item_4_body_size_cap_before_parsing() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("sec-4", models=["fake-1"], rpm=10, monthly_tokens=100)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()}, max_body_bytes=50)
    env = _make_wsgi_env(auth=f"Bearer {raw_key}", body="{" + " " * 60 + "}")
    status, _, body = _run_app(gw, env)
    assert status.startswith("413")
    assert json.loads(body.decode("utf-8"))["error"]["code"] == "body_too_large"


def test_defended_item_5_provider_exceptions_masked() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue("sec-5", models=["fake-1"], rpm=10, monthly_tokens=100)

    def leaking_provider(req: ChatRequest) -> ChatResponse:
        raise ValueError("Connection error to https://api.openai.com/v1 with secret bearer token")

    gw = Gateway(keys=ks, routes={"fake-": FakeProvider(leaking_provider)})
    env = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "fake-1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env)
    assert status.startswith("502")
    res_json = json.loads(body.decode("utf-8"))
    assert res_json == {"error": {"code": "upstream_error", "message": "Provider call failed"}}


def test_keystore_invalid_config_and_revoke_unknown() -> None:
    with pytest.raises(GatewayError) as exc1:
        KeyStore(max_keys=0)
    assert exc1.value.code == "invalid_config"

    ks = KeyStore()
    with pytest.raises(GatewayError) as exc2:
        ks.issue("name", models=["m"], rpm=0, monthly_tokens=10)
    assert exc2.value.code == "invalid_config"

    with pytest.raises(GatewayError) as exc3:
        ks.issue("name", models=["m"], rpm=10, monthly_tokens=0)
    assert exc3.value.code == "invalid_config"

    with pytest.raises(GatewayError) as exc4:
        ks.revoke("non-existent-key-id")
    assert exc4.value.code == "unknown_key"


def test_gateway_empty_routes_raises() -> None:
    ks = KeyStore()
    with pytest.raises(GatewayError) as exc:
        Gateway(keys=ks, routes={})
    assert exc.value.code == "invalid_config"


def test_longest_prefix_routing() -> None:
    ks = KeyStore()
    raw_key, _ = ks.issue(
        "route-test", models=["model-abc-pro", "model-abc"], rpm=10, monthly_tokens=100
    )

    p_short = FakeProvider(
        lambda req: ChatResponse(content="from-short", prompt_tokens=1, completion_tokens=1)
    )
    p_long = FakeProvider(
        lambda req: ChatResponse(content="from-long", prompt_tokens=1, completion_tokens=1)
    )

    routes = {
        "model-": p_short,
        "model-abc-": p_long,
    }
    gw = Gateway(keys=ks, routes=routes)

    # Matches model-abc- (longest prefix)
    env1 = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {
                "model": "model-abc-pro",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 10,
            }
        ),
    )
    _, _, body1 = _run_app(gw, env1)
    assert json.loads(body1.decode("utf-8"))["choices"][0]["message"]["content"] == "from-long"

    # Matches model- (only shorter prefix applies)
    env2 = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {
                "model": "model-abc",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 10,
            }
        ),
    )
    _, _, body2 = _run_app(gw, env2)
    assert json.loads(body2.decode("utf-8"))["choices"][0]["message"]["content"] == "from-short"


def test_on_event_handles_callback_exception() -> None:
    def broken_callback(event: dict[str, Any]) -> None:
        raise RuntimeError("telemetry failure")

    ks = KeyStore()
    raw_key, _ = ks.issue("err-event", models=["fake-1"], rpm=10, monthly_tokens=100)
    gw = Gateway(keys=ks, routes={"fake-": FakeProvider()}, on_event=broken_callback)

    env = _make_wsgi_env(
        auth=f"Bearer {raw_key}",
        body=json.dumps(
            {"model": "fake-1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}
        ),
    )
    status, _, body = _run_app(gw, env)
    assert status.startswith("200")
    assert json.loads(body.decode("utf-8"))["choices"][0]["message"]["content"] == "echo: hi"


def test_default_token_generation() -> None:
    tok = default_token()
    assert tok.startswith("vk_")
    assert len(tok) > 40
