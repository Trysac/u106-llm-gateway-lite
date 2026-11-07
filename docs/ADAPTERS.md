# Provider Adapters

`trysac-llm-gateway-lite` connects to LLM backends via the `ProviderPort` protocol:

```python
class ProviderPort(Protocol):
    def complete(self, req: ChatRequest) -> ChatResponse: ...
```

## Writing a Real HTTP Provider Adapter

Here is an example adapter for an OpenAI-compatible endpoint using the standard library's `urllib.request`:

```python
import json
import urllib.request
from llm_gateway_lite import ChatRequest, ChatResponse


class OpenAIPromptAdapter:
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1") -> None:
        self._api_key = api_key
        self._url = f"{base_url}/chat/completions"

    def complete(self, req: ChatRequest) -> ChatResponse:
        payload = json.dumps(
            {
                "model": req.model,
                "messages": [{"role": m.role, "content": m.content} for m in req.messages],
                "max_tokens": req.max_tokens,
            }
        ).encode("utf-8")

        http_req = urllib.request.Request(
            self._url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(http_req, timeout=30.0) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            usage = body.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
            finish_reason = body["choices"][0].get("finish_reason", "stop")
            return ChatResponse(
                content=content,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                finish_reason=finish_reason,
            )
```
