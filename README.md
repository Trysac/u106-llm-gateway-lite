# llm-gateway-lite

[![PyPI version](https://img.shields.io/pypi/v/trysac-llm-gateway-lite)](https://pypi.org/project/trysac-llm-gateway-lite/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-llm-gateway-lite)](LICENSE)
[![CI](https://github.com/Trysac/u106-llm-gateway-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u106-llm-gateway-lite/actions/workflows/ci.yml)

Minimal WSGI LLM gateway: OpenAI-compatible chat endpoint over injected providers, hashed virtual keys, per-key model lists, rate and monthly token caps, content-free audit events

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-llm-gateway-lite
# or
uv add trysac-llm-gateway-lite
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import llm_gateway_lite

# normalize() trims surrounding whitespace and lower-cases the text.
print(llm_gateway_lite.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    llm_gateway_lite.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
