# pseudonymizer

[![PyPI version](https://img.shields.io/pypi/v/trysac-pseudonymizer)](https://pypi.org/project/trysac-pseudonymizer/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-pseudonymizer)](LICENSE)
[![CI](https://github.com/Trysac/u288-pseudonymizer/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u288-pseudonymizer/actions/workflows/ci.yml)

Keyed pseudonymization with HMAC-SHA256 tokens per domain, key ids for rotation and re-identification through a bounded vault port, with a stated threat model

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-pseudonymizer
# or
uv add trysac-pseudonymizer
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import pseudonymizer

# normalize() trims surrounding whitespace and lower-cases the text.
print(pseudonymizer.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    pseudonymizer.normalize("   ")
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
