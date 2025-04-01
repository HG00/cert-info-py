# cert-info-py

[![PyPI version](https://img.shields.io/pypi/v/cert-info-py)](https://pypi.org/project/cert-info-py/)

🔐 Cross-platform CLI tool to fetch and inspect TLS certificates.

## Features
- Shows certificate subject, issuer, validity, and expiry
- Displays SAN (Subject Alternative Names)
- JSON output option
- Fully cross-platform (Linux, Mac, Windows)

## Installation

Quick install (with pipx):
```bash
pipx install cert-info-py
```

Or via pip:
```bash
pip install cert-info-py
```

## Usage
```bash
cert-info <hostname> [port] [--json]
```

## License
MIT