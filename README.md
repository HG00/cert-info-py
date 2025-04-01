# cert-info (Python)

🔐 Simple cross-platform CLI tool to fetch and inspect TLS certificates.

## Features
- Shows certificate subject, issuer, validity, and expiry
- Displays SAN (Subject Alternative Names)
- JSON output option
- Fully cross-platform (Linux, Mac, Windows)

## Installation

Quick install (with pipx):
```bash
pipx install git+https://github.com/your-username/cert-info-python.git
```

## Usage
```bash
cert-info <hostname> [port] [--json]
```

## License
MIT