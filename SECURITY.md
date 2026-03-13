# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

Instead, please email: **security@fraction.estate**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Fix timeline:** depends on severity, typically within 30 days

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| < 1.1   | No        |

## Security Practices

This crate follows strict security practices for cryptographic code:

- **Constant-time operations** via `subtle::ConstantTimeEq` for secret comparisons
- **Zeroization** of secret key material via `zeroize::ZeroizeOnDrop`
- **No panics** in library code — all functions return `Result`
- **Debug redaction** — secret keys display `[REDACTED]`
- **no_std compatible** — minimal attack surface
