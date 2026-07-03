# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest  | yes       |

## Reporting a vulnerability

If you discover a security issue in Depfuse, please report it responsibly:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Email the maintainers with a description, reproduction steps, and impact assessment.
3. Allow reasonable time for a fix before public disclosure.

## Scope

In scope:

- Incorrect level/verdict logic that could cause a hold to be missed
- Execution or download of exploit/PoC code contrary to design
- Credential leakage via logs or reports

Out of scope:

- Vulnerabilities in scanned third-party dependencies themselves
- GitHub/OSV upstream data accuracy

## Design guarantees

Depfuse is designed to:

- Never download or execute PoC/exploit code
- Never generate exploit payloads
- Keep verdict logic deterministic (not LLM-driven)
