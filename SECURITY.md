# Security

## Reporting a vulnerability

Use [GitHub Private Vulnerability Reporting](https://github.com/sebastian-software/paratix/security/advisories/new) to report
security issues. This keeps the disclosure private until a fix is ready.

If GitHub PVR is unavailable, email <s.fastner@sebastian-software.de> with the subject line `[SECURITY] Paratix`.

Please include: affected version, steps to reproduce, and potential impact. We aim to acknowledge reports
within 72 hours and publish a fix or advisory as soon as one is available.

## Supported versions

Paratix is pre-1.0 software. Only the latest `0.12.x` release receives security fixes. Older minor
versions are not supported.

## Security posture

Paratix runs playbooks over SSH and handles sensitive material on your behalf:

- **Strict host-key checking on by default**: Paratix refuses to connect to a host whose key has changed,
  protecting against MITM attacks during automated runs.
- **Secret redaction**: values passed via `--env` or `--env-file` are redacted from the CLI output.

Keep private keys and secret values out of version control and use short-lived credentials where possible.
