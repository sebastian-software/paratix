# Review Areas

1. Security (critical), including:
   - SSH connection management (ssh.ts, sshHelpers.ts) - private key handling, sudo password caching, reconnect logic
   - Remote command execution (command.ts) - shell injection risks, secret masking
   - Download module (download.ts) - header injection, checksum verification, URL escaping
   - SFTP/file operations (sftp.ts, file.ts) - temporary file handling, atomic writes, permissions
   - Template system (template.ts) - injection through placeholder values
   - Environment/secrets (environment.ts) - .env parsing, secret leakage in logs/error messages
   - TOTP implementation (totp.ts) - correctness of the RFC 6238/4226 implementation
2. Robustness and error handling, including:
   - Idempotency guarantees - module behavior during network interruptions, timeouts, partial states
   - Reconnect logic - exponential backoff, behavior after SSH port changes
   - Graceful shutdown - SIGINT/SIGTERM handling, active SFTP transfers
   - Error recovery - what happens when errors occur during playbook execution?
3. Test coverage and quality, including:
   - Mocking vs. integration - tests use mocked SSH connections; are there also E2E tests against real servers?
   - Edge cases - empty inputs, Unicode, very large files, race conditions
   - Module test coverage - are all 17+ modules sufficiently tested?
4. Code quality and architecture, including:
   - TypeScript strict mode - use of `any`, type assertions, unchecked casts
   - Dependency review - ssh2 as a critical dependency (currency, known CVEs)
   - Module consistency (uniform error handling, logging, return values)
   - Runner logic (runner.ts, runnerHelpers.ts) - orchestration, signal system
5. Operations and developer experience, including:
   - CLI validation (cli.ts) - error messages, input sanitization
   - Dry-run mode - completeness and reliability
   - Logging and observability - sufficient for debugging in production?
   - create-paratix scaffolding - does it produce secure defaults?
