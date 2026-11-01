# Review Areas

1. Security (critical), including:
   - SSH connection management (ssh.ts, sshHelpers.ts, transportNative.ts) - private key copies and zeroization, sudo password caching, reconnect logic, native error codes
   - Authentication validation (serverDefinitionValidation.ts) - reject privateKey with passwordFallback or agentForward; forwarding requires a usable agent and must never fall back to a password prompt
   - Remote command execution (command.ts) - shell injection risks, secret masking
   - Download module (download.ts) - header injection, checksum verification, URL escaping
   - SFTP/file operations (sftp.ts, file.ts) - temporary file handling, atomic writes, permissions
   - Template system (template.ts) - injection through placeholder values
   - Environment/secrets (environment.ts) - .env parsing, secret leakage in logs/error messages
   - TOTP implementation (totp.ts) - correctness of the RFC 6238/4226 implementation
2. Robustness and error handling, including:
   - Idempotency guarantees - module behavior during network interruptions, timeouts, partial states
   - Reconnect logic - exponential backoff, behavior after SSH port changes, immediate stop on ENCRYPTED_KEY/UNSUPPORTED_KEY, DISCONNECTED detection for reboot/restart
   - Graceful shutdown - SIGINT/SIGTERM handling, active SFTP transfers
   - Error recovery - what happens when errors occur during playbook execution?
3. Test coverage and quality, including:
   - Mocking vs. integration - tests use mocked SSH connections; are there also E2E tests against real servers?
   - Edge cases - empty inputs, Unicode, very large files, race conditions
   - Module test coverage - are all 17+ modules sufficiently tested?
4. Code quality and architecture, including:
   - TypeScript strict mode - use of `any`, type assertions, unchecked casts
   - Dependency review - @paratix/ssh-native, russh, russh-sftp, and native platform packages (currency, known CVEs); ssh2 is development-only
   - Module consistency (uniform error handling, logging, return values)
   - Runner logic (runner.ts, runnerHelpers.ts) - orchestration, signal system
5. Operations and developer experience, including:
   - CLI validation (cli.ts) - error messages, input sanitization
   - Dry-run mode - completeness and reliability
   - Logging and observability - sufficient for debugging in production?
   - create-paratix scaffolding - secure defaults, native scan offered only with a loadable binding, verified fingerprint or placeholder recovery
   - Native loader (nativeBinding.ts) - supported Linux/macOS targets, glibc/macOS minimum versions, optional dependency failures, check before secret resolution, binary-free imports/help/version
