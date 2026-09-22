# AGENTS.md

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](./llm-guide.md#agent-authoring-guidance) in the complete API reference.

## Integration tests

The `describe("Paratix integration", ...)` block in `test/integration/paratix.integration.test.ts` boots an sshd container through `harness.ts` and exercises the real SSH/SFTP code paths. The suite probes Docker at runtime and skips the block only in local environments without a reachable daemon. The GitHub-hosted `Integration Check` provides Docker and runs an explicit `docker info` preflight before `agent:check:integration`; if Docker is unavailable, the job must fail instead of silently skipping the integration suite. Run the suite locally with `pnpm --filter paratix test:integration` whenever changing `ssh` or `readFile` semantics.
