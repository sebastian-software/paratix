# AGENTS.md

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](./llm-guide.md#agent-authoring-guidance) in the complete API reference.

## Integration tests

The `describe("Paratix integration", ...)` block in `test/integration/paratix.integration.test.ts` boots an sshd container through `harness.ts` and exercises the real SSH/SFTP code paths. The GitHub Actions runners that execute `agent:check:integration` (Integration Check and Publish workflows) currently do not provide a working Docker runtime, so the block is marked with `describe.skip` to keep CI green. Re-enable it once Docker (or a compatible runtime such as Podman) is available on the runners again. Locally the block can still be run with `pnpm --filter paratix test:integration` whenever a Docker daemon is reachable.
