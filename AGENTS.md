# AGENTS.md

**Effective Flow project setup:** docs/adr/effective-flow-project-setup.md

Use `pnpm agent:check` to check code changes. Do not run checks on 'git commit'.

Before changing `ssh` or `readFile` semantics, run `pnpm --filter paratix test:integration` locally against a reachable Docker daemon. The GitHub-hosted `Integration Check` also provides Docker and runs an explicit `docker info` preflight; if Docker is unavailable, the job must fail instead of silently skipping the integration suite. The suite skips dynamically only in local environments without a reachable Docker daemon.

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](packages/paratix/llm-guide.md#agent-authoring-guidance) in the complete API reference.

Do not use cspell:ignore in the code. Write cspell findings into cspell.json
