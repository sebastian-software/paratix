# AGENTS.md

**Effective Flow project setup:** docs/adr/effective-flow-project-setup.md

Use `pnpm agent:check` to check code changes. Do not run checks on 'git commit'.

Before changing `ssh` or `readFile` semantics, run `pnpm --filter paratix test:integration` locally against a Docker daemon. CI has no Docker runtime, so that suite skips itself there and cannot catch such a change — a deliberate `readFile` fix once invalidated eight integration assertions unnoticed for months.

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](packages/paratix/llm-guide.md#agent-authoring-guidance) in the complete API reference.

Do not use cspell:ignore in the code. Write cspell findings into cspell.json
