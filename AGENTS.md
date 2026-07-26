# AGENTS.md

**Effective Flow project setup:** docs/adr/effective-flow-project-setup.md

Use `pnpm agent:check` to check code changes. Do not run checks on 'git commit'.

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](packages/paratix/llm-guide.md#agent-authoring-guidance) in the complete API reference.

Do not use cspell:ignore in the code. Write cspell findings into cspell.json
