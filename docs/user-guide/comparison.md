# Choosing an Automation Tool

Paratix, Ansible, and pyinfra can all manage machines over SSH, but they optimize for different workflows. Choose based on the systems and team you have, not on feature counts.

| Criterion             | Paratix                                                         | Ansible                                                                                 | pyinfra                                                                            |
| --------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Authoring             | TypeScript playbooks with exported types                        | YAML playbooks, with Jinja templating and Python for extensions                         | Python deployment code and operations                                              |
| Idempotence           | Built-in modules use explicit check/apply behavior              | Modules describe or enforce state; behavior depends on each module                      | Operations inspect state and generate commands to reach the requested state        |
| Inventory and fleets  | One server definition per run; recipes structure work within it | Inventory, groups, variables, patterns, and play strategies are core concepts           | Inventory, groups, data, and parallel execution are built in                       |
| Transport and targets | Focused on Linux servers over SSH                               | SSH plus a broad connection-plugin system and modules for many platforms and services   | SSH by default, with connectors for local, container, and other execution contexts |
| Ecosystem             | Compact built-in module set in this repository                  | Large collection and role ecosystem                                                     | Python package with built-in operations and deploys that can call Python libraries |
| Entry cost            | Familiar to TypeScript developers; small operational model      | More concepts and configuration, with extensive documentation and established practices | Familiar to Python developers who want deployment logic as code                    |
| Extension model       | Compose existing TypeScript and implement Paratix modules       | Write modules and plugins, usually in Python, or use collections and roles              | Write normal Python and custom operations                                          |

See the official [Ansible playbook and inventory documentation](https://docs.ansible.com/ansible/latest/playbook_guide/index.html) and [pyinfra documentation](https://docs.pyinfra.com/) for their current capabilities.

## Choose Paratix when

- You manage a VPS or a small number of Linux hosts over SSH.
- Your team prefers typed TypeScript playbooks and explicit module ordering.
- Bootstrap, SSH hardening, port changes, and reboot reconnects are central to the workflow.
- The built-in modules cover the state you need, or you are comfortable extending a compact TypeScript codebase.

Paratix is not the appropriate choice for large fleet orchestration, dynamic inventory at scale, or targets that are not managed over SSH. It also does not attempt to match the breadth of Ansible's ecosystem.

## Choose Ansible when

- Inventory groups, host patterns, roles, collections, and fleet-wide orchestration are important.
- You need broad platform, network-device, cloud-service, or connection-plugin coverage.
- Your organization already has Ansible content, operational practices, and expertise.

Ansible may be a less natural fit when a small TypeScript team specifically wants infrastructure definitions to use its existing language, type checker, and editor workflow.

## Choose pyinfra when

- You prefer Python and want deployment logic to remain regular Python code.
- You need inventory and parallel host execution without adopting YAML playbooks.
- Python libraries and custom operations are a natural extension point for your team.

pyinfra may be a less natural fit for a TypeScript-only team or when Paratix's opinionated VPS bootstrap and reconnect workflow is the main requirement.

[Back to the user guide](./README.md)
