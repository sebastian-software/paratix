# Paratix

Paratix is a CLI tool that configures VPS servers over SSH using TypeScript playbooks. Each step checks its target state before acting — running a playbook twice does nothing on a already-configured server.

## Quickstart

```bash
# Scaffold a new server config
pnpm create paratix my-server

# Apply it
paratix apply ./my-server.ts
```

## Example playbook

```typescript
import { server } from "paratix"
import { apt, file, service, hostname } from "paratix/modules"

export default server({
  name: "vps-01",
  host: "1.2.3.4",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/id_ed25519" },
  run: [
    hostname.set("vps-01"),
    apt.installed("nginx", "fail2ban"),
    apt.upgrade("2024-03-10"),
    file.template("/etc/nginx/nginx.conf", "./files/nginx.tmpl.conf"),
    service.running("nginx"),
  ],
})
```

## Features

- **Idempotent** — every module checks current state before making changes
- **SSH-resilient** — reconnects automatically when a step changes the SSH port or triggers a reboot
- **TypeScript-native** — playbooks are plain `.ts` files with full type checking and editor support
- **Template system** — deploy config files with `{{key}}` variable substitution from the env
- **Recipes** — group modules with optional signals (e.g. restart a service only when its config changed)

## Modules

| Module     | What it does                                                       |
| ---------- | ------------------------------------------------------------------ |
| `apt`      | Install/remove packages, add repositories, run upgrades            |
| `file`     | Copy files, render templates, manage lines/blocks, set permissions |
| `service`  | Start, stop, enable, disable systemd services                      |
| `sshd`     | Change SSH port, set `sshd_config` options                         |
| `ufw`      | Add firewall rules, enable UFW                                     |
| `user`     | Create and remove user accounts                                    |
| `group`    | Create and remove system groups                                    |
| `hostname` | Set the server hostname                                            |
| `command`  | Run a shell command (with optional idempotency check)              |

Additional modules in the spec (not yet implemented): `compose`, `sysctl`, `mount`, `rsync`, `op`, `git`, `download`, `cron`, `systemd`, `system`, `package`, `net`, `script`, `archive`, `ssh`.

## CLI options

```
paratix apply <file> [options]

Options:
  --dry-run                     Check state only, do not apply changes
  --env <key=value>             Set an env variable (repeatable)
  --env-file <path>             Load env variables from a dotenv file
  --reconnect-timeout <seconds> SSH reconnect timeout in seconds (default: 300)
```

## Built-in functions

These are imported from `paratix` alongside `server` and `recipe`:

| Function                      | Description                                        |
| ----------------------------- | -------------------------------------------------- |
| `assert(condition, message)`  | Abort if a condition on the env is false           |
| `debug(message)`              | Print a message during execution                   |
| `fail(message)`               | Unconditionally abort with a message               |
| `pause(message?)`             | Wait for user confirmation before continuing       |
| `when(condition, ...modules)` | Run modules only if a condition on the env is true |

## Development

```bash
pnpm install
pnpm build
pnpm test
```

Additional scripts: `pnpm lint`, `pnpm format`, `pnpm agent:check` (lint + format check + typecheck + test).

## License

MIT
