# create-paratix

Scaffolds a new [Paratix](https://github.com/sebastian-software/paratix) server project. The default template assumes a dedicated admin user and a final hardened SSH setup. If you must bootstrap from `root`, that mode is available explicitly via `--bootstrap-root`.

## Quick Start

**Step 1 -- Create the project**

```sh
# npm
npm create paratix my-server

# pnpm
pnpm create paratix my-server

# yarn
yarn create paratix my-server

# bun
bunx create-paratix my-server
```

Optional transitional root bootstrap mode:

```sh
# npm
npm create paratix my-server -- --bootstrap-root

# pnpm
pnpm create paratix my-server --bootstrap-root

# yarn
yarn create paratix my-server --bootstrap-root

# bun
bunx create-paratix my-server --bootstrap-root
```

**Step 2 -- Enter the directory**

Dependencies are installed automatically. If installation fails, run your package manager's install command manually.

```sh
cd my-server
```

**Step 3 -- Edit `server.ts`** with your actual server address, admin username, public key, and the modules you want to apply.

**Step 4 -- Apply**

```sh
# pnpm / yarn / bun
pnpm apply:dry   # dry run first -- see what would change
pnpm apply       # apply to the server

# npm
npm run apply:dry
npm run apply
```

## Project Structure

| File / Directory | Purpose                                                                   |
| ---------------- | ------------------------------------------------------------------------- |
| `server.ts`      | Your playbook. Edit this file.                                            |
| `package.json`   | Includes `apply` and `apply:dry` scripts.                                 |
| `tsconfig.json`  | TypeScript config (ES2024, NodeNext, strict).                             |
| `.gitignore`     | Excludes `node_modules/`, `dist/`, `.env`, and log files.                 |
| `.env.example`   | Template for secrets. Copy to `.env` and fill in values.                  |
| `files/`         | Place template files here. They get uploaded to the server at apply time. |

## Writing Your Playbook

`server.ts` exports a server definition. The default scaffolded file uses the hardened admin mode:

```typescript
import { server, recipe } from "paratix"
import { package as pkg, hostname, sshd, ssh, ufw, service, user } from "paratix/modules"

const adminUser = "admin"
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY"

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    user: adminUser,
    ports: [22],
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
  },
  env: {
    SERVER_NAME: "my-server",
    SSH_PORT: 2222,
  },
  run: [
    hostname.set("my-server"),
    pkg.upgrade("2026-03-01"),
    pkg.installed("nginx", "curl", "htop"),

    recipe("admin-access", [
      user.present(adminUser, {
        groups: ["sudo"],
        shell: "/bin/bash",
      }),
      ssh.authorizedKeys(adminUser, adminPublicKey),
    ]),

    recipe(
      "ssh-hardening",
      [
        sshd.port(2222),
        sshd.config({
          PermitRootLogin: "no",
          PasswordAuthentication: "no",
        }),
      ],
      {
        signals: [service.restart("sshd")],
      }
    ),

    recipe("firewall", [ufw.rule("allow", [2222, 80, 443]), ufw.enabled()]),
  ],
})
```

Wenn du mit einem frischen Server startest, auf dem nur `root` per SSH erreichbar ist, verwende den expliziten Übergangsmodus `--bootstrap-root`. Dieses Template bleibt bewusst als temporärer Bootstrap markiert, erstellt den dedizierten Admin-User und lässt Root-Login nur vorübergehend auf `prohibit-password`, bis du `ssh.user` auf den Admin-User umgestellt hast.

Key concepts:

- **Modules** -- each item in `run` is a module. A module checks the current server state and applies changes only when needed (idempotent).
- **Recipes** -- `recipe()` groups related modules under a name. If any module in the group changes something, signals fire after the group completes (e.g. `service.restart("sshd")`).
- **Signals** -- actions that run after a recipe when at least one module in it made a change. Useful for reloading services.
- **Env** -- values in the `env` field are available in template files as `{{KEY}}`. See [Environment Variables](#environment-variables) below.

For the full list of built-in modules and their options, see the [Paratix module reference](https://github.com/sebastian-software/paratix).

## Applying to a Server

Always do a dry run first to see what Paratix would change without touching the server:

```sh
pnpm apply:dry
```

Then apply for real:

```sh
pnpm apply
```

These scripts map to:

```sh
paratix apply server.ts --dry-run
paratix apply server.ts
```

### CLI flags

| Flag                            | Default  | Description                                                          |
| ------------------------------- | -------- | -------------------------------------------------------------------- |
| `<file>`                        | required | Path to the playbook file (`.ts` or `.js`).                          |
| `--dry-run`                     | `false`  | Check state only. Shows what would change without applying anything. |
| `--env <key=value>`             | `{}`     | Set or override an env value. Repeatable: `--env A=1 --env B=2`.     |
| `--env-file <path>`             | --       | Load a `.env` file.                                                  |
| `--reconnect-timeout <seconds>` | `300`    | Seconds to wait for SSH reconnect after a port or reboot change.     |
| `--verbose`                     | `false`  | Show full stack traces on errors.                                    |

After all modules run, Paratix prints a summary:

```
3 changed · 5 ok · 0 skipped · 0 failed
```

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```sh
cp .env.example .env
```

The example contains:

```sh
# Server configuration
# SUDO_PASSWORD=your-sudo-password
# SSH_KEY_PATH=~/.ssh/id_ed25519
```

Env values come from three sources, merged in this order (last wins):

1. `--env-file <path>`
2. The `env` field in `server()`
3. `--env <key=value>` flags -- these have the highest priority

> **Note:** CLI `--env` flags override both `.env` files and `server({ env })`. Put stable project defaults in `server({ env })`, environment-specific values in `.env` files, and one-off overrides on the CLI.

### Template files

Files in `files/` with a `.tmpl` extension support `{{KEY}}` placeholders. Paratix replaces them with env values at apply time.

```
files/nginx.conf.tmpl
```

```nginx
server {
  server_name {{SERVER_NAME}};
}
```

To write a literal `{{`, use `\{{`.

## Requirements

- Node.js >= 24.0.0

## License

MIT
