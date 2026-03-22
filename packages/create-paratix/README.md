# create-paratix

Scaffolds a new [Paratix](https://github.com/sebastian-software/paratix) server project. The CLI now asks which SSH user exists initially on the target server and generates the matching bootstrap path: explicit `root` bootstrap or direct admin-user hardening.

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

Optional non-interactive initial-user selection:

```sh
# npm
npm create paratix my-server -- --initial-user root

# pnpm
pnpm create paratix my-server --initial-user root

# yarn
yarn create paratix my-server --initial-user deploy

# bun
bunx create-paratix my-server --initial-user deploy
```

**Step 2 -- Enter the directory**

Dependencies are installed automatically. If installation fails, run your package manager's install command manually.

```sh
cd my-server
```

**Step 3 -- Edit `server.ts`** with your actual server address, admin username, public key, and the modules you want to apply.

The scaffold also includes an explicit host-key bootstrap:

- first run: `strictHostKeyChecking: "accept-new"` so a fresh host can complete `apply:dry`
- after you have verified the host key out of band: replace that transition mode with `expectedHostFingerprint` or `expectedHostPublicKey`
- the generated playbook opens firewall port `2222` before `sshd.port(2222)` runs, so the first real apply can reconnect safely

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

`server.ts` exports a server definition. The generated file depends on the initial SSH user you choose:

- `root`: Bootstrap once via `root`, create a dedicated admin user, then switch `ssh.user` to that admin user and disable root login.
- `admin`: Connect directly as the named admin user and scaffold the hardened end state immediately.

The direct admin-user path looks like this:

```typescript
import { recipe, server } from "paratix"
import { hostname, package as packages, service, ssh, sshd, ufw, user } from "paratix/modules"

const adminUser = "admin"
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY"

export default server({
  host: "1.2.3.4",
  name: "my-server",
  env: {
    SERVER_NAME: "my-server",
    SSH_PORT: 2222,
  },
  ssh: {
    ports: [22],
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    user: adminUser,
    // Initial host-key bootstrap for fresh servers:
    // - keep this explicit accept-new mode only for the first verified connection
    // - then pin the host key and switch strictHostKeyChecking back to "yes"
    strictHostKeyChecking: "accept-new",
    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",
    // expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY",
  },
  run: [
    hostname.set("my-server"),
    packages.upgrade("2026-03-01"),
    packages.installed("nginx", "curl", "htop"),

    recipe("admin-access", [
      user.present(adminUser, {
        groups: ["sudo"],
        shell: "/bin/bash",
      }),
      ssh.authorizedKeys(adminUser, adminPublicKey),
    ]),

    recipe("firewall", [ufw.rule("allow", [2222, 80, 443]), ufw.enabled()]),

    recipe(
      "ssh-hardening",
      [
        sshd.port(2222),
        sshd.config({
          PasswordAuthentication: "no",
          PermitRootLogin: "no",
        }),
      ],
      {
        signals: [service.restart("sshd")],
      }
    ),
  ],
})
```

Wenn dein Server initial nur `root` per SSH anbietet, wähle im Prompt `root` oder rufe das Scaffold nicht-interaktiv mit `--initial-user root` auf. Dieses Template bleibt bewusst als temporärer Bootstrap markiert, erstellt den dedizierten Admin-User und lässt Root-Login nur vorübergehend auf `prohibit-password`, bis du `ssh.user` auf den Admin-User umgestellt hast.

Wenn bereits ein Admin-User wie `deploy`, `ubuntu` oder `admin` existiert, wähle diesen Namen direkt. Dann erzeugt `create-paratix` keinen Root-Bootstrap-Pfad, sondern scaffoldet sofort den gehärteten Zielzustand für genau diesen User.

### Initial user selection

Standardmäßig fragt `create-paratix` interaktiv:

1. Ist der initiale SSH-User `root` oder ein Admin-User?
2. Falls Admin-User: Wie heißt dieser User konkret?

Nicht-interaktiv funktioniert derselbe Vertrag über `--initial-user`:

```sh
# Root bootstrap
pnpm create paratix my-server --initial-user root

# Existing admin user
pnpm create paratix my-server --initial-user deploy
```

Wichtig für den ersten echten Lauf: Das Scaffold setzt die Firewall-Freigabe für `2222` bewusst vor den eigentlichen SSH-Portwechsel. Paratix reconnectet nach `sshd.port(...)` sofort auf den neuen Port; ohne diese Reihenfolge würde der erste Apply leicht an einer noch geschlossenen Firewall scheitern.

### Host-key bootstrap

Paratix verwendet standardmäßig striktes Host-Key-Checking. Ein frisch erzeugtes `create-paratix`-Projekt setzt deshalb im Scaffold explizit:

```ts
strictHostKeyChecking: "accept-new"
```

Das ist ein bewusst markierter Übergangsmodus für den ersten verifizierten Kontakt mit einem frischen Host. Direkt daneben enthält das generierte `server.ts` kommentierte Platzhalter für:

- `expectedHostFingerprint`
- `expectedHostPublicKey`

Empfohlener Ablauf:

1. Verifiziere den Host-Key deines Servers out of band.
2. Führe den ersten `apply:dry` mit dem expliziten `accept-new`-Bootstrap aus.
3. Ersetze danach `accept-new` durch `expectedHostFingerprint` oder `expectedHostPublicKey`.
4. Setze `strictHostKeyChecking` wieder auf `"yes"` oder lasse die Option weg.

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
