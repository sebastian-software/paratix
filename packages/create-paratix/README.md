# create-paratix

Scaffold a new Paratix server project in a few minutes.

`create-paratix` is the fastest way to start using Paratix on a real server. Instead of assembling a playbook, scripts, formatting, and bootstrap logic by hand, it gives you a ready-to-run project with a sensible structure and a hardened first-run workflow.

It is designed for the moment when you already know the server you want to manage, but do not want to rebuild the same setup every time. The scaffold gives you a practical default project, then leaves the actual infrastructure logic in your hands as normal TypeScript.

For fresh machines, it also handles the awkward part that usually gets glossed over: initial SSH access, first-run hardening, switching to a dedicated admin user, and continuing safely from there.

## Features

- **Project scaffold for Paratix**: generates a ready-to-edit server project instead of just a single file.
- **First-run bootstrap flow**: supports explicit `--first-run` hardening before later service rollout.
- **Initial user selection**: works with either a root bootstrap or an existing admin user.
- **SSH host-key bootstrap**: can pin the current host fingerprint during scaffolding.
- **DX-friendly TypeScript setup**: direct `tsx` execution, bundler-style module resolution, ESLint, and Prettier included.
- **Practical project defaults**: scripts, formatting, files directory, env example, and ignore files are created for you.

## Getting Started

Create a new project:

```bash
# npm
npm create paratix my-server

# pnpm
pnpm create paratix my-server

# yarn
yarn create paratix my-server

# bun
bunx create-paratix my-server
```

Then enter the directory and review the generated playbook:

```bash
cd my-server
```

Run the bootstrap flow:

```bash
pnpm apply:first-run:dry
pnpm apply:first-run
pnpm apply:dry
pnpm apply
```

The first run is intentionally staged. It applies the hardened baseline first, then later runs continue with the remaining services and application-specific steps.

## What You Get

The scaffolded project includes:

| File / Directory                  | Purpose                                                     |
| --------------------------------- | ----------------------------------------------------------- |
| `server.ts`                       | Your Paratix playbook                                       |
| `files/`                          | Templates and configuration files to upload                 |
| `package.json`                    | Apply, lint, and formatting scripts                         |
| `tsconfig.json`                   | TypeScript config for direct `tsx` execution                |
| `eslint.config.ts`                | ESLint config using `await getEslintConfig({ node: true })` |
| `.prettierrc` / `.prettierignore` | Formatting defaults, including lockfile ignores             |
| `.env.example`                    | Starting point for environment values                       |

## Bootstrap Model

`create-paratix` supports two entry paths:

- **Root bootstrap**: for a fresh server that still only accepts SSH as `root`
- **Admin-user bootstrap**: for a server where a dedicated admin user already exists

The generated project keeps this explicit:

- `paratix apply ... --first-run` stays on port `22`, completes the hardened bootstrap stage, and stops intentionally at the first-run checkpoint
- first and later runs use strict host-key checking; pin `expectedHostFingerprint`/`expectedHostPublicKey` or pre-populate `known_hosts` before connecting
- later runs use the hardened path, usually on port `2222`, with the same strict host-key checking

When you scaffold interactively, the CLI can also:

- select an admin public key from `~/.ssh`
- scan the current host key from SSH port `22` and pin it as `expectedHostFingerprint` after you verify it out of band

## Non-Interactive Usage

You can provide the important bootstrap values on the command line:

```bash
pnpm create paratix my-server --host example.com --initial-user root --admin-public-key-file ~/.ssh/id_ed25519.pub
```

Or for an existing admin user:

```bash
pnpm create paratix my-server --host deploy.example.com --initial-user deploy --admin-public-key "ssh-ed25519 AAAA... you@example.com"
```

## After Scaffolding

Edit `server.ts` and extend the generated baseline with your own services, files, deployments, and runtime configuration. The scaffold is meant to get you to a safe and productive starting point quickly, not to lock you into a fixed project shape.

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
