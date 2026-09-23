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

Requires Node.js 24 or newer.

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
| `AGENTS.md`                       | Project instructions for coding agents                      |
| `CLAUDE.md`                       | Imports `AGENTS.md` with `@AGENTS.md`                       |

`AGENTS.md` points to `node_modules/paratix/llm-guide.md#agent-authoring-guidance` in the generated project, so agents read the guide for the installed Paratix version. It also identifies the `paratix` and `paratix/modules` imports. Finish installing dependencies before using that guide. Both agent files are generated for root and admin-user projects; existing files or symlinks at those paths are never overwritten.

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

The project name is required and must contain only lowercase letters, numbers, and hyphens, starting with a letter or number. In an interactive terminal, omitted host and initial-user values are prompted for; the CLI can also offer a host-key scan and a local admin public key. For non-interactive use, pass `--host` and `--initial-user`. Root bootstrap also requires an admin public key so the new admin user can log in after the first run.

| Option                                      | Effect                                                                                                                 |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `--host <domain-or-ip>`                     | Server hostname or IP address.                                                                                         |
| `--initial-user <root\|name>`               | Use root bootstrap or connect as an existing named admin user.                                                         |
| `--expected-host-fingerprint <fingerprint>` | Pin an OpenSSH SHA256 host fingerprint.                                                                                |
| `--admin-public-key <ssh-public-key>`       | Set the admin SSH public key directly. Cannot be combined with `--admin-public-key-file`.                              |
| `--admin-public-key-file <path>`            | Read the admin SSH public key from a file. Cannot be combined with `--admin-public-key`.                               |
| `-h`, `--help`                              | Print usage and option descriptions to stdout and exit successfully, without prompting, installing, or creating files. |

Run `create-paratix --help` for the complete CLI help. Either help flag also works after the project name.

## Programmatic API

Install `create-paratix` in a Node.js 24+ TypeScript project before importing it. `scaffoldProject()` creates a new project in a private same-parent staging directory, publishes the completed files, then runs the supplied package manager's install command. The package-manager argument is an object with a `name` and a `command` containing an `executable` and `args`:

```typescript
import { scaffoldProject, type ScaffoldOptions } from "create-paratix"

const options: ScaffoldOptions = {
  host: "example.com",
  initialUser: { kind: "admin", user: "deploy" },
}

const installed = scaffoldProject(
  "my-server",
  { name: "pnpm", command: { executable: "pnpm", args: ["install"] } },
  options
)
```

`scaffoldProject()` returns `true` when installation succeeds. If the installer reports failure by returning `false`, it returns `false`, retains the generated project files, and sets `process.exitCode` to `1`; install dependencies manually before using the linked Paratix guide. An exception during generation or installation triggers cleanup of the project directory created by that call. An existing destination is protected.

For a files-only operation, use `writeProjectFiles()`. It writes directly to the target directory, does not install dependencies, and returns `void`. The target's parent directory must already exist. Because this call is not staged, files written before a collision or other error can remain; existing scaffold files and symlinks are not overwritten.

```typescript
import { writeProjectFiles, type InitialUserConfig, type ScaffoldOptions } from "create-paratix"

const initialUser: InitialUserConfig = { kind: "admin", user: "deploy" }
const options: ScaffoldOptions = { host: "example.com", initialUser }

writeProjectFiles("./my-server-files-only", options)
```

Both functions accept the same optional `ScaffoldOptions`: `host`, `initialUser`, `adminPublicKey`, `expectedHostFingerprint`, and an optional `installer` callback for `scaffoldProject()`. Without options, the programmatic defaults are `host: "1.2.3.4"` and `initialUser: { kind: "admin", user: "paratix" }`. Replace the placeholder host before applying the playbook. For root bootstrap, pass `initialUser: { kind: "root" }` and a valid `adminPublicKey`.

All exports from the package root are listed below. CLI and prompt helpers are available for callers building their own interface; the main project-generation calls above handle the normal workflow.

### Project generation

| Export                         | Purpose                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `scaffoldProject`              | Stage and publish project files, then install dependencies; returns `boolean`. |
| `writeProjectFiles`            | Write project files directly without installing; returns `void`.               |
| `ScaffoldOptions` (type)       | Optional generation values and installer callback.                             |
| `InitialUserConfig` (type)     | `{ kind: "root" }` or `{ kind: "admin", user: string }`.                       |
| `deriveParatixDependencyRange` | Derive the `paratix` dependency range from this package's version.             |

### Validation and normalization

| Export                                                                         | Purpose                                               |
| ------------------------------------------------------------------------------ | ----------------------------------------------------- |
| `isValidProjectName`, `normalizeProjectName`                                   | Check the CLI project-name form and trim a name.      |
| `isValidHost`, `normalizeHost`, `validateHost`                                 | Check, trim, or validate a server host.               |
| `isValidInitialUserName`, `normalizeInitialUserName`, `parseInitialUserConfig` | Check, trim, or parse an initial SSH user.            |
| `isValidExpectedHostFingerprint`, `validateExpectedHostFingerprint`            | Check or validate an OpenSSH SHA256 host fingerprint. |

### CLI and prompt helpers

| Export                                                        | Purpose                                                              |
| ------------------------------------------------------------- | -------------------------------------------------------------------- |
| `parseCliArguments`                                           | Parse CLI arguments into project and option values.                  |
| `resolveCliOrPromptHost`                                      | Use a supplied host or prompt for one on a TTY.                      |
| `promptForHost`, `promptForInitialUserConfig`                 | Collect host or bootstrap-user input interactively.                  |
| `promptForAdminPublicKey`, `promptForHostFingerprint`         | Collect an admin key or verified host fingerprint interactively.     |
| `CliExitError`, `handleCliExit`, `restoreInteractiveTerminal` | Represent and handle CLI errors, including terminal cleanup.         |
| `isDirectExecution`                                           | Check whether a module URL is the directly executed CLI entry point. |

## After Scaffolding

Edit `server.ts` and extend the generated baseline with your own services, files, deployments, and runtime configuration. The scaffold is meant to get you to a safe and productive starting point quickly, not to lock you into a fixed project shape.

For changes to generated project structure, CLI usage, and bootstrap defaults, see the [migration notes](../../docs/user-guide/migration.md). Connection failures in a generated project are covered by the [troubleshooting guide](../../docs/user-guide/troubleshooting.md).

## License

MIT — Copyright 2026 [Sebastian Software GmbH](https://sebastian-software.com)
