import { spawnSync } from "node:child_process"

import { escapeCliControlCharacters } from "./cliFormat.js"

const MS_PER_MINUTE = 60_000
const INSTALL_TIMEOUT_MS = 120_000

// R-0000663: model the install command as `{ executable, args }` so the
// caller can invoke `spawnSync` with `shell: false` and an argv array
// instead of feeding a single string through `execSync`. The previous
// `execSync("pnpm install", …)` shape resolves the command through
// `/bin/sh -c`, which would interpret shell metacharacters in any
// dynamically constructed command — a hidden shell-injection hazard if
// future code paths ever derived the executable or its arguments from
// user input. Splitting the command and forcing `shell: false` removes
// the `/bin/sh -c` step entirely so no shell parsing can be reintroduced
// by accident.
export type PackageManagerCommand = {
  args: readonly string[]
  executable: string
}

export type PackageManager = {
  command: PackageManagerCommand
  name: string
}

const PNPM_INSTALL: PackageManagerCommand = { args: ["install"], executable: "pnpm" }
const YARN_INSTALL: PackageManagerCommand = { args: ["install"], executable: "yarn" }
const BUN_INSTALL: PackageManagerCommand = { args: ["install"], executable: "bun" }
const NPM_INSTALL: PackageManagerCommand = { args: ["install"], executable: "npm" }

export function detectPackageManager(): PackageManager {
  const agent = process.env.npm_config_user_agent ?? ""

  if (agent.startsWith("pnpm")) {
    return { command: PNPM_INSTALL, name: "pnpm" }
  }
  if (agent.startsWith("yarn")) {
    return { command: YARN_INSTALL, name: "yarn" }
  }
  if (agent.startsWith("bun")) {
    return { command: BUN_INSTALL, name: "bun" }
  }
  return { command: NPM_INSTALL, name: "npm" }
}

const RUN_INSTALL_MANUALLY_HINT = "Run install manually."

function reportInstallFailure(message: string): false {
  console.error(`Failed to install dependencies: ${message}`)
  console.error(RUN_INSTALL_MANUALLY_HINT)
  return false
}

function reportInstallTimeout(): false {
  console.error(
    `Installation timed out after ${Math.round(INSTALL_TIMEOUT_MS / MS_PER_MINUTE)} minutes.`
  )
  console.error(RUN_INSTALL_MANUALLY_HINT)
  return false
}

export function installDependencies(projectDirectory: string, pm: PackageManager): boolean {
  console.log(`Installing dependencies with ${pm.name}...`)
  // R-0000663: `shell: false` is the load-bearing flag — it pins
  // `spawnSync` to the direct-exec path so the executable and its
  // arguments are never re-parsed by `/bin/sh`. The argv array is
  // forwarded verbatim to the OS-level spawn primitive.
  const result = spawnSync(pm.command.executable, [...pm.command.args], {
    cwd: projectDirectory,
    shell: false,
    stdio: "inherit",
    timeout: INSTALL_TIMEOUT_MS,
  })
  if (result.error) {
    return reportInstallFailure(
      result.error instanceof Error ? result.error.message : String(result.error)
    )
  }
  if (result.signal === "SIGTERM") {
    return reportInstallTimeout()
  }
  if (result.status !== 0) {
    return reportInstallFailure(
      `${pm.command.executable} exited with status ${String(result.status)}`
    )
  }
  return true
}

function getCommandPrefix(pm: PackageManager): string {
  return pm.name === "npm" ? "npm run" : pm.name
}

// R-0000736: even though projectName is validated upstream
// (isValidProjectName), the success messages are emitted into a
// terminal where any stray ANSI/control codepoint would be interpreted
// verbatim. Escaping defensively at the print site prevents future
// callers from relying on the upstream validation alone and ensures the
// `cd <name>` line a copy-pasting operator sees is always inert.
export function printSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = getCommandPrefix(pm)
  const escapedProjectName = escapeCliControlCharacters(projectName)
  console.log(`
Project created successfully!

  cd ${escapedProjectName}

Edit server.ts with your server details, then:

  ${prefix} apply:first-run:dry
  ${prefix} apply:first-run
  ${prefix} apply:dry
  ${prefix} apply
`)
}

export function printPartialSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = getCommandPrefix(pm)
  const escapedProjectName = escapeCliControlCharacters(projectName)
  console.log(`
Project files created, but dependency installation failed.

  cd ${escapedProjectName}

Install dependencies manually, then run:

  ${prefix} apply:first-run:dry
  ${prefix} apply:first-run
  ${prefix} apply:dry
  ${prefix} apply
`)
}
