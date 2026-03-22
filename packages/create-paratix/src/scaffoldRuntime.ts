import { execSync } from "node:child_process"

const MS_PER_MINUTE = 60_000
const INSTALL_TIMEOUT_MS = 120_000

export type PackageManager = { command: string; name: string }

export function detectPackageManager(): PackageManager {
  const agent = process.env.npm_config_user_agent ?? ""

  if (agent.startsWith("pnpm")) {
    return { command: "pnpm install", name: "pnpm" }
  }
  if (agent.startsWith("yarn")) {
    return { command: "yarn install", name: "yarn" }
  }
  if (agent.startsWith("bun")) {
    return { command: "bun install", name: "bun" }
  }
  return { command: "npm install", name: "npm" }
}

export function installDependencies(projectDirectory: string, pm: PackageManager): boolean {
  console.log(`Installing dependencies with ${pm.name}...`)
  try {
    execSync(pm.command, { cwd: projectDirectory, stdio: "inherit", timeout: INSTALL_TIMEOUT_MS })
    return true
  } catch (error) {
    if (error instanceof Error && "signal" in error && error.signal === "SIGTERM") {
      console.error(
        `Installation timed out after ${Math.round(INSTALL_TIMEOUT_MS / MS_PER_MINUTE)} minutes.`
      )
    } else {
      const message = error instanceof Error ? error.message : String(error)
      console.error(`Failed to install dependencies: ${message}`)
    }
    console.error("Run install manually.")
    return false
  }
}

function getCommandPrefix(pm: PackageManager): string {
  return pm.name === "npm" ? "npm run" : pm.name
}

export function printSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = getCommandPrefix(pm)
  console.log(`
Project created successfully!

  cd ${projectName}

Edit server.ts with your server details, then:

  ${prefix} apply:dry
  ${prefix} apply
`)
}

export function printPartialSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = getCommandPrefix(pm)
  console.log(`
Project files created, but dependency installation failed.

  cd ${projectName}

Install dependencies manually, then run:

  ${prefix} apply:dry
  ${prefix} apply
`)
}
