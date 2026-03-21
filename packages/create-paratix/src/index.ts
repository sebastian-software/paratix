import { execSync } from "node:child_process"
import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"

const MS_PER_MINUTE = 60_000
const INSTALL_TIMEOUT_MS = 120_000

export type ScaffoldMode = "bootstrap-root" | "hardened-admin"

const HARDENED_ADMIN_SERVER_TEMPLATE = `import { server, recipe } from "paratix";
import { package as pkg, hostname, sshd, ssh, ufw, service, user } from "paratix/modules";

const adminUser = "admin";
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    user: adminUser,
    ports: [22],
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    // Initial host-key bootstrap for fresh servers:
    // - keep this explicit accept-new mode only for the first verified connection
    // - then pin the host key and switch strictHostKeyChecking back to "yes"
    strictHostKeyChecking: "accept-new",
    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",
    // expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY",
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

    recipe("firewall", [
      ufw.rule("allow", [2222, 80, 443]),
      ufw.enabled(),
    ]),

    recipe("ssh-hardening", [
      sshd.port(2222),
      sshd.config({
        PermitRootLogin: "no",
        PasswordAuthentication: "no",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),
  ],
});
`

const BOOTSTRAP_ROOT_SERVER_TEMPLATE = `import { server, recipe } from "paratix";
import { package as pkg, hostname, sshd, ssh, ufw, service, user } from "paratix/modules";

const adminUser = "admin";
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    user: "root",
    ports: [22],
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    // Initial host-key bootstrap for fresh servers:
    // - keep this explicit accept-new mode only for the first verified connection
    // - then pin the host key and switch strictHostKeyChecking back to "yes"
    strictHostKeyChecking: "accept-new",
    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",
    // expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY",
  },
  env: {
    SERVER_NAME: "my-server",
    SSH_PORT: 2222,
  },
  run: [
    hostname.set("my-server"),
    pkg.upgrade("2026-03-01"),
    pkg.installed("nginx", "curl", "htop"),

    recipe("bootstrap-admin-user", [
      user.present(adminUser, {
        groups: ["sudo"],
        shell: "/bin/bash",
      }),
      ssh.authorizedKeys(adminUser, adminPublicKey),
    ]),

    recipe("firewall", [
      ufw.rule("allow", [2222, 80, 443]),
      ufw.enabled(),
    ]),

    // Transitional bootstrap mode:
    // 1. Run this once as root to create the dedicated admin user.
    // 2. Switch ssh.user to admin.
    // 3. Replace PermitRootLogin with "no" or regenerate without --bootstrap-root.
    recipe("ssh-hardening-transition", [
      sshd.port(2222),
      sshd.config({
        PermitRootLogin: "prohibit-password",
        PasswordAuthentication: "no",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),
  ],
});
`

const TSCONFIG_TEMPLATE = `{
  "compilerOptions": {
    "target": "ES2024",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["*.ts"]
}
`

const GITIGNORE_TEMPLATE = `node_modules/
dist/
.env
*.log
`

const ENV_EXAMPLE_TEMPLATE = `# Server configuration
# SUDO_PASSWORD=your-sudo-password
# SSH_KEY_PATH=~/.ssh/id_ed25519
`

type PackageManager = { command: string; name: string }
type ScaffoldOptions = {
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
  mode?: ScaffoldMode
}

function createServerTemplate(mode: ScaffoldMode): string {
  return mode === "bootstrap-root" ? BOOTSTRAP_ROOT_SERVER_TEMPLATE : HARDENED_ADMIN_SERVER_TEMPLATE
}

function detectPackageManager(): PackageManager {
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

export function writeProjectFiles(projectDirectory: string, options?: ScaffoldOptions): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const mode = options?.mode ?? "hardened-admin"

  const packageJson = {
    dependencies: {
      paratix: "^0.1.0",
    },
    devDependencies: {
      tsx: "^4.20.6",
    },
    engines: {
      node: ">=24.0.0",
    },
    name: derivePackageName(projectDirectory),
    private: true,
    scripts: {
      apply: "paratix apply server.ts",
      "apply:dry": "paratix apply server.ts --dry-run",
    },
    type: "module",
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "package.json"), `${JSON.stringify(packageJson, null, 2)}\n`)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "server.ts"), createServerTemplate(mode))
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "tsconfig.json"), TSCONFIG_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".gitignore"), GITIGNORE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".env.example"), ENV_EXAMPLE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "files", ".gitkeep"), "")
}

function installDependencies(projectDirectory: string, pm: PackageManager): boolean {
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

function printSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = pm.name === "npm" ? "npm run" : pm.name
  console.log(`
Project created successfully!

  cd ${projectName}

Edit server.ts with your server details, then:

  ${prefix} apply:dry
  ${prefix} apply
`)
}

function printPartialSuccessMessage(projectName: string, pm: PackageManager): void {
  const prefix = pm.name === "npm" ? "npm run" : pm.name
  console.log(`
Project files created, but dependency installation failed.

  cd ${projectName}

Install dependencies manually, then run:

  ${prefix} apply:dry
  ${prefix} apply
`)
}

export function isValidProjectName(name: string): boolean {
  const trimmed = name.trim()
  return /^[a-z0-9][a-z0-9\x2d]*$/v.test(trimmed)
}

export function normalizeProjectName(name: string): string {
  return name.trim()
}

function derivePackageName(projectDirectory: string): string {
  return basename(projectDirectory.replaceAll("\\", "/"))
}

export function parseCliArguments(argv: string[]): {
  mode: ScaffoldMode
  projectName: string | undefined
} {
  let mode: ScaffoldMode = "hardened-admin"
  let projectName: string | undefined

  for (const argument of argv) {
    if (argument === "--bootstrap-root") {
      mode = "bootstrap-root"
      continue
    }

    if (argument.startsWith("--")) {
      console.error(`Error: Unknown option "${argument}".`)
      // eslint-disable-next-line node/no-process-exit
      process.exit(1)
    }

    if (projectName == null) {
      projectName = argument
      continue
    }

    console.error("Usage: create-paratix <project-name> [--bootstrap-root]")
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  return { mode, projectName }
}

function validateProjectName(name: string | undefined): string {
  if (name == null || name === "") {
    console.error("Usage: create-paratix <project-name>")
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  const normalizedName = normalizeProjectName(name)

  if (!isValidProjectName(normalizedName)) {
    console.error(
      `Error: Invalid project name "${name}" — use only lowercase letters, numbers, and hyphens.`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  return normalizedName
}

export function scaffoldProject(
  projectName: string,
  pm: PackageManager,
  options?: ScaffoldOptions
): boolean {
  const normalizedProjectName = normalizeProjectName(projectName)
  const projectDirectory = resolve(normalizedProjectName)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (existsSync(projectDirectory)) {
    console.error(`Error: Directory "${normalizedProjectName}" already exists.`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  console.log(`Creating Paratix project in ${projectDirectory}...`)

  writeProjectFiles(projectDirectory, options)
  const installer = options?.installer ?? installDependencies
  const installed = installer(projectDirectory, pm)
  if (!installed) {
    process.exitCode = 1
    printPartialSuccessMessage(normalizedProjectName, pm)
    return false
  }

  printSuccessMessage(normalizedProjectName, pm)
  return true
}

function main(): void {
  const { mode, projectName } = parseCliArguments(process.argv.slice(2))

  const normalizedProjectName = validateProjectName(projectName)

  const pm = detectPackageManager()
  scaffoldProject(normalizedProjectName, pm, { mode })
}

// Only run when executed directly, not when imported (e.g. in tests)
// Exported for testing: verifies the guard is safe when argv[1] is undefined.
export function isDirectExecution(moduleUrl: string, argv1: null | string | undefined): boolean {
  return argv1 != null && moduleUrl.endsWith(argv1.replaceAll("\\", "/"))
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
