import { execSync } from "node:child_process"
import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { join, resolve } from "node:path"

const MS_PER_MINUTE = 60_000
const INSTALL_TIMEOUT_MS = 120_000

const SERVER_TEMPLATE = `import { server, recipe } from "paratix";
import { package as pkg, hostname, sshd, ufw, file, service, user } from "paratix/modules";

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    user: "root",
    ports: [22],
    privateKey: "~/.ssh/id_ed25519",
  },
  env: {
    SERVER_NAME: "my-server",
    SSH_PORT: 2222,
  },
  run: [
    hostname.set("my-server"),
    pkg.upgrade("2026-03-01"),
    pkg.installed("nginx", "curl", "htop"),

    recipe("ssh-hardening", [
      sshd.port(2222),
      sshd.config({
        PermitRootLogin: "no",
        PasswordAuthentication: "no",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),

    recipe("firewall", [
      ufw.rule("allow", [22, 2222, 80, 443]),
      ufw.enabled(),
    ]),
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

function detectPackageManager(): { command: string; name: string } {
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

export function writeProjectFiles(projectDirectory: string): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const packageJson = {
    dependencies: {
      paratix: "^0.1.0",
    },
    engines: {
      node: ">=24.0.0",
    },
    name: projectDirectory.split("/").pop(),
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
  writeFileSync(join(projectDirectory, "server.ts"), SERVER_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "tsconfig.json"), TSCONFIG_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".gitignore"), GITIGNORE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".env.example"), ENV_EXAMPLE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "files", ".gitkeep"), "")
}

function installDependencies(
  projectDirectory: string,
  pm: { command: string; name: string }
): boolean {
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

export function isValidProjectName(name: string): boolean {
  const trimmed = name.trim()
  return /^[a-z0-9][a-z0-9\x2d]*$/v.test(trimmed)
}

function validateProjectName(name: string | undefined): asserts name is string {
  if (name == null || name === "") {
    console.error("Usage: create-paratix <project-name>")
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  if (!isValidProjectName(name)) {
    console.error(
      `Error: Invalid project name "${name}" — use only lowercase letters, numbers, and hyphens.`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }
}

function main(): void {
  const projectName = process.argv[2]

  validateProjectName(projectName)

  const projectDirectory = resolve(projectName)

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (existsSync(projectDirectory)) {
    console.error(`Error: Directory "${projectName}" already exists.`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(1)
  }

  const pm = detectPackageManager()

  console.log(`Creating Paratix project in ${projectDirectory}...`)

  writeProjectFiles(projectDirectory)
  if (!installDependencies(projectDirectory, pm)) {
    process.exitCode = 1
  }

  console.log(`
Project created successfully!

  cd ${projectName}

Edit server.ts with your server details, then:

  ${pm.name === "npm" ? "npm run" : pm.name} apply
`)
}

// Only run when executed directly, not when imported (e.g. in tests)
// Exported for testing: verifies the guard is safe when argv[1] is undefined.
export function isDirectExecution(moduleUrl: string, argv1: null | string | undefined): boolean {
  return argv1 != null && moduleUrl.endsWith(argv1.replaceAll("\\", "/"))
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
