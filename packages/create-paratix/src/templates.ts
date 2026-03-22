export type InitialUserConfig = { kind: "admin"; user: string } | { kind: "root" }

type ServerTemplateOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host: string
  initialUser: InitialUserConfig
}

export const TSCONFIG_TEMPLATE = `{
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

export const GITIGNORE_TEMPLATE = `node_modules/
dist/
.env
*.log
`

export const ENV_EXAMPLE_TEMPLATE = `# Server configuration
# SUDO_PASSWORD=your-sudo-password
# SSH_KEY_PATH=~/.ssh/id_ed25519
`

type BaseServerHeaderOptions = {
  adminPublicKey?: string
  adminUserDeclaration: string
  expectedHostFingerprint?: string
  host: string
  sshUser: string
}

function createBaseServerHeader({
  adminPublicKey,
  adminUserDeclaration,
  expectedHostFingerprint,
  host,
  sshUser,
}: BaseServerHeaderOptions): string {
  const strictHostKeyCheckingDeclaration =
    expectedHostFingerprint == null
      ? 'const strictHostKeyChecking = FIRST_RUN ? "accept-new" : "yes";'
      : 'const strictHostKeyChecking = "yes";'
  const expectedHostFingerprintLine =
    expectedHostFingerprint == null
      ? '    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",'
      : `    expectedHostFingerprint: ${JSON.stringify(expectedHostFingerprint)}, // captured from port 22 during scaffolding`

  return `import { recipe, server } from "paratix";
import { hostname, package as packages, service, ssh, sshd, ufw, user } from "paratix/modules";

${adminUserDeclaration}
const adminPublicKey = ${JSON.stringify(adminPublicKey ?? "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY")};
const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";
const sshPorts = FIRST_RUN ? [22] : [2222];
const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443];
${strictHostKeyCheckingDeclaration}

export default server({
  name: "my-server",
  host: ${JSON.stringify(host)},
  ssh: {
    ports: sshPorts,
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    // FIRST_RUN keeps the bootstrap path explicit:
    // - pass "paratix apply ... --first-run" for the bootstrap run
    // - later runs omit that flag and go through port 2222 with strict host-key checking again
    strictHostKeyChecking,
    user: ${sshUser},
${expectedHostFingerprintLine}
    // expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY",
  },
  env: {
    FIRST_RUN,
    SERVER_NAME: "my-server",
    SSH_PORT: 2222,
  },
  run: [
    hostname.set("my-server"),
    packages.upgrade("2026-03-01"),
    packages.installed("nginx", "curl", "htop"),
`
}

function createFirewallRecipe(): string {
  return `
    recipe("firewall", [
      ufw.rule("allow", firewallTcpPorts),
      ufw.enabled(),
    ]),
`
}

function createAdminRecipe(recipeName: string): string {
  return `
    recipe("${recipeName}", [
      user.present(adminUser, {
        groups: ["sudo"],
        shell: "/bin/bash",
      }),
      ssh.authorizedKeys(adminUser, adminPublicKey),
    ]),
`
}

function createHardenedAdminServerTemplate(parameters: {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host: string
  initialAdminUser: string
}): string {
  const { adminPublicKey, expectedHostFingerprint, host, initialAdminUser } = parameters
  const adminUserDeclaration = `const adminUser = "${initialAdminUser}";`

  return `${createBaseServerHeader({
    adminPublicKey,
    adminUserDeclaration,
    expectedHostFingerprint,
    host,
    sshUser: "adminUser",
  })}
${createAdminRecipe("admin-access")}
${createFirewallRecipe()}
    recipe("ssh-hardening", [
      sshd.port(2222),
      sshd.config({
        PasswordAuthentication: "no",
        PermitRootLogin: "no",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),
  ],
});
`
}

function createBootstrapRootServerTemplate(
  host: string,
  adminPublicKey?: string,
  expectedHostFingerprint?: string
): string {
  const adminUserDeclaration = 'const adminUser = "admin";'

  return `${createBaseServerHeader({
    adminPublicKey,
    adminUserDeclaration,
    expectedHostFingerprint,
    host,
    sshUser: 'FIRST_RUN ? "root" : adminUser',
  })}
${createAdminRecipe("bootstrap-admin-user")}
${createFirewallRecipe()}
    // Transitional bootstrap mode:
    // 1. Run this once as root with "--first-run" to create the dedicated admin user.
    // 2. Later runs omit "--first-run" and connect as the dedicated admin user on port 2222.
    // 3. The next regular run disables root login completely.
    recipe("ssh-hardening-transition", [
      sshd.port(2222),
      sshd.config({
        PasswordAuthentication: "no",
        PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),
  ],
});
`
}

export function createServerTemplate(options: ServerTemplateOptions): string {
  return options.initialUser.kind === "root"
    ? createBootstrapRootServerTemplate(
        options.host,
        options.adminPublicKey,
        options.expectedHostFingerprint
      )
    : createHardenedAdminServerTemplate({
        adminPublicKey: options.adminPublicKey,
        expectedHostFingerprint: options.expectedHostFingerprint,
        host: options.host,
        initialAdminUser: options.initialUser.user,
      })
}
