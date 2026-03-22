export type InitialUserConfig = { kind: "admin"; user: string } | { kind: "root" }

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

function createBaseServerHeader(adminUserDeclaration: string, sshUser: string): string {
  return `import { recipe, server } from "paratix";
import { hostname, package as packages, service, ssh, sshd, ufw, user } from "paratix/modules";

${adminUserDeclaration}
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";
const FIRST_RUN = true;
const sshPorts = FIRST_RUN ? [22] : [2222];
const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443];
const strictHostKeyChecking = FIRST_RUN ? "accept-new" : "yes";

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    ports: sshPorts,
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    // FIRST_RUN keeps the bootstrap path explicit:
    // - true: connect on port 22 and allow explicit TOFU via "accept-new"
    // - false: connect on port 2222 with strict host-key checking again
    strictHostKeyChecking,
    user: ${sshUser},
    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",
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

function createHardenedAdminServerTemplate(initialAdminUser: string): string {
  const adminUserDeclaration = `const adminUser = "${initialAdminUser}";`

  return `${createBaseServerHeader(adminUserDeclaration, "adminUser")}
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

function createBootstrapRootServerTemplate(): string {
  const adminUserDeclaration = 'const adminUser = "admin";'

  return `${createBaseServerHeader(adminUserDeclaration, '"root"')}
${createAdminRecipe("bootstrap-admin-user")}
${createFirewallRecipe()}
    // Transitional bootstrap mode:
    // 1. Run this once as root to create the dedicated admin user.
    // 2. Set FIRST_RUN = false and switch ssh.user to admin.
    // 3. Replace PermitRootLogin with "no".
    recipe("ssh-hardening-transition", [
      sshd.port(2222),
      sshd.config({
        PasswordAuthentication: "no",
        PermitRootLogin: "prohibit-password",
      }),
    ], {
      signals: [service.restart("sshd")],
    }),
  ],
});
`
}

export function createServerTemplate(initialUser: InitialUserConfig): string {
  return initialUser.kind === "root"
    ? createBootstrapRootServerTemplate()
    : createHardenedAdminServerTemplate(initialUser.user)
}
