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
  return `import { server, recipe } from "paratix";
import { package as pkg, hostname, sshd, ssh, ufw, service, user } from "paratix/modules";

${adminUserDeclaration}
const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";

export default server({
  name: "my-server",
  host: "1.2.3.4",
  ssh: {
    user: ${sshUser},
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
`
}

function createFirewallRecipe(): string {
  return `
    recipe("firewall", [
      ufw.rule("allow", [2222, 80, 443]),
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
        PermitRootLogin: "no",
        PasswordAuthentication: "no",
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
    // 2. Switch ssh.user to admin.
    // 3. Replace PermitRootLogin with "no".
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
}

export function createServerTemplate(initialUser: InitialUserConfig): string {
  return initialUser.kind === "root"
    ? createBootstrapRootServerTemplate()
    : createHardenedAdminServerTemplate(initialUser.user)
}
