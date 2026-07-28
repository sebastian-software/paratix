import type { InitialUserConfig } from "./templates.js"

// Matches printWidth in PRETTIER_RC_TEMPLATE, which the scaffold ships.
const SCAFFOLD_PRINT_WIDTH = 100

type ServerTemplateOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host: string
  initialUser: InitialUserConfig
}

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
  // Without a key the ssh import and the constant would sit unused, so both
  // only appear once there is one. Prettier moves a long value onto its own
  // line, and a real public key is long enough, so the same threshold is
  // applied here — otherwise a fresh project fails its own format:check.
  const keyLiteral = JSON.stringify(adminPublicKey)
  const singleLineKey = `const adminPublicKey = ${keyLiteral}`
  const wrappedKey =
    singleLineKey.length > SCAFFOLD_PRINT_WIDTH
      ? `const adminPublicKey =\n  ${keyLiteral}`
      : singleLineKey
  const adminPublicKeyDeclaration = adminPublicKey == null ? "" : `${wrappedKey}\n`
  const sshImportLine = adminPublicKey == null ? "" : "  ssh,\n"
  const strictHostKeyCheckingDeclaration = 'const strictHostKeyChecking = "yes"'
  const expectedHostFingerprintLine =
    expectedHostFingerprint == null
      ? '    // expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT",'
      : `    expectedHostFingerprint: ${JSON.stringify(expectedHostFingerprint)}, // captured from port 22 during scaffolding`

  return `import { firstRun, isFirstRun, recipe, server, when } from "paratix"
import {
  command,
  file,
  hostname,
  net,
  package as packages,
${sshImportLine}  sshd,
  sysctl,
  ufw,
  user,
} from "paratix/modules"

${adminUserDeclaration}
${adminPublicKeyDeclaration}const serverName = "my-server"
const FIRST_RUN = isFirstRun()
const sshPorts = FIRST_RUN ? [22] : [2222]
const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443]
${strictHostKeyCheckingDeclaration}

export default server({
  name: serverName,
  host: ${JSON.stringify(host)},
  ssh: {
    ports: sshPorts,
    privateKey: "~/.ssh/id_ed25519", // "~" is expanded by Paratix
    // FIRST_RUN keeps the bootstrap path explicit and fail-closed:
    // - pass "paratix apply ... --first-run" for the bootstrap run
    // - pin expectedHostFingerprint/PublicKey or pre-populate known_hosts before connecting
    // - later runs omit that flag and go through port 2222 with the same strict host-key checking
    strictHostKeyChecking,
    user: ${sshUser},
${expectedHostFingerprintLine}
    // expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY",
  },
  env: {
    FIRST_RUN,
    SERVER_NAME: serverName,
    SSH_PORT: 2222,
  },
  run: [
    net.hosts("127.0.1.1", [serverName]),
    hostname.set(serverName),
    packages.upgrade("2026-03-01"),
    packages.installed("curl", "htop", "ufw"),`
}

function createFirewallRecipe(): string {
  return `
    recipe("firewall", [
      ufw.rule("allow", firewallTcpPorts),
      when(
        (env) => env.FIRST_RUN !== true,
        command.shell(
          "ufw --force delete allow 22 || true; ufw --force delete allow 22/tcp || true; ! ufw status | grep -Eq '^22(/tcp)?[[:space:]]+(\\\\(v6\\\\)[[:space:]]+)?ALLOW'",
          {
            check: "! ufw status | grep -Eq '^22(/tcp)?[[:space:]]+(\\\\(v6\\\\)[[:space:]]+)?ALLOW'",
            name: "remove bootstrap ssh firewall rule",
          }
        )
      ),
      ufw.enabled(),
    ]),`
}

function createKernelHardeningRecipe(): string {
  return `
    recipe("kernel-hardening", [
      sysctl.set("fs.protected_hardlinks", "1"),
      sysctl.set("fs.protected_symlinks", "1"),
      sysctl.set("kernel.dmesg_restrict", "1"),
      sysctl.set("kernel.kptr_restrict", "2"),
      sysctl.set("net.ipv4.conf.all.rp_filter", "1"),
      sysctl.set("net.ipv4.conf.default.rp_filter", "1"),
      sysctl.set("net.ipv4.tcp_syncookies", "1"),
    ]),`
}

function createAutomaticSecurityUpgradesRecipe(): string {
  return `
    recipe("automatic-security-upgrades", [
      packages.installed("unattended-upgrades"),
      file.copy("/etc/apt/apt.conf.d/20auto-upgrades", "./files/20auto-upgrades", {
        mode: "0644",
        owner: "root:root",
      }),
      file.copy("/etc/apt/apt.conf.d/50unattended-upgrades", "./files/50unattended-upgrades", {
        mode: "0644",
        owner: "root:root",
      }),
    ]),`
}

function createFirstRunStopModule(): string {
  return `
    firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue."),

    // Add application and user-facing services below this line.`
}

function createAdminRecipe(recipeName: string, adminPublicKey?: string): string {
  const authorizedKeysLine =
    adminPublicKey == null
      ? [
          "      // To let the admin user log in, add ssh to the paratix/modules",
          "      // import above and enable this line with your own public key:",
          '      // ssh.authorizedKeys(adminUser, "ssh-ed25519 AAAA... you@example.com"),',
        ].join("\n")
      : "      ssh.authorizedKeys(adminUser, adminPublicKey),"

  return `
    recipe("${recipeName}", [
      user.present(adminUser, {
        groups: ["sudo"],
        shell: "/bin/bash",
      }),
${authorizedKeysLine}
    ]),`
}

function createHardenedAdminServerTemplate(parameters: {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host: string
  initialAdminUser: string
}): string {
  const { adminPublicKey, expectedHostFingerprint, host, initialAdminUser } = parameters
  const adminUserDeclaration = `const adminUser = ${JSON.stringify(initialAdminUser)}`

  return `${createBaseServerHeader({
    adminPublicKey,
    adminUserDeclaration,
    expectedHostFingerprint,
    host,
    sshUser: "adminUser",
  })}
${createAdminRecipe("admin-access", adminPublicKey)}
${createFirewallRecipe()}
    recipe("ssh-hardening", [
      sshd.port(2222),
      sshd.config({
        PasswordAuthentication: "no",
        PermitRootLogin: "no",
      }),
    ]),
${createKernelHardeningRecipe()}
${createAutomaticSecurityUpgradesRecipe()}
${createFirstRunStopModule()}
  ],
})
`
}

function createBootstrapRootServerTemplate(
  host: string,
  adminPublicKey?: string,
  expectedHostFingerprint?: string
): string {
  const adminUserDeclaration = 'const adminUser = "paratix"'

  return `${createBaseServerHeader({
    adminPublicKey,
    adminUserDeclaration,
    expectedHostFingerprint,
    host,
    sshUser: 'FIRST_RUN ? "root" : adminUser',
  })}
${createAdminRecipe("bootstrap-admin-user", adminPublicKey)}
    recipe("bootstrap-admin-sudo", [
      file.copy("/etc/sudoers.d/90-paratix-admin-nopasswd", "./files/admin-nopasswd-sudoers", {
        mode: "0440",
        owner: "root:root",
      }),
    ]),
${createFirewallRecipe()}
    // Transitional bootstrap mode:
    // 1. Run this once as root with "--first-run" to create the dedicated admin user.
    // 2. The generated sudoers drop-in keeps the new admin path non-interactive via NOPASSWD sudo.
    // 3. Later runs omit "--first-run" and connect as the dedicated admin user on port 2222.
    // 4. The next regular run disables root login completely.
    recipe("ssh-hardening-transition", [
      sshd.port(2222),
      sshd.config({
        PasswordAuthentication: "no",
        PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no",
      }),
    ]),
${createKernelHardeningRecipe()}
${createAutomaticSecurityUpgradesRecipe()}
${createFirstRunStopModule()}
  ],
})
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
