export type InitialUserConfig = { kind: "admin"; user: string } | { kind: "root" }

export const AGENTS_TEMPLATE = `# Paratix project instructions

Before changing \`server.ts\`, playbooks, or custom modules, read the
[agent authoring guidance](node_modules/paratix/llm-guide.md#agent-authoring-guidance)
for the installed Paratix version. If \`node_modules\` is missing, complete the
project installation first.

Import the core API from \`paratix\` and built-in modules from \`paratix/modules\`.
Use the installed guide for the actual API and authoring patterns.
`

export const CLAUDE_TEMPLATE = `@AGENTS.md
`

export const TSCONFIG_TEMPLATE = `{
  "compilerOptions": {
    "target": "ES2024",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "types": ["node"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["**/*.ts"]
}
`

export const GITIGNORE_TEMPLATE = `node_modules/
dist/
.env
*.log
`

export const PRETTIER_RC_TEMPLATE = `{
  "semi": false,
  "singleQuote": false,
  "bracketSpacing": true,
  "arrowParens": "always",
  "tabWidth": 2,
  "trailingComma": "es5",
  "printWidth": 100
}
`

export const PRETTIER_IGNORE_TEMPLATE = `pnpm-lock.yaml
package-lock.json
yarn.lock
bun.lockb
`

export const ESLINT_CONFIG_TEMPLATE = `import { getEslintConfig } from "eslint-config-setup"

export default [
  ...(await getEslintConfig({ node: true })),
  {
    // The shared config registers JavaScript rules that ESLint refuses to run
    // against the json/json language, which aborts the whole lint run rather
    // than reporting findings. Nothing here needs JSON linting.
    ignores: ["**/*.json", "node_modules/**", "files/**"],
  },
]
`

export const PNPM_WORKSPACE_TEMPLATE = `allowBuilds:
  cpu-features: true
  esbuild: true
  ssh2: true
  unrs-resolver: false
`

export const CSPELL_TEMPLATE = `{
  "version": "0.2",
  "language": "en",
  "words": ["NOPASSWD", "paratix"]
}
`

export const ENV_EXAMPLE_TEMPLATE = `# Server configuration
# SUDO_PASSWORD=your-sudo-password
# SSH_KEY_PATH=~/.ssh/id_ed25519
`

export const AUTO_UPGRADES_20_TEMPLATE = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`

export const UNATTENDED_UPGRADES_50_TEMPLATE = `Unattended-Upgrade::Origins-Pattern {
        "origin=\${distro_id},archive=\${distro_codename}-security";
};

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
`

export function createAdminNopasswdSudoersContent(adminUser: string): string {
  return `# Bootstrap default: dedicated admin user with passwordless sudo.
# This keeps the post-bootstrap Paratix workflow non-interactive after the
# initial root run. If you prefer password-protected sudo later, replace this
# with a stricter policy after the bootstrap is complete.
${adminUser} ALL=(ALL:ALL) NOPASSWD:ALL
`
}
