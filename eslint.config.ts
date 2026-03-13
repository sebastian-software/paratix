import { getEslintConfig } from "eslint-config-setup"

const config = await getEslintConfig({ ai: true, node: true })

export default [
  ...config,
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      ".claude/**",
      ".wisdom-*",
      "**/*.md",
      "**/*.json",
      "**/*.yaml",
      "**/*.yml",
    ],
  },
  {
    rules: {
      "@cspell/spellchecker": [
        "warn",
        {
          cspell: {
            words: [
              "paratix",
              "getent",
              "userdel",
              "usermod",
              "tmpl",
              "oxlint",
              "nginx",
              "sshd",
              "dpkg",
              "hostnamectl",
              "systemctl",
              "groupadd",
              "groupdel",
              "chpasswd",
              "claude",
            ],
          },
        },
      ],
    },
  },
]
