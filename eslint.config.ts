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
]
