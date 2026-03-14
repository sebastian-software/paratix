import type { Linter } from "eslint"

import { getEslintConfig } from "eslint-config-setup"

const config = await getEslintConfig({ ai: true, node: true, oxlint: true })

const eslintConfig: Linter.Config[] = [
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
    files: ["**/test/**/*.ts"],
    rules: {
      "security/detect-non-literal-fs-filename": "off",
    },
  },
]

export default eslintConfig
