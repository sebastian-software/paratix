import type { Linter } from "eslint"

import { getEslintConfig } from "eslint-config-setup"

const config = await getEslintConfig({ ai: true, node: true, oxlint: true })

const eslintConfig: Linter.Config[] = [
  ...config,
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/coverage/**",
      ".claude/**",
      ".sf-plugin/**",
      ".wisdom-*",
      "**/*.md",
      "**/*.json",
      "**/*.yaml",
      "**/*.yml",
      "sebastian-gmbh-paratix-test/**",
      "packages/create-paratix/create-paratix-scaffold-test/**",
    ],
  },
  {
    files: ["**/test/**/*.ts"],
    rules: {
      // Test helpers routinely create partial mock objects that are narrower
      // than the full interface — unsafe-type-assertion and unsafe-argument
      // false-positives are expected here.
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-type-assertion": "off",
      "security/detect-non-literal-fs-filename": "off",
    },
  },
]

export default eslintConfig
