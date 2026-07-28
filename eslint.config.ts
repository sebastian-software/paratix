import type { Linter } from "eslint"

import { getEslintConfig } from "eslint-config-setup"

const config = await getEslintConfig({ ai: true, node: true, oxlint: true })

const eslintConfig: Linter.Config[] = [
  ...config,
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/.react-router/**",
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
    files: ["**/test/**/*.{mjs,ts}"],
    rules: {
      // Test helpers routinely create partial mock objects that are narrower
      // than the full interface — unsafe-type-assertion and unsafe-argument
      // false-positives are expected here.
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-type-assertion": "off",
      // Same origin: assertions reference methods of those mock objects
      // detached from their receiver (`expect(mock.method).toHaveBeenCalled()`).
      // The rule guards against losing `this`, which a mock that never uses
      // `this` cannot lose.
      "@typescript-eslint/unbound-method": "off",
      "node/no-unsupported-features/node-builtins": "off",
      "security/detect-non-literal-fs-filename": "off",
    },
  },
  {
    files: ["website/app/**/*.tsx"],
    rules: {
      "@typescript-eslint/naming-convention": "off",
      "max-lines": "off",
      "max-lines-per-function": "off",
      "node/no-unsupported-features/node-builtins": "off",
    },
  },
]

export default eslintConfig
