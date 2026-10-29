import { getOxlintConfig } from "eslint-config-setup"
import { defineConfig, type OxlintConfig, type OxlintOverride } from "oxlint"

const config = getOxlintConfig({ ai: true, node: true })

// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- OxlintConfigResult is structurally compatible with OxlintConfig
const baseConfig = config as unknown as OxlintConfig

const VITEST_ASSERT_FUNCTION_NAMES = [
  "expect",
  "expectTypeOf",
  "assert",
  "assertType",
  "expectGeneratedServerToTypecheck",
]

// Mutate the existing test-files override block in place. Oxlint resolves
// `overrides` by first-match per file glob and does not deep-merge a later
// block that targets the same files, so appending a new override block has
// no effect and we must rewrite the existing rule entry.
const overrides: OxlintOverride[] = (baseConfig.overrides ?? []).map((override) => {
  if (override.rules?.["vitest/expect-expect"] === undefined) {
    return override
  }
  return {
    ...override,
    rules: {
      ...override.rules,
      "vitest/expect-expect": ["error", { assertFunctionNames: VITEST_ASSERT_FUNCTION_NAMES }],
    },
  }
})

export default defineConfig({
  ...baseConfig,
  ignorePatterns: [
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.react-router/**",
    ".sf-plugin/**",
    "sebastian-gmbh-paratix-test/**",
    "packages/create-paratix/create-paratix-scaffold-test/**",
  ],
  overrides: [
    {
      files: ["website/app/routes/**/*.tsx"],
      rules: {
        "max-lines": "off",
        "max-lines-per-function": "off",
      },
    },
    ...overrides,
  ],
})
