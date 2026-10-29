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
    // packages/ssh-native: cargo output, platform package manifests and the
    // napi-generated index.d.ts (diff-checked in CI instead).
    "packages/ssh-native/target/**",
    "packages/ssh-native/npm/**",
    "packages/ssh-native/index.d.ts",
  ],
  overrides: [
    {
      // packages/ssh-native has no `"type": "module"`, so its hand-written
      // loader and JS wrapper are CommonJS. Node wraps every CommonJS file in a
      // module function, so top-level declarations never become implicit
      // globals; oxlint parses these files as scripts and reports them anyway.
      files: ["packages/ssh-native/*.js", "packages/ssh-native/lib/**/*.js"],
      rules: {
        "no-implicit-globals": "off",
      },
    },
    {
      // packages/ssh-native tests are plain node:test `.test.mjs` files; the
      // shared config only relaxes these limits for `*.test.{ts,tsx}`.
      files: ["packages/ssh-native/test/**/*.test.mjs"],
      rules: {
        "max-lines-per-function": "off",
        "max-nested-callbacks": "off",
        "max-statements": "off",
      },
    },
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
