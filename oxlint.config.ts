import { getOxlintConfig } from "eslint-config-setup"
import { defineConfig, type OxlintConfig } from "oxlint"

const config = getOxlintConfig({ ai: true, node: true })

export default defineConfig({
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- OxlintConfigResult is structurally compatible with OxlintConfig
  ...(config as unknown as OxlintConfig),
  ignorePatterns: ["**/node_modules/**", "**/dist/**", "sebastian-gmbh-paratix-test/**"],
})
