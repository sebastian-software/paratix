import { describe, expect, it } from "vitest"

import * as packageApi from "../src/index.js"
import { resolveEnvironment } from "../src/index.js"
import * as moduleApi from "../src/modules/index.js"

const EXPECTED_PACKAGE_EXPORTS = [
  "NEEDS_APPLY",
  "apt",
  "archive",
  "assert",
  "assertValidModuleMetaEntries",
  "assertValidModuleMetaEntry",
  "buildKeyValueDiff",
  "buildUnifiedDiff",
  "command",
  "compose",
  "cron",
  "debug",
  "diffEnvironmentToMetaEntries",
  "download",
  "environmentMeta",
  "environmentToMetaEntries",
  "fail",
  "failed",
  "failedCommand",
  "failedCommandWithDiagnostic",
  "file",
  "firstRun",
  "git",
  "group",
  "hostname",
  "isBooleanEnvironmentMetaEntry",
  "isEnvironmentMetaEntry",
  "isFirstRun",
  "isLazyEnvironmentMetaEntry",
  "isNumberEnvironmentMetaEntry",
  "isSshdPortMetaEntry",
  "isStringEnvironmentMetaEntry",
  "isSystemHostMetaEntry",
  "isSystemRebootMetaEntry",
  "mergeEnvironmentFromMeta",
  "meta",
  "mount",
  "net",
  "op",
  "package",
  "pause",
  "quadlet",
  "recipe",
  "releaseUpgrade",
  "resolveEnvironment",
  "restartSystemdUnit",
  "rsync",
  "script",
  "server",
  "service",
  "shellQuote",
  "signals",
  "ssh",
  "sshd",
  "sshdPortMeta",
  "swap",
  "sysctl",
  "system",
  "systemHostMeta",
  "systemRebootMeta",
  "systemd",
  "timer",
  "ufw",
  "user",
  "when",
] as const

const EXPECTED_MODULE_EXPORTS = [
  "apt",
  "archive",
  "buildKeyValueDiff",
  "buildUnifiedDiff",
  "command",
  "compose",
  "cron",
  "download",
  "file",
  "git",
  "group",
  "hostname",
  "mount",
  "net",
  "op",
  "package",
  "quadlet",
  "releaseUpgrade",
  "restartSystemdUnit",
  "rsync",
  "script",
  "service",
  "ssh",
  "sshd",
  "swap",
  "sysctl",
  "system",
  "systemd",
  "timer",
  "ufw",
  "user",
] as const

describe("public API", () => {
  it("exports resolveEnvironment from the package entry point", async () => {
    await expect(
      resolveEnvironment(
        {
          async SECRET() {
            await Promise.resolve()
            return "resolved-secret"
          },
        },
        "SECRET"
      )
    ).resolves.toBe("resolved-secret")
  })

  it("exposes the complete supported runtime export sets", () => {
    expect(Object.keys(packageApi).sort()).toStrictEqual(EXPECTED_PACKAGE_EXPORTS)
    expect(Object.keys(moduleApi).sort()).toStrictEqual(EXPECTED_MODULE_EXPORTS)
  })

  it("re-exports every built-in module from the package entry point", () => {
    for (const exportName of EXPECTED_MODULE_EXPORTS) {
      expect(packageApi, `missing root built-in export: ${exportName}`).toHaveProperty(exportName)
      expect(packageApi[exportName]).toBe(moduleApi[exportName])
    }
  })
})
