/* eslint-disable no-template-curly-in-string -- Shell dpkg-query format strings, not JS templates */
import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { pkg } from "../../src/modules/package.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    allowUnstubbedDefaults: true,
    defaultTestResult: false,
    ...options,
  })

// ---------------------------------------------------------------------------
// Helpers: mock responses for package manager detection
// ---------------------------------------------------------------------------

/** Mock responses that simulate apt being available. */
const APT_FOUND = {
  "which apt-get": { code: 0 },
}

/** Mock responses that simulate dnf being available (apt not present). */
const DNF_FOUND = {
  "which apt-get": { code: 1 },
  "which dnf": { code: 0 },
}

/** Mock responses that simulate yum being available (apt + dnf not present). */
const YUM_FOUND = {
  "which apt-get": { code: 1 },
  "which dnf": { code: 1 },
  "which yum": { code: 0 },
}

/** Mock responses that simulate apk being available (apt + dnf + yum not present). */
const APK_FOUND = {
  "which apk": { code: 0 },
  "which apt-get": { code: 1 },
  "which dnf": { code: 1 },
  "which yum": { code: 1 },
}

/** Mock responses that simulate no package manager being available. */
const NO_PM = {
  "which apk": { code: 1 },
  "which apt-get": { code: 1 },
  "which dnf": { code: 1 },
  "which yum": { code: 1 },
}

// ---------------------------------------------------------------------------
// Helpers: stateful exec/test overrides for apply() flows
//
// R-0000535: runInstallAndVerify re-checks each package after install. We
// need to model the transition from "missing" (pre-install) to "installed"
// (post-install) without conditionals inside the test bodies, which are
// forbidden by `eslint-plugin-vitest(no-conditional-in-test)`. The helpers
// below encapsulate the branching outside the it() blocks.
// ---------------------------------------------------------------------------

type MockSsh = ReturnType<typeof createMockSsh>
type InstallTrackingOverrides = {
  exec: MockSsh["exec"]
  test: MockSsh["test"]
}

// `await Promise.resolve()` in each branch satisfies @typescript-eslint/require-await
// and yields once to the microtask queue, matching the original mocks' timing.

const reportMissingProbe = async () => {
  await Promise.resolve()
  return false
}

// Build paired exec()/test() overrides that record install execution and flip
// the listed package-status probes from "missing" to "installed" once the
// install command has run.
function makeInstallTrackingOverrides(
  ssh: MockSsh,
  installCommand: string,
  missingProbes: readonly string[]
): InstallTrackingOverrides {
  const originalExec = ssh.exec.bind(ssh)
  const originalTest = ssh.test.bind(ssh)
  const installCommands = new Set([installCommand])
  const tracked = new Set(missingProbes)
  let installExecuted = false
  const runInstall = async (command: string, options?: ExecOptions) => {
    await Promise.resolve()
    installExecuted = true
    ssh.calls.push(command)
    ssh.execCalls.push({ command, options })
    return { code: 0, stderr: "", stdout: "" }
  }
  return {
    async exec(command, options) {
      return installCommands.has(command)
        ? runInstall(command, options)
        : originalExec(command, options)
    },
    async test(command) {
      return tracked.has(command) && !installExecuted ? reportMissingProbe() : originalTest(command)
    },
  }
}

// Build a test() override that returns false exactly once for the configured
// command (modelling the pre-install probe), then forwards to the underlying
// test() handler.
function makeOneShotMissingTest(ssh: MockSsh, missingCommand: string): MockSsh["test"] {
  const originalTest = ssh.test.bind(ssh)
  let consumed = false
  const reportMissingOnce = async () => {
    await Promise.resolve()
    consumed = true
    return false
  }
  return async (command) =>
    command === missingCommand && !consumed ? reportMissingOnce() : originalTest(command)
}

function makeAlwaysMissingPackageTest(
  ssh: MockSsh,
  missingCommand: string
): { getProbeCount: () => number; test: MockSsh["test"] } {
  const originalTest = ssh.test.bind(ssh)
  let probeCount = 0
  const reportStillMissing = async (command: string) => {
    await Promise.resolve()
    probeCount += 1
    ssh.calls.push(command)
    return false
  }
  return {
    getProbeCount: () => probeCount,
    async test(command) {
      return command === missingCommand ? reportStillMissing(command) : originalTest(command)
    },
  }
}

// ---------------------------------------------------------------------------
// pkg.installed
// ---------------------------------------------------------------------------

describe("pkg.installed", () => {
  // check

  it("check returns ok when all packages are installed (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'curl' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.installed("nginx", "curl")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns ok when all packages are installed (dnf)", async () => {
    const ssh = createMockSsh({
      ...DNF_FOUND,
      "rpm -q 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns ok when all packages are installed (apk)", async () => {
    const ssh = createMockSsh({
      ...APK_FOUND,
      "apk info -e 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when a package is missing", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'curl' 2>/dev/null | grep -q 'install ok installed'": {
        code: 1,
      },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.installed("nginx", "curl")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = pkg.installed("nginx")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when no package manager is found", async () => {
    const ssh = createMockSsh({
      ...NO_PM,
    })
    const mod = pkg.installed("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  // apply

  it("apply returns changed when install succeeds (apt)", async () => {
    // R-0000535: runInstallAndVerify re-checks each package after install.
    // apply() first calls hasAnyMissingPackage (pre-install), then runs the
    // install, then calls collectStillMissingPackages (post-install verify).
    // We use a sequential mock for the dpkg-query test calls: the first call
    // per package returns false (not installed → proceed to install), subsequent
    // calls return true (installed → verify passes → changed).
    const dpkgNginx =
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'"
    const dpkgCurl =
      "dpkg-query -W -f='${Status}' 'curl' 2>/dev/null | grep -q 'install ok installed'"
    const ssh = createMockSsh(
      {
        ...APT_FOUND,
      },
      { defaultTestResult: true }
    )
    // Override exec()/test() so that probes report "missing" until the install
    // command has run, then report "installed" via the underlying defaults.
    const overrides = makeInstallTrackingOverrides(
      ssh,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx' 'curl'",
      [dpkgNginx, dpkgCurl]
    )
    ssh.exec = overrides.exec
    ssh.test = overrides.test
    const mod = pkg.installed("nginx", "curl")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx' 'curl'"
    )
  })

  it("apply returns failed when apt install succeeds but package remains missing", async () => {
    const dpkgNginx =
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'"
    const installCommand = "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      [installCommand]: { code: 0 },
    })
    const missingPackage = makeAlwaysMissingPackageTest(ssh, dpkgNginx)
    ssh.test = missingPackage.test
    const mod = pkg.installed("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[package.installed: nginx] packages still missing after install: nginx"
    )
    expect(ssh.calls).toStrictEqual(["which apt-get", dpkgNginx, installCommand, dpkgNginx])
    expect(missingPackage.getProbeCount()).toBe(2)
  })

  it("apply forwards options.timeout when last argument is an options object", async () => {
    // R-0000535: runInstallAndVerify re-checks each package after install.
    const dpkgTexlive =
      "dpkg-query -W -f='${Status}' 'texlive-full' 2>/dev/null | grep -q 'install ok installed'"
    const ssh = createMockSsh(
      {
        ...APT_FOUND,
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'texlive-full'": { code: 0 },
      },
      { defaultTestResult: true }
    )
    ssh.test = makeOneShotMissingTest(ssh, dpkgTexlive)
    const mod = pkg.installed("texlive-full", { timeout: 600_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(mod.name).toBe("package.installed: texlive-full")
    const installCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'texlive-full'"
    )
    expect(installCall?.options?.timeout).toBe(600_000)
  })

  it("apply without options does not set a timeout key (installed)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    await mod.apply(ssh, emptyEnv)
    const installCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'"
    )
    expect(installCall?.options).not.toHaveProperty("timeout")
  })

  it("apply returns ok without install when all packages are already installed", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'curl' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.installed("nginx", "curl")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "ok" })
    expect(ssh.calls.some((call) => call.includes("apt-get install"))).toBe(false)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = pkg.installed("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[package.installed: nginx] SSH connection is required")
  })

  it("apply returns failed when no package manager is found", async () => {
    const ssh = createMockSsh({ ...NO_PM })
    const mod = pkg.installed("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("No supported package manager found")
  })

  it("apply returns failed when install command fails", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'": { code: 1 },
    })
    const mod = pkg.installed("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain("package installation failed")
  })

  // name

  it("has correct name format: package.installed: nginx, curl", () => {
    const mod = pkg.installed("nginx", "curl")
    expect(mod.name).toBe("package.installed: nginx, curl")
  })

  // input validation

  it("throws when called with no packages", () => {
    expect(() => pkg.installed()).toThrow("at least one package name is required")
  })

  it.each([
    "",
    " ",
    "nginx curl",
    "nginx\ncurl",
    "nginx\rcurl",
    "-o",
    "nginx-",
    "nginx+",
    "+nginx",
  ])("throws for invalid package name %j", (packageName) => {
    expect(() => pkg.installed(packageName)).toThrow("invalid package name")
  })
})

// ---------------------------------------------------------------------------
// pkg.absent
// ---------------------------------------------------------------------------

describe("pkg.absent", () => {
  // check

  it("check returns ok when no packages are installed", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 1,
      },
    })
    const mod = pkg.absent("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when a package is installed", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.absent("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = pkg.absent("nginx")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when no package manager is found", async () => {
    const ssh = createMockSsh({ ...NO_PM })
    const mod = pkg.absent("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  // apply

  it("apply returns changed when remove succeeds (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get remove -y -- 'nginx'": { code: 0 },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.absent("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
  })

  it("apply forwards options.timeout when last argument is an options object", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get remove -y -- 'nginx'": { code: 0 },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.absent("nginx", { timeout: 300_000 })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(mod.name).toBe("package.absent: nginx")
    const removeCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get remove -y -- 'nginx'"
    )
    expect(removeCall?.options?.timeout).toBe(300_000)
  })

  it("apply returns ok without remove when all packages are already absent", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 1,
      },
    })
    const mod = pkg.absent("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "ok" })
    expect(ssh.calls.some((call) => call.includes("apt-get remove"))).toBe(false)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = pkg.absent("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[package.absent: nginx] SSH connection is required")
  })

  it("apply returns failed when no package manager is found", async () => {
    const ssh = createMockSsh({ ...NO_PM })
    const mod = pkg.absent("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("No supported package manager found")
  })

  it("apply returns failed when the remove command fails", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get remove -y -- 'nginx'": {
        code: 1,
        stderr: "remove failed",
      },
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.absent("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain("package removal failed")
  })

  // name

  it("has correct name format: package.absent: nginx", () => {
    const mod = pkg.absent("nginx")
    expect(mod.name).toBe("package.absent: nginx")
  })

  // input validation

  it("throws when called with no packages", () => {
    expect(() => pkg.absent()).toThrow("at least one package name is required")
  })

  it.each([
    "",
    " ",
    "nginx curl",
    "nginx\ncurl",
    "nginx\rcurl",
    "-o",
    "nginx-",
    "nginx+",
    "+nginx",
  ])("throws for invalid package name %j", (packageName) => {
    expect(() => pkg.absent(packageName)).toThrow("invalid package name")
  })
})

// ---------------------------------------------------------------------------
// pkg.update
// ---------------------------------------------------------------------------

describe("pkg.update", () => {
  const FLAG = "[ -f /var/lib/paratix/flags/'package-update-2024-01-15' ]"

  // check

  it("check returns ok when flag file exists", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 0 },
    })
    const mod = pkg.update("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when flag is missing", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 1 },
    })
    const mod = pkg.update("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = pkg.update("2024-01-15")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  // apply

  it("apply returns changed and sets flag after update (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "apt-get update": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-update-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-update-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.update("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("apt-get update")
    expect(ssh.calls).toContain(
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-update-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-update-2024-01-15'"
    )
  })

  it("apply forwards options.timeout to the update command", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "apt-get update": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-update-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-update-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.update("2024-01-15", { timeout: 450_000 })
    await mod.apply(ssh, emptyEnv)
    const updateCall = ssh.execCalls.find((c) => c.command === "apt-get update")
    expect(updateCall?.options?.timeout).toBe(450_000)
  })

  it("apply returns ok without update when flag already exists", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 0 },
    })
    const mod = pkg.update("2024-01-15")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "ok" })
    expect(ssh.calls).not.toContain("apt-get update")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = pkg.update("2024-01-15")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[package.update: 2024-01-15] SSH connection is required"
    )
  })

  it("apply returns failed when no package manager is found", async () => {
    const ssh = createMockSsh({ ...NO_PM })
    const mod = pkg.update("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("No supported package manager found")
  })

  // name

  it("has correct name format: package.update: 2024-01-15", () => {
    const mod = pkg.update("2024-01-15")
    expect(mod.name).toBe("package.update: 2024-01-15")
  })
})

// ---------------------------------------------------------------------------
// pkg.upgrade
// ---------------------------------------------------------------------------

describe("pkg.upgrade", () => {
  const FLAG = "[ -f /var/lib/paratix/flags/'package-upgrade-2024-01-15' ]"

  // check

  it("check returns ok when flag file exists", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when flag is missing", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 1 },
    })
    const mod = pkg.upgrade("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = pkg.upgrade("2024-01-15")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  // apply

  it("apply returns changed and runs split apt upgrade pipeline", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")
    expect(ssh.calls).not.toContain(
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a && DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    )
    expect(ssh.calls).toContain(
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2024-01-15'"
    )
  })

  it("apply without options does not set a timeout key on exec options (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    await mod.apply(ssh, emptyEnv)
    const upgradeCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    )
    expect(upgradeCall).toBeDefined()
    expect(upgradeCall?.options).toBeDefined()
    expect(upgradeCall?.options).not.toHaveProperty("timeout")
  })

  it("apply forwards options.timeout to every step of the upgrade pipeline (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2026-05-01'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.upgrade("2026-05-01", { timeout: 900_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })

    const pipelineCommands = [
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a",
      "DEBIAN_FRONTEND=noninteractive apt-get update",
      "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
    ]
    for (const command of pipelineCommands) {
      const call = ssh.execCalls.find((c) => c.command === command)
      expect(call).toBeDefined()
      expect(call?.options?.timeout).toBe(900_000)
    }
  })

  it("apply with options.timeout=undefined does not set a timeout key (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15", { timeout: undefined })
    await mod.apply(ssh, emptyEnv)
    const upgradeCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    )
    expect(upgradeCall?.options).not.toHaveProperty("timeout")
  })

  it("apply returns ok without upgrade when flag already exists", async () => {
    const ssh = createMockSsh({
      [FLAG]: { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "ok" })
    expect(ssh.calls.some((call) => call.includes("apt-get upgrade"))).toBe(false)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = pkg.upgrade("2024-01-15")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[package.upgrade: 2024-01-15] SSH connection is required"
    )
  })

  it("apply stops at the first failing pipeline step (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get update": {
        code: 100,
        stderr: "E: dpkg was interrupted",
      },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[package.upgrade: 2024-01-15] package upgrade failed")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y")
  })

  // name

  it("has correct name format: package.upgrade: 2024-01-15", () => {
    const mod = pkg.upgrade("2024-01-15")
    expect(mod.name).toBe("package.upgrade: 2024-01-15")
  })
})

// ---------------------------------------------------------------------------
// Package Manager Detection
// ---------------------------------------------------------------------------

describe("package manager detection", () => {
  it("uses apt when which apt-get succeeds", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'")
  })

  it("uses dnf when apt-get is absent but dnf is present", async () => {
    const ssh = createMockSsh({
      ...DNF_FOUND,
      "dnf install -y -- 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("dnf install -y -- 'nginx'")
  })

  it("uses yum when apt-get and dnf are absent but yum is present", async () => {
    const ssh = createMockSsh({
      ...YUM_FOUND,
      "yum install -y -- 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("yum install -y -- 'nginx'")
  })

  it("uses apk when apt-get, dnf and yum are absent but apk is present", async () => {
    // R-0000: apk add now uses the argument terminator `--` to prevent
    // package names starting with `-` from being interpreted as flags.
    const ssh = createMockSsh({
      ...APK_FOUND,
      "apk add -- 'nginx'": { code: 0 },
    })
    const mod = pkg.installed("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("apk add -- 'nginx'")
  })

  it("uses correct remove command for dnf", async () => {
    const ssh = createMockSsh({
      ...DNF_FOUND,
      "dnf remove -y -- 'nginx'": { code: 0 },
      "rpm -q 'nginx'": { code: 0 },
    })
    const mod = pkg.absent("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("dnf remove -y -- 'nginx'")
  })

  it("uses correct remove command for apk", async () => {
    // R-0000: apk del now uses the argument terminator `--`.
    const ssh = createMockSsh({
      ...APK_FOUND,
      "apk del -- 'nginx'": { code: 0 },
      "apk info -e 'nginx'": { code: 0 },
    })
    const mod = pkg.absent("nginx")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("apk del -- 'nginx'")
  })

  it("uses correct update command for dnf (makecache)", async () => {
    const ssh = createMockSsh({
      ...DNF_FOUND,
      "dnf makecache": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-update-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-update-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.update("2024-01-15")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("dnf makecache")
  })

  it("uses correct update command for apk", async () => {
    const ssh = createMockSsh({
      ...APK_FOUND,
      "apk update": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-update-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-update-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.update("2024-01-15")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("apk update")
  })

  it("uses split upgrade pipeline for apk", async () => {
    const ssh = createMockSsh({
      ...APK_FOUND,
      "apk update": { code: 0 },
      "apk upgrade": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'package-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'package-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = pkg.upgrade("2024-01-15")
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("apk update")
    expect(ssh.calls).toContain("apk upgrade")
    expect(ssh.calls).not.toContain("apk update && apk upgrade")
  })
})
