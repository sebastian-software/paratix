/* eslint-disable no-template-curly-in-string -- Shell dpkg-query format strings, not JS templates */
import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { detectPackageManager, pkg } from "../../src/modules/package.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

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

function makePackageManagerAppearsExec(ssh: MockSsh): {
  exec: MockSsh["exec"]
  setAptAvailable: () => void
} {
  let aptAvailable = false
  const recordProbe = (command: string, options?: ExecOptions) => {
    ssh.calls.push(command)
    ssh.execCalls.push({ command, options })
  }
  return {
    async exec(command, options) {
      await Promise.resolve()
      recordProbe(command, options)
      return {
        code: command === "which apt-get" && aptAvailable ? 0 : 1,
        stderr: "",
        stdout: "",
      }
    },
    setAptAvailable() {
      aptAvailable = true
    },
  }
}

function makeOneShotTransportFailureExec(ssh: MockSsh): MockSsh["exec"] {
  let transportFailurePending = true
  const transportError = new Error("SSH transport failed")
  return async (command, options) => {
    await Promise.resolve()
    ssh.calls.push(command)
    ssh.execCalls.push({ command, options })
    if (transportFailurePending) {
      transportFailurePending = false
      throw transportError
    }
    return { code: command === "which apt-get" ? 0 : 1, stderr: "", stdout: "" }
  }
}

// `await Promise.resolve()` in each branch satisfies @typescript-eslint/require-await
// and yields once to the microtask queue, matching the original mocks' timing.

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
      if (!tracked.has(command)) return originalTest(command)
      await Promise.resolve()
      ssh.calls.push(command)
      return installExecuted
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
    ssh.calls.push(missingCommand)
    consumed = true
    return false
  }
  return async (command) => {
    if (command !== missingCommand) return originalTest(command)
    if (!consumed) return reportMissingOnce()
    await Promise.resolve()
    ssh.calls.push(command)
    return true
  }
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
// Helpers: version-pinning mocks
//
// These encapsulate the "reports version A before install, version B after"
// branching outside the it() bodies (eslint-plugin-vitest forbids conditionals
// in tests). Each helper installs an exec()/output() override that flips a
// single boolean once the given install/downgrade command has executed.
// ---------------------------------------------------------------------------

// Build exec()/output() overrides so `queryCommand` yields `before` until
// `installCommand` has run via exec(), then `after`. The install command and
// its options are recorded. Returns the overrides for the test body to assign
// (assigning inside the helper would trip `no-param-reassign`).
function makeVersionOutputOverride(
  ssh: MockSsh,
  parameters: {
    after: string
    before: string
    installCommand: string
    queryCommand: string
  }
): { exec: MockSsh["exec"]; output: MockSsh["output"] } {
  const { after, before, installCommand, queryCommand } = parameters
  const originalOutput = ssh.output.bind(ssh)
  const originalExec = ssh.exec.bind(ssh)
  let installed = false
  return {
    async exec(command, options) {
      if (command !== installCommand) return originalExec(command, options)
      installed = true
      ssh.calls.push(command)
      ssh.execCalls.push({ command, options })
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "" }
    },
    async output(command) {
      if (command !== queryCommand) return originalOutput(command)
      await Promise.resolve()
      ssh.calls.push(command)
      return installed ? after : before
    },
  }
}

// Build an exec() override so the rpm `queryCommand` reports `before` (as
// stdout) until `mutatingCommand` has executed, then `after`. Models both the
// install and the downgrade direction for dnf/yum. Returns the override for the
// test body to assign.
function makeRpmVersionExecOverride(
  ssh: MockSsh,
  parameters: {
    after: string
    before: string
    mutatingCommand: string
    queryCommand: string
  }
): MockSsh["exec"] {
  const { after, before, mutatingCommand, queryCommand } = parameters
  const originalExec = ssh.exec.bind(ssh)
  let mutated = false
  const respond = async (command: string, options: ExecOptions | undefined, stdout: string) => {
    ssh.calls.push(command)
    ssh.execCalls.push({ command, options })
    await Promise.resolve()
    return { code: 0, stderr: "", stdout }
  }
  return async (command, options) => {
    if (command === queryCommand) return respond(command, options, mutated ? after : before)
    if (command === mutatingCommand) {
      mutated = true
      return respond(command, options, "")
    }
    return originalExec(command, options)
  }
}

// Build the exact `sort -V` version-comparison command that
// `collectDowngradeTokens` issues via ssh.test to decide the dnf/yum direction.
// `installed` is the version reported by rpm, `pinned` the requested version.
function sortVCommand(installed: string, pinned: string): string {
  return `test "$(printf '%s\\n%s\\n' '${pinned}' '${installed}' | sort -V | tail -n1)" = '${installed}'`
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
    const ssh = createMockSsh({
      ...APT_FOUND,
    })
    // Override exec()/test() so that tracked probes report "missing" until the
    // install command has run, then report "installed" explicitly.
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
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'texlive-full'": { code: 0 },
    })
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
    const dpkgNginx =
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'": { code: 0 },
    })
    ssh.test = makeOneShotMissingTest(ssh, dpkgNginx)
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
    const dpkgNginx =
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'": { code: 1 },
      [dpkgNginx]: { code: 1 },
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

  // R-0000812: a bare string that looks like PM syntax is NOT parsed into a
  // pinned version — it stays an invalid package name.
  it("does not silently parse a bare name=version string", () => {
    expect(() => pkg.installed("grafana=13.1.0")).toThrow("invalid package name")
  })
})

// ---------------------------------------------------------------------------
// pkg.installed — version pinning
// ---------------------------------------------------------------------------

describe("pkg.installed version pinning", () => {
  // token construction / no throw

  it("accepts a PackageSpec with a version without throwing", () => {
    expect(() => pkg.installed({ name: "grafana", version: "13.1.0" })).not.toThrow()
  })

  it("builds name=version token for apt", async () => {
    const installCommand =
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -- 'grafana=13.1.0'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg --compare-versions '13.1.0' eq '13.1.0'": { code: 0 },
    })
    const aptOverride = makeVersionOutputOverride(ssh, {
      after: "13.1.0",
      before: "",
      installCommand,
      queryCommand: "dpkg-query -W -f='${Version}' 'grafana' 2>/dev/null",
    })
    ssh.exec = aptOverride.exec
    ssh.output = aptOverride.output
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("builds name-version token for dnf", async () => {
    const installCommand = "dnf install -y -- 'grafana-13.1.0-1.el9'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      // Installed 12.0.0-1.el9 is NOT higher than pinned 13.1.0-1.el9 → install.
      [sortVCommand("12.0.0-1.el9", "13.1.0-1.el9")]: { code: 1 },
    })
    ssh.exec = makeRpmVersionExecOverride(ssh, {
      after: "13.1.0-1.el9",
      before: "12.0.0-1.el9",
      mutatingCommand: installCommand,
      queryCommand: "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'",
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0-1.el9" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("builds name=version token for apk", async () => {
    const installCommand = "apk add -- 'grafana=13.1.0-r0'"
    const ssh = createMockSsh({ ...APK_FOUND })
    const apkOverride = makeVersionOutputOverride(ssh, {
      after: "grafana-13.1.0-r0 = 13.1.0-r0",
      before: "",
      installCommand,
      queryCommand: "apk version -v 'grafana'",
    })
    ssh.exec = apkOverride.exec
    ssh.output = apkOverride.output
    const mod = pkg.installed({ name: "grafana", version: "13.1.0-r0" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  // check semantics

  it("check returns ok when the pinned version is installed (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg --compare-versions '13.1.0' eq '13.1.0'": { code: 0 },
      "dpkg-query -W -f='${Version}' 'grafana' 2>/dev/null": { code: 0, stdout: "13.1.0" },
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply on version drift (apt)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg --compare-versions '12.0.0' eq '13.1.0'": { code: 1 },
      "dpkg-query -W -f='${Version}' 'grafana' 2>/dev/null": { code: 0, stdout: "12.0.0" },
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when a pinned package is absent (dnf)", async () => {
    const ssh = createMockSsh({
      ...DNF_FOUND,
      "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'": { code: 1, stdout: "" },
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0-1.el9" })
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check ignores version for a bare name (presence only)", async () => {
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'": {
        code: 0,
      },
    })
    const mod = pkg.installed("nginx")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  // downgrade paths

  it("apply uses --allow-downgrades for apt when a version is pinned", async () => {
    const installCommand =
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -- 'grafana=13.1.0'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      "dpkg --compare-versions '13.1.0' eq '13.1.0'": { code: 0 },
      // Pre-install drift check: installed 14.0.0 != pinned 13.1.0.
      "dpkg --compare-versions '14.0.0' eq '13.1.0'": { code: 1 },
    })
    const aptOverride = makeVersionOutputOverride(ssh, {
      after: "13.1.0",
      before: "14.0.0",
      installCommand,
      queryCommand: "dpkg-query -W -f='${Version}' 'grafana' 2>/dev/null",
    })
    ssh.exec = aptOverride.exec
    ssh.output = aptOverride.output
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("apply uses dnf downgrade when installed version is higher", async () => {
    const downgradeCommand = "dnf downgrade -y -- 'grafana-13.1.0'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      // Installed 14.0.0 IS higher than pinned 13.1.0 → downgrade.
      [sortVCommand("14.0.0", "13.1.0")]: { code: 0 },
    })
    // Installed 14.0.0 initially (higher → downgrade), then 13.1.0.
    ssh.exec = makeRpmVersionExecOverride(ssh, {
      after: "13.1.0",
      before: "14.0.0",
      mutatingCommand: downgradeCommand,
      queryCommand: "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'",
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(downgradeCommand)
    expect(ssh.calls).not.toContain("dnf install -y -- 'grafana-13.1.0'")
  })

  it("apply uses dnf install (not downgrade) when installed version is lower", async () => {
    const installCommand = "dnf install -y -- 'grafana-13.1.0'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      // Installed 12.0.0 is NOT higher than pinned 13.1.0 → install.
      [sortVCommand("12.0.0", "13.1.0")]: { code: 1 },
    })
    ssh.exec = makeRpmVersionExecOverride(ssh, {
      after: "13.1.0",
      before: "12.0.0",
      mutatingCommand: installCommand,
      queryCommand: "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'",
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
    expect(ssh.calls).not.toContain("dnf downgrade -y -- 'grafana-13.1.0'")
  })

  // Regression: multi-digit version components must compare version-aware, not
  // lexicographically. `"13.9.0" > "13.10.0"` is true in JS but wrong.

  it("apply uses dnf install for a multi-digit upgrade 13.9.0 -> 13.10.0", async () => {
    const installCommand = "dnf install -y -- 'grafana-13.10.0-1'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      // 13.9.0-1 is NOT higher than 13.10.0-1 → install (a lexical compare would
      // wrongly pick downgrade here).
      [sortVCommand("13.9.0-1", "13.10.0-1")]: { code: 1 },
    })
    ssh.exec = makeRpmVersionExecOverride(ssh, {
      after: "13.10.0-1",
      before: "13.9.0-1",
      mutatingCommand: installCommand,
      queryCommand: "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'",
    })
    const mod = pkg.installed({ name: "grafana", version: "13.10.0-1" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
    expect(ssh.calls).not.toContain("dnf downgrade -y -- 'grafana-13.10.0-1'")
  })

  it("apply uses dnf downgrade for a multi-digit downgrade 13.10.0 -> 13.9.0", async () => {
    const downgradeCommand = "dnf downgrade -y -- 'grafana-13.9.0-1'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      // 13.10.0-1 IS higher than 13.9.0-1 → downgrade (a lexical compare would
      // wrongly pick install here).
      [sortVCommand("13.10.0-1", "13.9.0-1")]: { code: 0 },
    })
    ssh.exec = makeRpmVersionExecOverride(ssh, {
      after: "13.9.0-1",
      before: "13.10.0-1",
      mutatingCommand: downgradeCommand,
      queryCommand: "rpm -q --qf '%{VERSION}-%{RELEASE}' 'grafana'",
    })
    const mod = pkg.installed({ name: "grafana", version: "13.9.0-1" })
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(downgradeCommand)
    expect(ssh.calls).not.toContain("dnf install -y -- 'grafana-13.9.0-1'")
  })

  // post-install verification

  it("apply fails when the wrong version remains after install (apt)", async () => {
    const dpkg = "dpkg-query -W -f='${Version}' 'grafana' 2>/dev/null"
    const installCommand =
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -- 'grafana=13.1.0'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      // ssh.output default returns "" for unstubbed; stub the version query so
      // it always reports the (wrong) installed version 12.0.0.
      [dpkg]: { code: 0, stdout: "12.0.0" },
      // The installed version never matches the pin.
      "dpkg --compare-versions '12.0.0' eq '13.1.0'": { code: 1 },
      [installCommand]: { code: 0 },
    })
    const mod = pkg.installed({ name: "grafana", version: "13.1.0" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("packages still missing after install: grafana")
  })

  // mixed call

  it("handles a mixed call: bare name, pinned spec and trailing options", () => {
    const mod = pkg.installed("curl", { name: "grafana", version: "13.1.0" }, { timeout: 600_000 })
    expect(mod.name).toBe("package.installed: curl, grafana=13.1.0")
  })

  it("keeps a PackageSpec as the last argument (not treated as options)", () => {
    const mod = pkg.installed("curl", { name: "grafana", version: "13.1.0" })
    expect(mod.name).toBe("package.installed: curl, grafana=13.1.0")
  })

  // version validation

  it.each(["", " ", "1.0 2.0", "1.0;rm", "1.0\n2", "=1.0", "-1.0", "$(x)"])(
    "throws for invalid version %j",
    (version) => {
      expect(() => pkg.installed({ name: "grafana", version })).toThrow("invalid package version")
    }
  )

  it.each(["13.1.0", "1:2.3-1ubuntu0.2", "13.1.0-1.el9", "2.3.4~beta1", "1.0_2"])(
    "accepts valid version %j",
    (version) => {
      expect(() => pkg.installed({ name: "grafana", version })).not.toThrow()
    }
  )

  it("throws on conflicting versions for the same package in one call", () => {
    expect(() =>
      pkg.installed({ name: "grafana", version: "13.1.0" }, { name: "grafana", version: "12.0.0" })
    ).toThrow("conflicting versions")
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

  // R-0000812: version pinning is meaningless for removal and must be rejected
  // rather than silently ignored.
  it("throws when a PackageSpec with a version is passed", () => {
    expect(() => pkg.absent({ name: "grafana", version: "13.1.0" })).toThrow(
      "version pinning is not supported"
    )
  })

  it("accepts a PackageSpec without a version", () => {
    const mod = pkg.absent({ name: "nginx" })
    expect(mod.name).toBe("package.absent: nginx")
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
      [FLAG]: { code: 1 },
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
      [FLAG]: { code: 1 },
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
    const ssh = createMockSsh({ ...NO_PM, [FLAG]: { code: 1 } })
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
      [FLAG]: { code: 1 },
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
      [FLAG]: { code: 1 },
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
      "[ -f /var/lib/paratix/flags/'package-upgrade-2026-05-01' ]": { code: 1 },
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
      [FLAG]: { code: 1 },
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
      [FLAG]: { code: 1 },
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
    const dpkgNginx =
      "dpkg-query -W -f='${Status}' 'nginx' 2>/dev/null | grep -q 'install ok installed'"
    const installCommand = "DEBIAN_FRONTEND=noninteractive apt-get install -y -- 'nginx'"
    const ssh = createMockSsh({
      ...APT_FOUND,
      [dpkgNginx]: { code: 0 },
    })
    const overrides = makeInstallTrackingOverrides(ssh, installCommand, [dpkgNginx])
    ssh.exec = overrides.exec
    ssh.test = overrides.test
    const mod = pkg.installed("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("retries detection after no package manager was found", async () => {
    const ssh = createMockSsh()
    const managerProbe = makePackageManagerAppearsExec(ssh)
    ssh.exec = managerProbe.exec

    await expect(detectPackageManager(ssh)).resolves.toBeNull()
    managerProbe.setAptAvailable()
    await expect(detectPackageManager(ssh)).resolves.toBe("apt")
    await expect(detectPackageManager(ssh)).resolves.toBe("apt")

    expect(ssh.calls).toStrictEqual([
      "which apt-get",
      "which dnf",
      "which yum",
      "which apk",
      "which apt-get",
    ])
    expect(ssh.execCalls.map((call) => call.command)).toStrictEqual(ssh.calls)
    expect(ssh.execCalls.filter((call) => call.command === "which apt-get")).toHaveLength(2)
    expect(ssh.execCalls.every((call) => call.options?.ignoreExitCode === true)).toBe(true)
  })

  it("retries detection after an ssh transport failure", async () => {
    const ssh = createMockSsh()
    ssh.exec = makeOneShotTransportFailureExec(ssh)

    await expect(detectPackageManager(ssh)).rejects.toThrow("SSH transport failed")
    await expect(detectPackageManager(ssh)).resolves.toBe("apt")
    await expect(detectPackageManager(ssh)).resolves.toBe("apt")

    expect(ssh.calls).toStrictEqual(["which apt-get", "which apt-get"])
    expect(ssh.execCalls.map((call) => call.command)).toStrictEqual(ssh.calls)
    expect(ssh.execCalls.every((call) => call.options?.ignoreExitCode === true)).toBe(true)
  })

  it("uses dnf when apt-get is absent but dnf is present", async () => {
    const rpmNginx = "rpm -q 'nginx'"
    const installCommand = "dnf install -y -- 'nginx'"
    const ssh = createMockSsh({
      ...DNF_FOUND,
      [rpmNginx]: { code: 0 },
    })
    const overrides = makeInstallTrackingOverrides(ssh, installCommand, [rpmNginx])
    ssh.exec = overrides.exec
    ssh.test = overrides.test
    const mod = pkg.installed("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("uses yum when apt-get and dnf are absent but yum is present", async () => {
    const rpmNginx = "rpm -q 'nginx'"
    const installCommand = "yum install -y -- 'nginx'"
    const ssh = createMockSsh({
      ...YUM_FOUND,
      [rpmNginx]: { code: 0 },
    })
    const overrides = makeInstallTrackingOverrides(ssh, installCommand, [rpmNginx])
    ssh.exec = overrides.exec
    ssh.test = overrides.test
    const mod = pkg.installed("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
  })

  it("uses apk when apt-get, dnf and yum are absent but apk is present", async () => {
    // R-0000: apk add now uses the argument terminator `--` to prevent
    // package names starting with `-` from being interpreted as flags.
    const apkNginx = "apk info -e 'nginx'"
    const installCommand = "apk add -- 'nginx'"
    const ssh = createMockSsh({
      ...APK_FOUND,
      [apkNginx]: { code: 0 },
    })
    const overrides = makeInstallTrackingOverrides(ssh, installCommand, [apkNginx])
    ssh.exec = overrides.exec
    ssh.test = overrides.test
    const mod = pkg.installed("nginx")
    expect(await mod.apply(ssh, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(installCommand)
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
      "[ -f /var/lib/paratix/flags/'package-update-2024-01-15' ]": { code: 1 },
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
      "[ -f /var/lib/paratix/flags/'package-update-2024-01-15' ]": { code: 1 },
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
      "[ -f /var/lib/paratix/flags/'package-upgrade-2024-01-15' ]": { code: 1 },
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
