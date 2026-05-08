import { describe, expect, it, vi } from "vitest"

import { isSystemHostMetaEntry, isSystemRebootMetaEntry } from "../../src/meta.js"
import { releaseUpgrade } from "../../src/modules/releaseUpgrade.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: "/etc/apt/sources.list" },
      { options: { mode: "0644" }, remotePath: /^\/etc\/apt\/sources\.list\.d\/.+$/v },
      ...(options?.allowWrites ?? []),
    ],
    // R-0000241: every sources file rewrite issues `stat -c '%a' <path>` to
    // capture the original mode. Default the stat probe to an empty stdout
    // (the rewrite then falls back to the historical 0644 default) unless an
    // individual test stubs it explicitly.
    responseStubs: [
      {
        // eslint-disable-next-line security/detect-unsafe-regex -- Bounded literal pattern matching the well-known apt sources stat command issued by the module under test.
        command: /^stat -c '%a' '\/etc\/apt\/sources\.list(?:\.d\/.+)?'$/v,
        result: { code: 0 },
      },
      ...(options?.responseStubs ?? []),
    ],
  })

// os-release content helpers
const UBUNTU_OS_RELEASE = 'ID=ubuntu\nVERSION_ID="22.04"\n'
const DEBIAN_OS_RELEASE = "ID=debian\nVERSION_CODENAME=bookworm\n"
const UNKNOWN_OS_RELEASE = "ID=arch\n"

// Debian stable codename response from curl
const DEBIAN_STABLE_RELEASE_CURL = "Origin: Debian\nCodename: trixie\nSuite: stable\n"

// Default find response for sources.list.d (empty = no extra files)
const FIND_SOURCES_EMPTY = { code: 0, stdout: "" }

type WriteCapture = { content: string; path: string }

// Helper: build responses for Ubuntu check/apply
function ubuntuResponses(
  upgradeCheckCode: number,
  output = ""
): Record<string, { code?: number; stdout?: string }> {
  return {
    "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
    "do-release-upgrade -c": { code: upgradeCheckCode, stdout: output },
  }
}

// Helper: build full responses for Debian check
function debianCheckResponses(currentCodename: string, stableCodename: string) {
  return {
    "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
    "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
      code: 0,
      stdout: `Origin: Debian\nCodename: ${stableCodename}\nSuite: stable\n`,
    },
    "lsb_release -cs": { code: 0, stdout: `${currentCodename}\n` },
  }
}

// Helper: build full responses for Debian apply (happy path)
function debianApplyResponses(
  currentCodename: string,
  targetCodename: string,
  overrides: Record<string, { code?: number; stderr?: string; stdout?: string }> = {}
) {
  return {
    "[ -e '/etc/apt/sources.list' ]": { code: 0 },
    "cat '/etc/apt/sources.list'": {
      code: 0,
      stdout: `deb http://deb.debian.org/debian ${currentCodename} main\n`,
    },
    "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
    "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
      code: 0,
      stdout: `Origin: Debian\nCodename: ${targetCodename}\nSuite: stable\n`,
    },
    "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
    "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
      FIND_SOURCES_EMPTY,
    "lsb_release -cs": { code: 0, stdout: `${currentCodename}\n` },
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// CHECK phase
// ---------------------------------------------------------------------------

describe("releaseUpgrade.upgrade — check", () => {
  it("Ubuntu: do-release-upgrade -c exits 0 → needs-apply (upgrade available)", async () => {
    const ssh = createMockSsh(ubuntuResponses(0))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("Ubuntu: do-release-upgrade -c reports no new release → ok", async () => {
    const ssh = createMockSsh(ubuntuResponses(1, "No new release found.\n"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("Ubuntu: do-release-upgrade -c execution error → needs-apply", async () => {
    const ssh = createMockSsh(ubuntuResponses(127, "do-release-upgrade: not found\n"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("Debian: current codename differs from stable → needs-apply", async () => {
    const ssh = createMockSsh(debianCheckResponses("bookworm", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("Debian: current codename equals stable → ok", async () => {
    const ssh = createMockSsh(debianCheckResponses("trixie", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("unknown distro → needs-apply", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UNKNOWN_OS_RELEASE },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000239: Ubuntu detected when ID is upper-cased", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: 'ID=Ubuntu\nVERSION_ID="22.04"\n' },
      "do-release-upgrade -c": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).toContain("do-release-upgrade -c")
  })

  it("R-0000239: Debian fork detected via ID_LIKE fallback", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": {
        code: 0,
        stdout: "ID=raspbian\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n",
      },
      "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).toContain("lsb_release -cs")
  })

  it("no SSH connection → needs-apply", async () => {
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ---------------------------------------------------------------------------
// APPLY phase
// ---------------------------------------------------------------------------

describe("releaseUpgrade.upgrade — apply (Ubuntu)", () => {
  it("runs apt-get update + do-release-upgrade and returns changed + reboot meta", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("do-release-upgrade -f DistUpgradeViewNonInteractive")
  })

  it("passes timeout to Ubuntu upgrade commands", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade({ timeout: 900_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(
      ssh.execCalls
        .filter((call) =>
          [
            "DEBIAN_FRONTEND=noninteractive apt-get update",
            "do-release-upgrade -f DistUpgradeViewNonInteractive",
          ].includes(call.command)
        )
        .map((call) => call.options)
    ).toStrictEqual([
      { ignoreExitCode: true, silent: true, timeout: 900_000 },
      { ignoreExitCode: true, silent: true, timeout: 900_000 },
    ])
  })

  it("R-0000184: applies the default 30-minute timeout when none is provided", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    const upgradeCall = ssh.execCalls.find(
      (call) => call.command === "do-release-upgrade -f DistUpgradeViewNonInteractive"
    )
    expect(upgradeCall?.options).toStrictEqual({
      ignoreExitCode: true,
      silent: true,
      timeout: 30 * 60 * 1000,
    })
  })

  it("dryRun: runs only do-release-upgrade -c and returns ok", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "do-release-upgrade -c": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).toContain("do-release-upgrade -c")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).not.toContain("do-release-upgrade -f DistUpgradeViewNonInteractive")
  })

  it("dryRun: passes timeout to do-release-upgrade -c", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "do-release-upgrade -c": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true, timeout: 900_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(
      ssh.execCalls.find((call) => call.command === "do-release-upgrade -c")?.options
    ).toStrictEqual({ ignoreExitCode: true, silent: true, timeout: 900_000 })
  })

  it("dryRun: fails when do-release-upgrade -c execution fails", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "do-release-upgrade -c": { code: 127, stderr: "do-release-upgrade: not found" },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("do-release-upgrade -c failed")
  })

  it("apt-get update fails → failed", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("do-release-upgrade fails → failed", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 1 },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("releaseUpgrade.upgrade — apply (Debian)", () => {
  it("replaces codename in sources.list, runs full-upgrade + autoremove, returns changed + reboot meta", async () => {
    const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get autoremove -y")
  })

  it("passes timeout to Debian upgrade pipeline commands", async () => {
    const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
    const mod = releaseUpgrade.upgrade({ timeout: 1_200_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(
      ssh.execCalls
        .filter((call) =>
          [
            "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y",
            "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y",
            "DEBIAN_FRONTEND=noninteractive apt-get update",
            "DEBIAN_FRONTEND=noninteractive dpkg --configure -a",
          ].includes(call.command)
        )
        .map((call) => call.options)
    ).toStrictEqual([
      { ignoreExitCode: true, silent: true, timeout: 1_200_000 },
      { ignoreExitCode: true, silent: true, timeout: 1_200_000 },
      { ignoreExitCode: true, silent: true, timeout: 1_200_000 },
      { ignoreExitCode: true, silent: true, timeout: 1_200_000 },
    ])
  })

  it("R-0000177: stable codename curl uses --max-time 30", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain(
      "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release"
    )
  })

  it("dryRun: no commands executed after codename lookup, returns ok", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y")
  })

  it("returns ok without running the upgrade pipeline when Debian already uses the target codename", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "trixie\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta).toBeUndefined()
    expect(ssh.calls).not.toContain("cat /etc/apt/sources.list")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y")
  })

  it("fails without rewriting sources when Debian is on testing instead of the stable predecessor", async () => {
    const ssh = createMockSsh(debianApplyResponses("testing", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("unsupported Debian release upgrade path")
    expect(ssh.calls).not.toContain("cat '/etc/apt/sources.list'")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
  })

  it("fails without rewriting sources when Debian is newer than current stable", async () => {
    const ssh = createMockSsh(debianApplyResponses("forky", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("unsupported Debian release upgrade path")
    expect(ssh.calls).not.toContain("cat '/etc/apt/sources.list'")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
  })

  it("apt-get update fails → failed", async () => {
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
      })
    )
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("supports Deb822-only sources when the main sources.list file is missing", async () => {
    const sourcesPath = "/etc/apt/sources.list.d/debian.sources"
    const originalSources = [
      "Types: deb",
      "URIs: https://deb.debian.org/debian",
      "Suites: bookworm bookworm-updates",
      "Components: main",
      "",
    ].join("\n")
    const writes: WriteCapture[] = []
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "[ -e '/etc/apt/sources.list' ]": { code: 1 },
        [`cat '${sourcesPath}'`]: { code: 0, stdout: originalSources },
        "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
          {
            code: 0,
            stdout: `${sourcesPath}\0`,
          },
      })
    )
    ssh.writeFile = async (path, content): Promise<void> => {
      await Promise.resolve()
      writes.push({ content, path })
    }

    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).not.toContain("cat '/etc/apt/sources.list'")
    expect(ssh.calls).toContain(`cat '${sourcesPath}'`)
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    const written = writes.find((write) => write.path === sourcesPath)?.content
    expect(written).toContain("Suites: trixie trixie-updates")
    expect(writes.some((write) => write.path === "/etc/apt/sources.list")).toBe(false)
  })

  it("apt-get full-upgrade fails → failed", async () => {
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 1 },
      })
    )
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apt-get autoremove fails → failed", async () => {
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 1 },
      })
    )
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("Debian: returns failed when dpkg --configure -a fails", async () => {
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 1 },
      })
    )
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("Debian: runs dpkg --configure -a after apt-get update and before apt-get full-upgrade", async () => {
    const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
    const mod = releaseUpgrade.upgrade()
    await mod.apply(ssh, emptyEnv)

    const updateIndex = ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive apt-get update")
    const dpkgIndex = ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    const fullUpgradeIndex = ssh.calls.indexOf(
      "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y"
    )

    expect(updateIndex).toBeGreaterThan(-1)
    expect(dpkgIndex).toBeGreaterThan(-1)
    expect(fullUpgradeIndex).toBeGreaterThan(-1)
    expect(dpkgIndex).toBeGreaterThan(updateIndex)
    expect(dpkgIndex).toBeLessThan(fullUpgradeIndex)
  })

  // R-0000046 regression: a downstream apt failure must roll the rewritten
  // sources files back to the original suite so the host never ends up with
  // sources pointing at the new suite while the upgrade itself failed.
  describe("R-0000046: sources rollback on apt failure", () => {
    const captureWriteFile = (ssh: ReturnType<typeof createMockSsh>): WriteCapture[] => {
      const writes: WriteCapture[] = []
      // eslint-disable-next-line @typescript-eslint/require-await
      const replacement = async (path: string, content: string): Promise<void> => {
        writes.push({ content, path })
      }
      // Override the noop `writeFile` so the test can observe what content
      // (and in which order) was written to disk.
      Object.assign(ssh, { writeFile: replacement })
      return writes
    }

    it("apt-get update fails → restores the original /etc/apt/sources.list content", async () => {
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      // The last write to sources.list must restore the original content,
      // not leave the rewritten "trixie" content on disk.
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites.length).toBeGreaterThan(0)
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
    })

    it("dpkg --configure -a fails → restores the original sources content", async () => {
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 1 },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
    })

    it("apt-get full-upgrade fails → restores the original sources content", async () => {
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 1 },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
    })

    it("apt-get autoremove fails → restores the original sources content", async () => {
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 1 },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
    })

    it("rolls back additional sources.list.d files alongside sources.list", async () => {
      const originalMainSources = "deb http://deb.debian.org/debian bookworm main\n"
      const originalExtraSources = "deb http://example.com/repo bookworm contrib"
      const extraPath = "/etc/apt/sources.list.d/extra.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${extraPath}'`]: { code: 0, stdout: originalExtraSources },
          "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
          // R-0000053: find emits NUL-delimited paths via -print0; the
          // mock returns the path followed by the NUL terminator.
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            {
              code: 0,
              stdout: `${extraPath}\0`,
            },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")

      const mainWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      const extraWrites = writes.filter((w) => w.path === extraPath)
      expect(mainWrites.at(-1)?.content).toBe(originalMainSources)
      expect(extraWrites.at(-1)?.content).toBe(originalExtraSources)
    })

    // R-0000053 regression: a filename with embedded whitespace that comes
    // through find -print0 must be processed end-to-end without splitting
    // on the embedded space. The previous newline-splitting code would
    // pass the path verbatim too, but a path containing a literal newline
    // would be silently truncated. NUL-delimited splitting is robust.
    it("R-0000172: skips paths that escape the sources.list.d directory", async () => {
      // The find pipeline could in principle yield paths outside the
      // expected directory if it were ever swapped for a less constrained
      // command. Defense-in-depth: such paths must be skipped.
      const escapingPath = "/etc/passwd"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${escapingPath}\0` },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(writes.find((w) => w.path === escapingPath)).toBeUndefined()
    })

    it("R-0000172: skips paths containing newlines or NUL-like control chars", async () => {
      // Even when -print0 keeps the NUL boundaries clean, an embedded
      // newline in a filename could still break downstream tooling.
      const cleanPath = "/etc/apt/sources.list.d/clean.list"
      const dirtyPath = "/etc/apt/sources.list.d/with\nnewline.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${cleanPath}'`]: { code: 0, stdout: "deb http://example.com/repo bookworm main" },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${dirtyPath}\0${cleanPath}\0` },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(writes.find((w) => w.path === dirtyPath)).toBeUndefined()
      expect(writes.find((w) => w.path === cleanPath)).toBeDefined()
    })

    // R-0000240 regression: a sources file enumerated by `find -print0` can
    // vanish before the subsequent `readFile`. Such a transient absence must
    // be skipped so the upgrade still proceeds for the remaining files.
    it("R-0000240: skips a sources file that vanishes between find and readFile", async () => {
      const cleanPath = "/etc/apt/sources.list.d/clean.list"
      const vanishedPath = "/etc/apt/sources.list.d/vanished.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${cleanPath}'`]: { code: 0, stdout: "deb http://example.com/repo bookworm main" },
          [`cat '${vanishedPath}'`]: {
            code: 1,
            stderr: `cat: ${vanishedPath}: No such file or directory`,
          },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${vanishedPath}\0${cleanPath}\0` },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(writes.find((w) => w.path === vanishedPath)).toBeUndefined()
      expect(writes.find((w) => w.path === cleanPath)).toBeDefined()
    })

    it("R-0000240: skips the main sources.list when it vanishes between exists and readFile", async () => {
      // The main sources.list is reported by `exists` but the subsequent
      // `cat` fails because the file was removed in between. The upgrade
      // must still complete using the sources.list.d entries instead of
      // aborting on the transient ENOENT.
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "cat '/etc/apt/sources.list'": {
            code: 1,
            stderr: "cat: /etc/apt/sources.list: No such file or directory",
          },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(writes.find((w) => w.path === "/etc/apt/sources.list")).toBeUndefined()
    })

    it("R-0000240: re-throws non-ENOENT readFile errors so they surface to the runner", async () => {
      const protectedPath = "/etc/apt/sources.list.d/protected.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${protectedPath}'`]: { code: 1, stderr: "cat: Permission denied" },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${protectedPath}\0` },
        })
      )
      const mod = releaseUpgrade.upgrade()
      // Permission errors are not transient absences — the upgrade refuses
      // to swallow them and lets the exception propagate so the runner can
      // surface the failure with the original cause attached.
      await expect(mod.apply(ssh, emptyEnv)).rejects.toThrow(/Permission denied/v)
    })

    it("processes a sources.list.d filename containing whitespace via -print0", async () => {
      // readFile (mock output()) trims trailing whitespace.
      const originalExtraSources = "deb http://example.com/repo bookworm main"
      const extraPath = "/etc/apt/sources.list.d/repo with space.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${extraPath}'`]: { code: 0, stdout: originalExtraSources },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            {
              code: 0,
              stdout: `${extraPath}\0`,
            },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      // The file with embedded whitespace must have been rewritten to
      // point at trixie.
      const extraWrites = writes.filter((w) => w.path === extraPath)
      expect(extraWrites).toHaveLength(1)
      expect(extraWrites[0]?.content).toContain("trixie")
      expect(extraWrites[0]?.content).not.toContain("bookworm")
    })

    // R-0000103 regression: codename substitution must be field-aware so URLs,
    // repository names and comments that merely contain the codename as a
    // substring are left intact. Only suite fields of active source entries
    // may be rewritten.
    it("R-0000103: only replaces suite fields, not URL or comment substring matches", async () => {
      const currentCodename = "bookworm"
      const targetCodename = "trixie"
      // Mixed content: real `deb` suite references (must change), a URL path
      // that contains `bookworm` as part of a longer host segment (must NOT
      // change) and a comment line that mentions `bookworm-backports` (must also
      // stay intact because comments are not apt suite fields).
      const originalSources = [
        `deb http://archive.ubuntu.com/ubuntu-bookworm-updates/ ${currentCodename} main`,
        "# repo backports for bookworm-backports stay untouched",
        "deb http://archive.ubuntu.com/ubuntu/ bookworm-security main",
      ].join("\n")
      const ssh = createMockSsh({
        "[ -e '/etc/apt/sources.list' ]": { code: 0 },
        "cat '/etc/apt/sources.list'": { code: 0, stdout: originalSources },
        "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
        "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
          code: 0,
          stdout: `Origin: Debian\nCodename: ${targetCodename}\nSuite: stable\n`,
        },
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
        "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
          FIND_SOURCES_EMPTY,
        "lsb_release -cs": { code: 0, stdout: `${currentCodename}\n` },
      })
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites).toHaveLength(1)
      const written = sourcesWrites[0].content

      // Standalone suite reference is rewritten.
      expect(written).toContain(`ubuntu-bookworm-updates/ ${targetCodename} main`)
      expect(written).toContain(
        `deb http://archive.ubuntu.com/ubuntu/ ${targetCodename}-security main`
      )

      // Substring occurrences outside suite fields (URL path segment and the
      // comment) must remain unchanged.
      expect(written).toContain("ubuntu-bookworm-updates/")
      expect(written).toContain("bookworm-backports")

      // Sanity: the only standalone `bookworm` token (the suite field of the
      // first `deb` line) has been rewritten, and the new codename appears as
      // a standalone token.
      const standaloneBookworm = /(?<![\w.\-])bookworm(?![\w.\-])/v
      const standaloneTrixie = /(?<![\w.\-])trixie(?![\w.\-])/v
      expect(standaloneBookworm.test(written)).toBe(false)
      expect(standaloneTrixie.test(written)).toBe(true)
    })

    it("migrates release-derived suites in active .list source fields", async () => {
      const originalSources = [
        "deb [arch=amd64 signed-by=/usr/share/keyrings/debian.gpg] http://deb.debian.org/debian bookworm main contrib",
        "deb http://deb.debian.org/debian bookworm-updates main",
        "deb-src http://security.debian.org/debian-security bookworm-security main",
        "deb http://deb.debian.org/debian bookworm-backports main",
        "# deb http://deb.debian.org/debian bookworm-updates main",
        "deb http://mirror.example/bookworm-updates bookworm main",
      ].join("\n")
      const ssh = createMockSsh({
        "[ -e '/etc/apt/sources.list' ]": { code: 0 },
        "cat '/etc/apt/sources.list'": { code: 0, stdout: originalSources },
        "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
        "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release": {
          code: 0,
          stdout: "Origin: Debian\nCodename: trixie\nSuite: stable\n",
        },
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
        "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
          FIND_SOURCES_EMPTY,
        "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
      })
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      const written = writes.find((w) => w.path === "/etc/apt/sources.list")?.content
      expect(written).toBe(
        [
          "deb [arch=amd64 signed-by=/usr/share/keyrings/debian.gpg] http://deb.debian.org/debian trixie main contrib",
          "deb http://deb.debian.org/debian trixie-updates main",
          "deb-src http://security.debian.org/debian-security trixie-security main",
          "deb http://deb.debian.org/debian trixie-backports main",
          "# deb http://deb.debian.org/debian bookworm-updates main",
          "deb http://mirror.example/bookworm-updates trixie main",
        ].join("\n")
      )
    })

    it("migrates release-derived suites in deb822 .sources files", async () => {
      const sourcesPath = "/etc/apt/sources.list.d/debian.sources"
      const originalSources = [
        "Types: deb deb-src",
        "URIs: http://deb.debian.org/debian-bookworm",
        "Suites: bookworm bookworm-updates bookworm-security bookworm-backports experimental",
        "Components: main contrib",
      ].join("\n")
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${sourcesPath}'`]: { code: 0, stdout: originalSources },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            {
              code: 0,
              stdout: `${sourcesPath}\0`,
            },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      const written = writes.find((w) => w.path === sourcesPath)?.content
      expect(written).toBe(
        [
          "Types: deb deb-src",
          "URIs: http://deb.debian.org/debian-bookworm",
          "Suites: trixie trixie-updates trixie-security trixie-backports experimental",
          "Components: main contrib",
        ].join("\n")
      )
    })

    it("does not roll back when the upgrade pipeline succeeds", async () => {
      const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      // The only write to sources.list is the rewrite to "trixie" — no
      // rollback restore happens on the success path.
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      expect(sourcesWrites).toHaveLength(1)
      expect(sourcesWrites[0]?.content).toContain("trixie")
    })

    // R-0000241: the snapshot must capture the original mode so a rollback
    // restores the operator's exact permissions instead of forcing 0644.
    it("R-0000241: rollback restores the operator-specified mode of /etc/apt/sources.list", async () => {
      type ModeWriteCapture = { content: string; mode: string | undefined; path: string }
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
          "stat -c '%a' '/etc/apt/sources.list'": { code: 0, stdout: "640\n" },
        })
      )
      const writes: ModeWriteCapture[] = []
      const replacement = async (
        path: string,
        content: string,
        writeOptions?: { mode?: string }
      ): Promise<void> => {
        writes.push({ content, mode: writeOptions?.mode, path })
        await Promise.resolve()
      }
      Object.assign(ssh, { writeFile: replacement })

      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      // The last write to sources.list is the rollback. It must restore the
      // captured 0640 mode rather than overwriting it with the 0644 default.
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
      expect(sourcesWrites.at(-1)?.mode).toBe("0640")
    })
  })
})

describe("releaseUpgrade.upgrade — apply (general)", () => {
  it("no SSH connection → failed", async () => {
    const mod = releaseUpgrade.upgrade()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("unknown distro → failed", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UNKNOWN_OS_RELEASE },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("resolveHost is called and meta contains system.host", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const resolveHost = vi.fn().mockResolvedValue("10.0.0.99")
    const mod = releaseUpgrade.upgrade({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(resolveHost).toHaveBeenCalledOnce()
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("10.0.0.99")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("returns failed when resolveHost fails", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const resolveHost = vi.fn().mockRejectedValue(new Error("DNS timeout"))
    const mod = releaseUpgrade.upgrade({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[releaseUpgrade.upgrade] resolveHost failed")
    expect(result.error?.message).toContain("DNS timeout")
    expect(result.meta).toBeUndefined()
  })

  // R-0000243: a hanging resolver must not stall the playbook indefinitely.
  it("R-0000243: returns failed when resolveHost exceeds the configured timeout", async () => {
    vi.useFakeTimers()
    try {
      const ssh = createMockSsh({
        "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
      })
      const resolveHost = vi.fn().mockReturnValue(
        new Promise<string>(() => {
          // never settles
        })
      )
      const mod = releaseUpgrade.upgrade({ resolveHost, resolveHostTimeoutMs: 25 })
      const promise = mod.apply(ssh, emptyEnv)
      await vi.advanceTimersByTimeAsync(25)
      const result = await promise
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("[releaseUpgrade.upgrade] resolveHost failed")
      expect(result.error?.message).toContain("timed out after 25ms")
      expect(result.meta).toBeUndefined()
    } finally {
      vi.useRealTimers()
    }
  })
})
