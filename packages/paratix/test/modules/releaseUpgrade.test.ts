import { describe, expect, it, vi } from "vitest"

import { releaseUpgrade } from "../../src/modules/releaseUpgrade.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

// os-release content helpers
const UBUNTU_OS_RELEASE = 'ID=ubuntu\nVERSION_ID="22.04"\n'
const DEBIAN_OS_RELEASE = "ID=debian\nVERSION_CODENAME=bookworm\n"
const UNKNOWN_OS_RELEASE = "ID=arch\n"

// Debian stable codename response from curl
const DEBIAN_STABLE_RELEASE_CURL = "Origin: Debian\nCodename: trixie\nSuite: stable\n"

// Default find response for sources.list.d (empty = no extra files)
const FIND_SOURCES_EMPTY = { code: 0, stdout: "" }

// Helper: build responses for Ubuntu check/apply
function ubuntuResponses(
  upgradeCheckCode: number
): Record<string, { code?: number; stdout?: string }> {
  return {
    "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
    "do-release-upgrade -c": { code: upgradeCheckCode },
  }
}

// Helper: build full responses for Debian check
function debianCheckResponses(currentCodename: string, stableCodename: string) {
  return {
    "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
    "curl -fsSL https://deb.debian.org/debian/dists/stable/Release": {
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
  overrides: Record<string, { code?: number; stdout?: string }> = {}
) {
  return {
    "cat '/etc/apt/sources.list'": {
      code: 0,
      stdout: `deb http://deb.debian.org/debian ${currentCodename} main\n`,
    },
    "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
    "curl -fsSL https://deb.debian.org/debian/dists/stable/Release": {
      code: 0,
      stdout: `Origin: Debian\nCodename: ${targetCodename}\nSuite: stable\n`,
    },
    "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
    "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f":
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

  it("Ubuntu: do-release-upgrade -c exits non-0 → ok (no upgrade)", async () => {
    const ssh = createMockSsh(ubuntuResponses(1))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
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
    expect(result.meta?.["system.reboot"]).toBe("true")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("do-release-upgrade -f DistUpgradeViewNonInteractive")
  })

  it("dryRun: runs only do-release-upgrade -c and returns ok", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -c": { code: 0 },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).toContain("do-release-upgrade -c")
    expect(ssh.calls).not.toContain("do-release-upgrade -f DistUpgradeViewNonInteractive")
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
    expect(result.meta?.["system.reboot"]).toBe("true")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get autoremove -y")
  })

  it("dryRun: no commands executed after codename lookup, returns ok", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      "curl -fsSL https://deb.debian.org/debian/dists/stable/Release": {
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
    expect(result.meta?.["system.host"]).toBe("10.0.0.99")
    expect(result.meta?.["system.reboot"]).toBe("true")
  })

  it("resolveHost fails → meta without system.host, upgrade still succeeds", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: UBUNTU_OS_RELEASE },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "do-release-upgrade -f DistUpgradeViewNonInteractive": { code: 0 },
    })
    const resolveHost = vi.fn().mockRejectedValue(new Error("DNS timeout"))
    const mod = releaseUpgrade.upgrade({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.["system.reboot"]).toBe("true")
    expect(result.meta).not.toHaveProperty("system.host")
  })
})
