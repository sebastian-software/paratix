import { describe, expect, it, vi } from "vitest"

import { isSystemHostMetaEntry, isSystemRebootMetaEntry } from "../../src/meta.js"
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

  it("returns ok without running the upgrade pipeline when Debian already uses the target codename", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      "curl -fsSL https://deb.debian.org/debian/dists/stable/Release": {
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
      // readFile (output) trims trailing whitespace, so the snapshot is the
      // trimmed content (no trailing newline).
      const originalSources = "deb http://deb.debian.org/debian bookworm main"
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
      // readFile (output) trims trailing whitespace, so the snapshot is the
      // trimmed content (no trailing newline).
      const originalSources = "deb http://deb.debian.org/debian bookworm main"
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
      // readFile (output) trims trailing whitespace, so the snapshot is the
      // trimmed content (no trailing newline).
      const originalSources = "deb http://deb.debian.org/debian bookworm main"
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
      // readFile (output) trims trailing whitespace, so the snapshot is the
      // trimmed content (no trailing newline).
      const originalSources = "deb http://deb.debian.org/debian bookworm main"
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
      // readFile (output) trims trailing whitespace.
      const originalMainSources = "deb http://deb.debian.org/debian bookworm main"
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

    // R-0000103 regression: codename substitution must be anchored at token
    // boundaries so URLs, repository names and other strings that merely
    // contain the codename as a substring are left intact. Only standalone
    // codename occurrences (e.g. the suite field of a `deb` line) may be
    // rewritten.
    it("R-0000103: only replaces standalone codename occurrences, not substring matches", async () => {
      const currentCodename = "trusty"
      const targetCodename = "noble"
      // Mixed content: a real `deb` suite reference (must change), a URL
      // path that contains `trusty` as part of a longer host segment (must
      // NOT change) and a comment line that mentions `trusty-updates` (must
      // also stay intact because the codename is part of a hyphenated
      // token).
      const originalSources = [
        `deb http://archive.ubuntu.com/ubuntu-trusty-updates/ ${currentCodename} main`,
        "# repo backports for trusty-backports stay untouched",
        "deb http://archive.ubuntu.com/ubuntu/ trusty-security main",
      ].join("\n")
      const ssh = createMockSsh({
        "cat '/etc/apt/sources.list'": { code: 0, stdout: originalSources },
        "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
        "curl -fsSL https://deb.debian.org/debian/dists/stable/Release": {
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
      expect(written).toContain(`ubuntu-trusty-updates/ ${targetCodename} main`)

      // Substring occurrences (URL path segment, hyphenated suite tokens
      // and the comment) must remain unchanged.
      expect(written).toContain("ubuntu-trusty-updates/")
      expect(written).toContain("trusty-backports")
      expect(written).toContain("trusty-security")

      // Sanity: the only standalone `trusty` token (the suite field of
      // the first `deb` line) has been rewritten, and the new codename
      // appears as a standalone token. We deliberately use look-behind
      // and look-ahead patterns that reject adjacent word characters,
      // dots and hyphens because JavaScript's `\b` treats `-` as a
      // non-word boundary and would still match `trusty` inside
      // `ubuntu-trusty-updates`.
      const standaloneTrusty = /(?<![\w.\-])trusty(?![\w.\-])/v
      const standaloneNoble = /(?<![\w.\-])noble(?![\w.\-])/v
      expect(standaloneTrusty.test(written)).toBe(false)
      expect(standaloneNoble.test(written)).toBe(true)
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
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
  })
})
