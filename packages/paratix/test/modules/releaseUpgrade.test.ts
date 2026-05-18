import { describe, expect, it, vi } from "vitest"

import type { ExecResult } from "../../src/types.js"

import { isSystemHostMetaEntry, isSystemRebootMetaEntry } from "../../src/meta.js"
import { releaseUpgrade } from "../../src/modules/releaseUpgrade.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import { makeIsVerifiedReleaseCall } from "../helpers/mockSshFlagLock.js"

const emptyEnv = {}

// R-0000629: the production code now reads sources files via a single
// shell statement that combines the `[ -L ]` symlink guard with
// `dd … iflag=nofollow` to close the find/read TOCTOU window. The test
// stubs continue to be expressed as `cat '<path>': { stdout }` for
// readability and rewriting effort — this helper duplicates each such
// `cat` stub under the new dd-shaped key so existing tests keep matching
// without rewriting every response map. ENOENT-shaped failures (exit code
// non-zero) are mapped to dd's typical stderr so the production code's
// vanished-file detection (which goes through wrapMissingSourcesFileError)
// recognises them just as it would have for cat.
const CAT_SOURCES_PREFIX = "cat '"
function ddNoFollowCommandFor(quotedPath: string): string {
  return `{ if [ -L ${quotedPath} ]; then exit 200; fi; dd if=${quotedPath} iflag=nofollow status=none; }`
}

function ddStderrFor(catStderr: string, quotedPath: string): string {
  if (catStderr.length === 0) return ""
  return catStderr.replace(/^cat: /v, `dd: failed to open ${quotedPath}: `)
}

function bridgeCatSourcesStubsToDdNoFollow(
  responses: Record<string, Partial<ExecResult>> | undefined
): Record<string, Partial<ExecResult>> | undefined {
  if (!responses) return responses
  const bridged: Record<string, Partial<ExecResult>> = { ...responses }
  for (const [command, result] of Object.entries(responses)) {
    if (!command.startsWith(CAT_SOURCES_PREFIX)) continue
    const quotedPath = command.slice("cat ".length)
    const ddCommand = ddNoFollowCommandFor(quotedPath)
    if (ddCommand in bridged) continue
    bridged[ddCommand] = {
      code: result.code,
      stderr: ddStderrFor(result.stderr ?? "", quotedPath),
      stdout: result.stdout,
    }
  }
  return bridged
}

// R-0000718: pattern that matches the NOFOLLOW write pipeline emitted by
// `writeSourcesFileNoFollow` from the production module. Tests stub the
// pipeline to succeed by default; the capture helper intercepts the
// pipeline to record the new content for assertions.
const NOFOLLOW_WRITE_COMMAND_PATTERN =
  // eslint-disable-next-line security/detect-unsafe-regex -- Bounded literal pattern matching the well-known apt sources write command issued by the module under test.
  /^set -eu; \[ ! -L '(?<path>\/etc\/apt\/sources\.list(?:\.d\/[^']+)?)' \] \|\| exit 201; dd if=\/dev\/stdin of='\/etc\/apt\/sources\.list(?:\.d\/[^']+)?' conv=notrunc oflag=nofollow status=none; truncate -s \d+ '\/etc\/apt\/sources\.list(?:\.d\/[^']+)?'; chmod '(?<mode>[0-7]+)' '\/etc\/apt\/sources\.list(?:\.d\/[^']+)?' \|\| exit 202$/v

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(bridgeCatSourcesStubsToDdNoFollow(responses), {
    ...options,
    allowFlagLockInternalDefaults: true,
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
      // R-0000718: default the NOFOLLOW write pipeline to success so
      // existing tests that previously stubbed `ssh.writeFile` to succeed
      // continue to work. Tests that need to simulate a write failure
      // override the response via `responseStubs` or `installSequencedExec`.
      {
        command: NOFOLLOW_WRITE_COMMAND_PATTERN,
        result: { code: 0 },
      },
      ...(options?.responseStubs ?? []),
    ],
  })

// R-0000629: shorthand to build the dd-shaped read command for a given
// path so assertions can check both the legacy `cat` form is absent and
// the new fused-statement form is present (or absent). The quoting must
// match `shellQuote` from src/ssh.ts as used by the production code.
function readSourcesCommand(path: string): string {
  return `{ if [ -L '${path}' ]; then exit 200; fi; dd if='${path}' iflag=nofollow status=none; }`
}

// R-0000634: release is now a single shell statement (ownership check +
// marker removal + rmdir); recognise it via the shared helper so tests no
// longer reference the legacy standalone `rmdir` call.
const isReleaseUpgradeVerifiedRelease = makeIsVerifiedReleaseCall("release-upgrade-mutex")

// os-release content helpers
const UBUNTU_OS_RELEASE = 'ID=ubuntu\nVERSION_ID="22.04"\n'
const DEBIAN_OS_RELEASE = "ID=debian\nVERSION_CODENAME=bookworm\n"
const UNKNOWN_OS_RELEASE = "ID=arch\n"

// R-0000716: the production code now fetches the signed `InRelease` file
// and verifies it with `gpgv` against the Debian archive keyring. The
// pipeline runs as a single shell statement that mirrors
// `buildDebianInReleaseFetchAndVerifyCommand` from the production module.
// Tests stub the command verbatim and return a cleartext PGP-signed body so
// the production code's `parseDebianStableCodenameFromInRelease` can extract
// the codename.
const DEBIAN_INRELEASE_VERIFY_COMMAND =
  "set -eu; tmpdir=$(mktemp -d -t paratix-inrelease.XXXXXX); trap 'rm -rf -- \"$tmpdir\"' EXIT; [ -r '/usr/share/keyrings/debian-archive-keyring.gpg' ] || exit 11; curl --max-time 30 -fsSL 'https://deb.debian.org/debian/dists/stable/InRelease' -o \"$tmpdir/InRelease\" || exit 10; gpgv --keyring '/usr/share/keyrings/debian-archive-keyring.gpg' \"$tmpdir/InRelease\" >/dev/null 2>&1 || exit 12; cat -- \"$tmpdir/InRelease\""

function debianInReleaseClearsignedBody(codename: string): string {
  return [
    "-----BEGIN PGP SIGNED MESSAGE-----",
    "Hash: SHA256",
    "",
    "Origin: Debian",
    `Codename: ${codename}`,
    "Suite: stable",
    "-----BEGIN PGP SIGNATURE-----",
    "",
    "ABCDEF",
    "-----END PGP SIGNATURE-----",
    "",
  ].join("\n")
}

// Debian stable codename response from curl
const DEBIAN_STABLE_RELEASE_CURL = debianInReleaseClearsignedBody("trixie")
const APT_UPDATE_COMMAND = "DEBIAN_FRONTEND=noninteractive apt-get update"

// Default find response for sources.list.d (empty = no extra files)
const FIND_SOURCES_EMPTY = { code: 0, stdout: "" }

type WriteCapture = { content: string; path: string }

function installSequencedExec(
  ssh: ReturnType<typeof createMockSsh>,
  command: string,
  responses: Array<Partial<ExecResult>>
): { callCount: () => number } {
  const originalExec = ssh.exec.bind(ssh)
  let calls = 0
  const exec: typeof ssh.exec = async (nextCommand, options) => {
    if (nextCommand !== command) return originalExec(nextCommand, options)
    ssh.calls.push(nextCommand)
    ssh.execCalls.push({ command: nextCommand, options })
    const response = responses[calls] ?? responses.at(-1)!
    calls += 1
    return {
      code: response.code ?? 0,
      stderr: response.stderr ?? "",
      stdout: response.stdout ?? "",
    }
  }
  Object.assign(ssh, { exec })
  return { callCount: () => calls }
}

function installSequencedOutput(
  ssh: ReturnType<typeof createMockSsh>,
  command: string,
  outputs: string[]
): { callCount: () => number } {
  const originalOutput = ssh.output.bind(ssh)
  let calls = 0
  const output: typeof ssh.output = async (nextCommand) => {
    if (nextCommand !== command) return originalOutput(nextCommand)
    const response = outputs[calls] ?? outputs.at(-1)!
    calls += 1
    return response
  }
  Object.assign(ssh, { output })
  return { callCount: () => calls }
}

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
    [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
      code: 0,
      stdout: debianInReleaseClearsignedBody(stableCodename),
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
    [APT_UPDATE_COMMAND]: { code: 0 },
    "cat '/etc/apt/sources.list'": {
      code: 0,
      stdout: `deb http://deb.debian.org/debian ${currentCodename} main\n`,
    },
    "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
    "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
    "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
    [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
      code: 0,
      stdout: debianInReleaseClearsignedBody(targetCodename),
    },
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

  it("does not treat Debian derivatives from ID_LIKE as supported Debian hosts", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": {
        code: 0,
        stdout: "ID=raspbian\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n",
      },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("lsb_release -cs")
    expect(ssh.calls).not.toContain(DEBIAN_INRELEASE_VERIFY_COMMAND)
  })

  it("fails apply for Debian derivatives that only declare Debian via ID_LIKE", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": {
        code: 0,
        stdout: "ID=raspbian\nID_LIKE=debian\nVERSION_CODENAME=bookworm\n",
      },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("Unsupported distribution")
    expect(ssh.calls).not.toContain("lsb_release -cs")
  })

  it("no SSH connection → needs-apply", async () => {
    const mod = releaseUpgrade.upgrade()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000715: the codename allowlist now lives inside
  // `getDebianStableCodename`, which is called from both `check` and
  // `apply`. The previous flow only ran the allowlist inside `applyDebian`,
  // so a TLS-MITM substituting an unstable codename slipped past `check`
  // and only failed at apply. `check` must now report `needs-apply` for
  // any non-allowlisted codename so the playbook re-evaluates the situation
  // (and apply surfaces the structured `failed(...)` ModuleResult) on the
  // next pass.
  it.each(["sid", "experimental", "forky", "rcbuggy"])(
    "R-0000715: check returns needs-apply when mirrors advertise non-allowlisted codename '%s'",
    async (maliciousCodename) => {
      const ssh = createMockSsh(debianCheckResponses("bookworm", maliciousCodename))
      const mod = releaseUpgrade.upgrade()
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    }
  )

  // R-0000716: the production code fetches the signed `InRelease` file and
  // verifies it with `gpgv` against the Debian archive keyring. The check
  // path tolerates fetch/verification failures by reporting `needs-apply`
  // so apply can surface a structured error on the next pass; here we
  // verify the verify-failure exit codes are recognised on the check path.
  it.each([
    [10, "fetch"],
    [11, "missing keyring"],
    [12, "signature rejection"],
  ] as const)(
    "R-0000716: check returns needs-apply when InRelease verification fails with exit code %d (%s)",
    async (exitCode, _label) => {
      const ssh = createMockSsh({
        "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
        [DEBIAN_INRELEASE_VERIFY_COMMAND]: { code: exitCode },
        "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
      })
      const mod = releaseUpgrade.upgrade()
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    }
  )

  // R-0000716: apply must surface a structured `failed` ModuleResult with a
  // human-readable error when gpgv rejects the InRelease signature so the
  // operator can tell signature-verification failure apart from other
  // failure modes (network, missing keyring, …).
  it("R-0000716: apply fails with a gpgv-signature message when verification is rejected", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: { code: 12 },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("Failed to verify signed Debian InRelease")
    expect(String(result.error)).toContain("gpgv rejected the InRelease signature")
  })

  it("R-0000716: apply fails with a missing-keyring message when the keyring is absent", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: { code: 11 },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("Debian archive keyring not found")
    expect(String(result.error)).toContain("/usr/share/keyrings/debian-archive-keyring.gpg")
  })

  it("R-0000716: apply fails with a fetch message when the InRelease download fails", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: { code: 10 },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("Failed to fetch signed Debian InRelease")
    expect(String(result.error)).toContain("https://deb.debian.org/debian/dists/stable/InRelease")
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

  it("acquires and releases the release-upgrade mutex around Debian sources rewrite and pipeline", async () => {
    const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const lockMkdir = "mkdir /var/lib/paratix/flags/'release-upgrade-mutex'"
    expect(ssh.calls).toContain(lockMkdir)
    expect(ssh.calls.some((call) => isReleaseUpgradeVerifiedRelease(call))).toBe(true)
    expect(ssh.calls.indexOf(lockMkdir)).toBeLessThan(ssh.calls.lastIndexOf("lsb_release -cs"))
    expect(ssh.calls.indexOf(lockMkdir)).toBeLessThan(
      ssh.calls.indexOf(readSourcesCommand("/etc/apt/sources.list"))
    )
    expect(ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive apt-get autoremove -y")).toBeLessThan(
      ssh.calls.findIndex((call) => isReleaseUpgradeVerifiedRelease(call))
    )
  })

  it("rechecks the Debian codename after acquiring the mutex and skips stale work", async () => {
    const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
    const codenameProbe = installSequencedOutput(ssh, "lsb_release -cs", ["bookworm", "trixie"])
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(codenameProbe.callCount()).toBe(2)
    expect(ssh.calls).toContain("mkdir /var/lib/paratix/flags/'release-upgrade-mutex'")
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls.some((call) => isReleaseUpgradeVerifiedRelease(call))).toBe(true)
  })

  it("returns failed when the release-upgrade mutex cannot be acquired", async () => {
    const ssh = createMockSsh(
      debianApplyResponses("bookworm", "trixie", {
        "mkdir -p /var/lib/paratix/flags": {
          code: 1,
          stderr: "mkdir: cannot create directory '/var/lib/paratix/flags': Permission denied\n",
        },
      })
    )
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to acquire release upgrade mutex")
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
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
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "bookworm\n" },
    })
    const mod = releaseUpgrade.upgrade({ dryRun: true })
    await mod.apply(ssh, emptyEnv)
    // R-0000716: the fetch is now embedded inside the gpgv-verified
    // pipeline, but the `--max-time 30` budget still bounds the wall-clock
    // duration of the curl call.
    expect(ssh.calls).toContain(DEBIAN_INRELEASE_VERIFY_COMMAND)
    expect(DEBIAN_INRELEASE_VERIFY_COMMAND).toContain("curl --max-time 30")
  })

  it("dryRun: no commands executed after codename lookup, returns ok", async () => {
    const ssh = createMockSsh({
      "cat '/etc/os-release'": { code: 0, stdout: DEBIAN_OS_RELEASE },
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
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
      [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
        code: 0,
        stdout: DEBIAN_STABLE_RELEASE_CURL,
      },
      "lsb_release -cs": { code: 0, stdout: "trixie\n" },
    })
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta).toBeUndefined()
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y")
  })

  it("fails without rewriting sources when Debian is on testing instead of the stable predecessor", async () => {
    const ssh = createMockSsh(debianApplyResponses("testing", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("unsupported Debian release upgrade path")
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
  })

  it("fails without rewriting sources when Debian is newer than current stable", async () => {
    const ssh = createMockSsh(debianApplyResponses("forky", "trixie"))
    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("unsupported Debian release upgrade path")
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
  })

  // R-0000632: the codename pulled from the unsigned Release file is the
  // only string the apt rewrite trusts when picking the new suite. A
  // TLS-MITM or CDN-hijack could replace the body with a development
  // suite name that satisfies CODENAME_RE; the apply path must refuse
  // every codename that isAllowedDebianStableTargetCodename does not
  // recognise as a legitimate stable target, before any sources file is
  // touched.
  // `rcbuggy` stands in for the literal `rc-buggy` suite shipped by Debian
  // during the freeze period: it is shape-valid for CODENAME_RE but never a
  // legitimate `Codename:` of `dists/stable/Release`, so an MITM injecting
  // it must be refused.
  it.each(["sid", "experimental", "forky", "rcbuggy"])(
    "R-0000632: rejects unexpected Debian stable codename '%s' from mirrors",
    async (maliciousCodename) => {
      const ssh = createMockSsh(debianApplyResponses("bookworm", maliciousCodename))
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("unexpected Debian stable codename from mirrors")
      expect(String(result.error)).toContain(JSON.stringify(maliciousCodename))
      // No sources file may be read, written or refreshed against the
      // hijacked suite.
      expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
      expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
      expect(ssh.writeFileCalls).toHaveLength(0)
    }
  )

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
    // R-0000718: writes go through the NOFOLLOW dd pipeline now; intercept
    // `ssh.exec` calls that match the pipeline and record the input
    // payload as the written content.
    const originalExec = ssh.exec.bind(ssh)
    ssh.exec = async (command, execOptions) => {
      const match = NOFOLLOW_WRITE_COMMAND_PATTERN.exec(command)
      // oxlint-disable-next-line no-conditional-in-test -- exec interceptor records pipeline writes; conditional dispatches to capture vs passthrough
      if (match?.groups != null) {
        // oxlint-disable-next-line no-conditional-in-test -- nullish coalescing default for the optional input payload of the recorded write
        writes.push({ content: execOptions?.input ?? "", path: match.groups.path })
      }
      return originalExec(command, execOptions)
    }

    const mod = releaseUpgrade.upgrade()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).not.toContain(readSourcesCommand("/etc/apt/sources.list"))
    expect(ssh.calls).toContain(readSourcesCommand(sourcesPath))
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
      // (and in which order) was written to disk. R-0000718: production
      // code now writes apt sources files via `ssh.exec` with the
      // NOFOLLOW pipeline and the new content as stdin, so the same
      // capture intercept must hook `ssh.exec` to record the input
      // payload from the matching command.
      Object.assign(ssh, { writeFile: replacement })
      const originalExec = ssh.exec.bind(ssh)
      const interceptExec: typeof ssh.exec = async (command, execOptions) => {
        const match = NOFOLLOW_WRITE_COMMAND_PATTERN.exec(command)
        if (match?.groups != null) {
          writes.push({ content: execOptions?.input ?? "", path: match.groups.path })
          return originalExec(command, execOptions)
        }
        return originalExec(command, execOptions)
      }
      Object.assign(ssh, { exec: interceptExec })
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

    it("keeps rollback and restored-cache refresh inside the release-upgrade mutex", async () => {
      const originalSources = "deb http://deb.debian.org/debian bookworm main\n"
      const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
      installSequencedExec(ssh, "DEBIAN_FRONTEND=noninteractive apt-get update", [
        { code: 1 },
        { code: 0 },
      ])
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const lockMkdir = "mkdir /var/lib/paratix/flags/'release-upgrade-mutex'"
      const releaseIndex = ssh.calls.findIndex((call) => isReleaseUpgradeVerifiedRelease(call))
      const updateIndexes = ssh.calls
        .map((call, index) => ({ call, index }))
        .filter((entry) => entry.call === "DEBIAN_FRONTEND=noninteractive apt-get update")
        .map((entry) => entry.index)
      expect(ssh.calls.indexOf(lockMkdir)).toBeLessThan(updateIndexes[0])
      expect(updateIndexes).toHaveLength(2)
      expect(updateIndexes[1]).toBeLessThan(releaseIndex)
      expect(writes.at(-1)).toMatchObject({
        content: originalSources,
        path: "/etc/apt/sources.list",
      })
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

    it("skips sources.list.d traversal paths after POSIX normalization", async () => {
      const traversalPath = "/etc/apt/sources.list.d/../../passwd"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${traversalPath}'`]: {
            code: 0,
            stdout: "deb http://example.com/repo bookworm main",
          },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${traversalPath}\0` },
        })
      )
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(ssh.calls).not.toContain(readSourcesCommand(traversalPath))
      expect(ssh.writeFileCalls.find((w) => w.remotePath === traversalPath)).toBeUndefined()
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

    // R-0000286: detect ENOENT primarily via `error.code` so non-English
    // locales (and SFTP/SSH provider variants) are recognized as a vanished
    // file. A German-localized `cat` error still surfaces a missing file and
    // must be skipped, just like the English equivalent.
    it("R-0000286: skips a sources file when readFile reports a German-localized ENOENT message", async () => {
      const vanishedPath = "/etc/apt/sources.list.d/vanished-de.list"
      const cleanPath = "/etc/apt/sources.list.d/clean-de.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${cleanPath}'`]: { code: 0, stdout: "deb http://example.com/repo bookworm main" },
          [`cat '${vanishedPath}'`]: {
            code: 1,
            stderr: `cat: '${vanishedPath}': Datei oder Verzeichnis nicht gefunden`,
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

    it("R-0000240: surfaces non-ENOENT readFile errors as a structured failed result", async () => {
      const protectedPath = "/etc/apt/sources.list.d/protected.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${protectedPath}'`]: { code: 1, stderr: "cat: Permission denied" },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${protectedPath}\0` },
        })
      )
      const mod = releaseUpgrade.upgrade()
      // R-0000240 / R-0000718: permission errors are not transient absences.
      // The sources-rewrite step now converts them into a structured
      // `failed(...)` ModuleResult so the runner can report the original
      // cause without an uncaught exception. The original message is
      // preserved in the failure error message.
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("Permission denied")
    })

    // R-0000629: the symlink probe and the read must share a single shell
    // statement that uses `dd … iflag=nofollow`, so an attacker cannot
    // swap the regular file for a symlink between a `[ -L ]` probe and a
    // subsequent `cat`/`readFile`.
    it("R-0000629: reads sources files via a single `[ -L ] + dd iflag=nofollow` statement", async () => {
      const extraPath = "/etc/apt/sources.list.d/extra.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${extraPath}'`]: {
            code: 0,
            stdout: "deb http://example.com/repo bookworm main",
          },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${extraPath}\0` },
        })
      )
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      // The fused read replaces both the separate `[ -L ]` probe and the
      // `cat` read. Neither legacy call shape may appear on the wire.
      expect(ssh.calls).toContain(readSourcesCommand(extraPath))
      expect(ssh.calls).toContain(readSourcesCommand("/etc/apt/sources.list"))
      expect(ssh.calls).not.toContain(`cat '${extraPath}'`)
      expect(ssh.calls).not.toContain("cat '/etc/apt/sources.list'")
      expect(ssh.calls).not.toContain(`[ -L '${extraPath}' ]`)
      expect(ssh.calls).not.toContain("[ -L '/etc/apt/sources.list' ]")
    })

    // R-0000629: a sources file that becomes a symlink between `find` and
    // the read (exit 200 from the fused statement) must be skipped without
    // following the link, the same way the previous standalone `[ -L ]`
    // probe did.
    it("R-0000629: skips a sources file that is a symlink at read time", async () => {
      const symlinkPath = "/etc/apt/sources.list.d/swapped.list"
      const cleanPath = "/etc/apt/sources.list.d/clean.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${cleanPath}'`]: { code: 0, stdout: "deb http://example.com/repo bookworm main" },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${symlinkPath}\0${cleanPath}\0` },
          [readSourcesCommand(symlinkPath)]: { code: 200 },
        })
      )
      const writes = captureWriteFile(ssh)
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(writes.find((w) => w.path === symlinkPath)).toBeUndefined()
      expect(writes.find((w) => w.path === cleanPath)).toBeDefined()
    })

    // R-0000629: a real ELOOP-shaped failure (the kernel rejected the
    // open(2) because `iflag=nofollow` saw a symlink between the probe and
    // the read) must surface rather than being silently swallowed.
    it("R-0000629: surfaces dd ELOOP failures from a planted symlink as a structured failed result", async () => {
      const symlinkPath = "/etc/apt/sources.list.d/late-swap.list"
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            { code: 0, stdout: `${symlinkPath}\0` },
          [readSourcesCommand(symlinkPath)]: {
            code: 1,
            stderr: `dd: failed to open '${symlinkPath}': Too many levels of symbolic links`,
          },
        })
      )
      const mod = releaseUpgrade.upgrade()
      // R-0000629 / R-0000718: an ELOOP-shaped read failure is now
      // converted into a structured `failed(...)` ModuleResult instead of
      // an uncaught exception. The original message survives in the
      // failure error.
      const result = await mod.apply(ssh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("Too many levels of symbolic links")
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
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
        [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
          code: 0,
          stdout: debianInReleaseClearsignedBody(targetCodename),
        },
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
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
        [DEBIAN_INRELEASE_VERIFY_COMMAND]: {
          code: 0,
          stdout: debianInReleaseClearsignedBody("trixie"),
        },
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
    // R-0000718: writes flow through the NOFOLLOW pipeline; the mode is
    // embedded as the `chmod <mode> <path>` step of the pipeline, which we
    // extract via `NOFOLLOW_WRITE_COMMAND_PATTERN`.
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
      const originalExec = ssh.exec.bind(ssh)
      ssh.exec = async (command, execOptions) => {
        const match = NOFOLLOW_WRITE_COMMAND_PATTERN.exec(command)
        // oxlint-disable-next-line no-conditional-in-test -- exec interceptor records pipeline writes; conditional dispatches to capture vs passthrough
        if (match?.groups != null) {
          writes.push({
            // oxlint-disable-next-line no-conditional-in-test -- nullish coalescing default for the optional input payload of the recorded write
            content: execOptions?.input ?? "",
            mode: match.groups.mode,
            path: match.groups.path,
          })
        }
        return originalExec(command, execOptions)
      }

      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      const sourcesWrites = writes.filter((w) => w.path === "/etc/apt/sources.list")
      // The last write to sources.list is the rollback. It must restore the
      // captured 0640 mode rather than overwriting it with the 0644 default.
      expect(sourcesWrites.at(-1)?.content).toBe(originalSources)
      expect(sourcesWrites.at(-1)?.mode).toBe("0640")
    })

    it("refreshes apt cache after a successful sources rollback", async () => {
      const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
      const sequencedUpdate = installSequencedExec(ssh, APT_UPDATE_COMMAND, [
        { code: 1, stderr: "E: target suite unavailable" },
        { code: 0 },
      ])

      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(sequencedUpdate.callCount()).toBe(2)
      expect(result.error?.message).toContain("apt-get update failed")
      expect(result.error?.message).not.toContain("rollback succeeded but")
    })

    it("reports both errors when the post-rollback apt cache refresh fails", async () => {
      const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
      const sequencedUpdate = installSequencedExec(ssh, APT_UPDATE_COMMAND, [
        { code: 1, stderr: "E: target suite unavailable" },
        { code: 100, stderr: "E: restored suite metadata unavailable" },
      ])

      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(sequencedUpdate.callCount()).toBe(2)
      expect(result.error?.message).toContain("apt-get update failed")
      expect(result.error?.message).toContain(
        "rollback succeeded but [releaseUpgrade.upgrade] apt-get update on restored sources failed"
      )
      expect(result.error?.message).toContain("E: restored suite metadata unavailable")
    })

    it("reports restore failures while still attempting the remaining sources rollbacks", async () => {
      const extraPath = "/etc/apt/sources.list.d/extra.list"
      const originalExtraSources = "deb http://example.com/repo bookworm contrib"
      const writes: WriteCapture[] = []
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          [`cat '${extraPath}'`]: { code: 0, stdout: originalExtraSources },
          "DEBIAN_FRONTEND=noninteractive apt-get update": {
            code: 1,
            stderr: "E: target suite unavailable",
          },
          "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0":
            {
              code: 0,
              stdout: `${extraPath}\0`,
            },
        })
      )
      // R-0000718: writes flow through the NOFOLLOW dd pipeline. Intercept
      // `ssh.exec` calls that match the pipeline, capture the input
      // payload, and simulate the third write (the rollback of
      // /etc/apt/sources.list) throwing so the rollback aggregation logic
      // surfaces a partial-rollback failure to the caller.
      let writeIndex = 0
      const originalExec = ssh.exec.bind(ssh)
      ssh.exec = async (command, execOptions) => {
        const match = NOFOLLOW_WRITE_COMMAND_PATTERN.exec(command)
        // oxlint-disable-next-line no-conditional-in-test -- mock dispatcher: forward non-pipeline commands to the original implementation
        if (match?.groups == null) return originalExec(command, execOptions)
        const path = match.groups.path
        // oxlint-disable-next-line no-conditional-in-test -- nullish coalescing default for the optional input payload
        const content = execOptions?.input ?? ""
        const stepIndex = writeIndex
        writeIndex += 1
        // oxlint-disable-next-line no-conditional-in-test -- simulate the third write failing to drive the partial-rollback aggregation path
        if (stepIndex === 2) {
          throw new Error("permission denied")
        }
        writes.push({ content, path })
        return { code: 0, stderr: "", stdout: "" }
      }

      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("apt-get update failed")
      expect(result.error?.message).toContain("sources rollback failed for 1 file(s)")
      expect(result.error?.message).toContain("/etc/apt/sources.list: permission denied")
      expect(writes).toContainEqual({ content: originalExtraSources, path: extraPath })
    })

    // R-0000718: sources writes (rewrite and rollback) must flow through
    // the NOFOLLOW dd pipeline so a symlink swap at the target path cannot
    // redirect the write to an attacker-controlled file. The pipeline
    // surfaces the symlink case as a structured failure that aborts the
    // upgrade rather than overwriting the symlink target.
    it("R-0000718: rewrite issues a NOFOLLOW dd write command for /etc/apt/sources.list", async () => {
      const ssh = createMockSsh(debianApplyResponses("bookworm", "trixie"))
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      const writeCall = ssh.calls.find((call) => NOFOLLOW_WRITE_COMMAND_PATTERN.test(call))
      expect(writeCall).toBeDefined()
      // oxlint-disable-next-line no-conditional-in-test -- nullish fallback when the optional regex input is unavailable; assertion above guarantees a match
      const match = NOFOLLOW_WRITE_COMMAND_PATTERN.exec(writeCall ?? "")
      expect(match?.groups?.path).toBe("/etc/apt/sources.list")
    })

    it("R-0000718: rewrite fails closed when the sources file is a symlink at write time", async () => {
      const ssh = createMockSsh(
        debianApplyResponses("bookworm", "trixie", {
          "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
        })
      )
      // Override the default response stub for the write pipeline so the
      // symlink-guard branch reports exit 201 (NOFOLLOW symlink refusal).
      const originalExec = ssh.exec.bind(ssh)
      ssh.exec = async (command, execOptions) => {
        // oxlint-disable-next-line no-conditional-in-test -- mock dispatcher returns exit 201 when the NOFOLLOW pipeline runs, otherwise falls through
        if (NOFOLLOW_WRITE_COMMAND_PATTERN.test(command)) {
          return { code: 201, stderr: "", stdout: "" }
        }
        return originalExec(command, execOptions)
      }
      const mod = releaseUpgrade.upgrade()
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("path is a symbolic link (NOFOLLOW guard)")
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
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
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
      expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
      expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })
})
