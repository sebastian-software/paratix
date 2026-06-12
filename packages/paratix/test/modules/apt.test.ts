/* eslint-disable no-template-curly-in-string -- Shell dpkg-query format strings, not JS templates */
import { describe, expect, it } from "vitest"

import { apt } from "../../src/modules/apt.js"
import { sha256String } from "../../src/modules/fileHelpers.js"
import { createMockSsh as createBaseMockSsh, type ExecCall } from "../helpers/mockSsh.js"
import { MOCK_FLAG_LOCK_HOLDER_TOKEN } from "../helpers/mockSshFlagLock.js"

const aptKeyringDirectoryRealpathCommand = "command -p realpath -m -- '/etc/apt/keyrings'"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowFlagLockInternalDefaults: true,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/etc\/apt\/sources\.list\.d\/.+\.list$/v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      {
        command: aptKeyringDirectoryRealpathCommand,
        result: { code: 0, stdout: "/etc/apt/keyrings\n" },
      },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}
const DIST_UPGRADE_FLAG = "apt-dist-upgrade-2024-01-15"

function distUpgradeApplyLockResponses(): Record<string, { code?: number; stdout?: string }> {
  const markerPath = `/var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}.lock'/holder`
  const lockPath = `/var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}.lock'`
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  const awkMarkerPath = `'/var/lib/paratix/flags/${DIST_UPGRADE_FLAG}.lock/holder'`
  // R-0000634: acquire reads the marker token back via `ssh.output`; release
  // is now a single shell statement that verifies ownership before removing
  // the marker and lock directory.
  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  // R-0000758: release captures the awk readback in `$awk_token` and uses
  // the POSIX `x`-prefix comparison.
  const verifiedReleaseCommand =
    `awk_token=$(awk 'NR==1{print $1}' ${awkMarkerPath} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = 'x${MOCK_FLAG_LOCK_HOLDER_TOKEN}' ] && ` +
    `rm -f -- ${markerPath} && ` +
    `rmdir -- ${lockPath}`
  return {
    [`[ -f /var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}' ]`]: { code: 1 },
    [`awk 'NR==1{print $1}' ${awkMarkerPath}`]: {
      code: 0,
      stdout: MOCK_FLAG_LOCK_HOLDER_TOKEN,
    },
    [`mkdir /var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}.lock'`]: { code: 0 },
    [`printf '%s@%s %s\\n' "$$" '' "$(date +%s)" > ${markerPath}`]: { code: 0 },
    hostname: { code: 0, stdout: "" },
    "mkdir -p /var/lib/paratix/flags": { code: 0 },
    [verifiedReleaseCommand]: { code: 0 },
  }
}

function installSequencedOutputForExec(
  ssh: ReturnType<typeof createMockSsh>,
  command: string,
  outputs: [string, ...string[]]
): () => number {
  const mockSsh = ssh
  const originalExec = mockSsh.exec.bind(mockSsh)
  let calls = 0
  mockSsh.exec = async (nextCommand, options) => {
    if (nextCommand === command) {
      mockSsh.calls.push(nextCommand)
      mockSsh.execCalls.push({ command: nextCommand, options })
      const stdout = outputs[Math.min(calls, outputs.length - 1)]
      calls += 1
      return { code: 0, stderr: "", stdout }
    }
    return originalExec(nextCommand, options)
  }
  return () => calls
}

function expectDebconfSetSelectionsExecCall(
  execCalls: ExecCall[],
  expectedInput: string,
  secrets: string[]
): void {
  const debconfSetSelectionsCalls = execCalls.filter(
    (call) => call.command === "debconf-set-selections"
  )
  expect(debconfSetSelectionsCalls).toHaveLength(1)
  expect(debconfSetSelectionsCalls[0]?.options).toStrictEqual({
    ignoreExitCode: true,
    input: expectedInput,
    secrets,
    silent: true,
  })
}

function expectNoExecCommandLeaksSecrets(execCalls: ExecCall[], secrets: string[]): void {
  for (const call of execCalls) {
    for (const secret of secrets) {
      expect(call.command).not.toContain(secret)
    }
  }
}

// R-0000163 helper: build an `exec` override whose first invocation of
// `apt-get update` returns failure and whose second invocation succeeds.
// Other commands raise so the override remains tightly scoped to the
// repository-rollback assertion.
function createSequencedAptGetUpdateExec(
  passthroughExec?: (command: string) => Promise<{ code: number; stderr: string; stdout: string }>
): {
  callCount: () => number
  exec: (command: string) => Promise<{ code: number; stderr: string; stdout: string }>
} {
  const responses = [
    { code: 1, stderr: "Some packages could not be installed", stdout: "" },
    { code: 0, stderr: "", stdout: "" },
  ]
  let calls = 0
  return {
    callCount: () => calls,
    async exec(command) {
      const expectedCommand = "DEBIAN_FRONTEND=noninteractive apt-get update"
      const isExpected = command === expectedCommand
      if (isExpected) {
        const next = responses[calls] ?? responses.at(-1)!
        calls += 1
        return next
      }
      // R-0000702: the rollback path now also probes the device:inode pair
      // via `stat -c '%d:%i'`. Defer to the supplied passthrough exec so
      // those probes (and any other stubbed commands) still flow through
      // the underlying mock instead of failing this override outright.
      if (passthroughExec) {
        return passthroughExec(command)
      }
      throw new Error(`unexpected exec command in override: ${command}`)
    },
  }
}

describe("apt.key", () => {
  const fingerprint = "1234567890ABCDEF1234567890ABCDEF12345678"
  const downloadCommand =
    "curl -fsSL -o '/tmp/apt-key-docker.ABCDEF' --proto '=https' --proto-redir '=https' --config -"
  // R-0000225: gpg now runs against a temp homedir and a chmod 0644 follows
  // the dearmor. Tests stub the homedir mktemp, the new dearmor command shape,
  // the chmod and the rm -rf cleanup.
  const gpgHomedir = "/tmp/apt-key-gpg-home.ABCDEF"
  const gpgHomedirMktempCmd = "mktemp -d /tmp/apt-key-gpg-home.XXXXXX"
  const gpgHomedirCleanupCmd = `rm -rf -- '${gpgHomedir}'`
  const dearmorKeyringPath = "/etc/apt/keyrings/docker.gpg"
  const dearmorTempPath = "/tmp/apt-key-docker.ABCDEF"
  // R-0000709: dearmor now writes to a staging file in the keyring directory,
  // then publishes via `mv -T` with an inline symlink guard.
  const dearmorStagingPath = "/etc/apt/keyrings/.apt-key.paratix-staging.ABCDEF"
  const dearmorStagingMktempCmd = `mktemp -p '/etc/apt/keyrings' -- '.apt-key.paratix-staging.XXXXXX'`
  const dearmorCommand = `gpg --no-default-keyring --no-options --homedir '${gpgHomedir}' --dearmor --yes -o '${dearmorStagingPath}' '${dearmorTempPath}'`
  const dearmorChmodCommand = `chmod 0644 '${dearmorStagingPath}'`
  const dearmorPublishCommand = `{ resolved=$(command -p realpath -m -- '/etc/apt/keyrings') && [ "x$resolved" = 'x/etc/apt/keyrings' ] || { rm -f -- '${dearmorStagingPath}'; exit 74; }; if [ -L '${dearmorKeyringPath}' ]; then rm -f -- '${dearmorStagingPath}'; exit 73; fi && mv -T -- '${dearmorStagingPath}' '${dearmorKeyringPath}'; } || { status=$?; rm -f -- '${dearmorStagingPath}'; exit "$status"; }`
  const dearmorStagingCleanupCmd = `rm -f -- '${dearmorStagingPath}'`

  // R-0000704: `gpg --show-keys` is wrapped in a dedicated homedir scope just
  // like the dearmor command, so tests must reference the longer command form
  // including `--no-default-keyring --no-options --homedir <tempdir>`.
  function showKeysCommand(path: string): string {
    return `gpg --no-default-keyring --no-options --homedir '${gpgHomedir}' --show-keys --with-colons '${path}'`
  }

  function aptKeyDearmorBaseStubs(): Record<string, { code?: number; stdout?: string }> {
    return {
      [dearmorChmodCommand]: { code: 0 },
      [dearmorPublishCommand]: { code: 0 },
      [dearmorStagingCleanupCmd]: { code: 0 },
      [dearmorStagingMktempCmd]: { stdout: `${dearmorStagingPath}\n` },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
    }
  }

  function aptKeyValidationMessage(url: string): string {
    try {
      apt.key("docker", url, { fingerprint })
    } catch (error) {
      return error instanceof Error ? error.message : String(error)
    }
    throw new Error("apt.key did not throw")
  }

  it("check returns ok when key file exists", async () => {
    const ssh = createMockSsh({
      "[ -f '/etc/apt/keyrings/docker.gpg' ] && [ ! -L '/etc/apt/keyrings/docker.gpg' ]": {
        code: 0,
      },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
      [showKeysCommand("/etc/apt/keyrings/docker.gpg")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key file is missing", async () => {
    const ssh = createMockSsh({
      "[ -f '/etc/apt/keyrings/docker.gpg' ] && [ ! -L '/etc/apt/keyrings/docker.gpg' ]": {
        code: 1,
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the installed key fingerprint mismatches", async () => {
    const ssh = createMockSsh({
      "[ -f '/etc/apt/keyrings/docker.gpg' ] && [ ! -L '/etc/apt/keyrings/docker.gpg' ]": {
        code: 0,
      },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
      [showKeysCommand("/etc/apt/keyrings/docker.gpg")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply downloads, verifies fingerprint, and then imports the key", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: {
        code: 0,
      },
      [downloadCommand]: {
        code: 0,
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("mkdir -p /etc/apt/keyrings")
    expect(ssh.calls).toContain("mktemp '/tmp/apt-key-docker.XXXXXX'")
    expect(ssh.calls).toContain(downloadCommand)
    expect(downloadCommand).toContain("--proto '=https' --proto-redir '=https'")
    expect(ssh.execCalls.find((call) => call.command === downloadCommand)?.options).toMatchObject({
      input: 'url = "https://download.docker.com/linux/ubuntu/gpg"\n',
      silent: true,
    })
    expect(ssh.calls).toContain(showKeysCommand("/tmp/apt-key-docker.ABCDEF"))
    expect(ssh.calls).toContain(dearmorCommand)
    // R-0000225: the dearmor must run with --homedir pointing at a fresh temp
    // dir, and the keyring must be chmod'd 0644 afterwards.
    expect(ssh.calls).toContain(gpgHomedirMktempCmd)
    expect(dearmorCommand).toContain("--homedir")
    expect(ssh.calls).toContain(dearmorChmodCommand)
    expect(ssh.calls).toContain(gpgHomedirCleanupCmd)
  })

  it("passes credentialed and sensitive query URLs through curl stdin instead of argv", async () => {
    const sensitiveUrl = "https://apt-user:s3cr3t@example.com/key.gpg?token=abc123&download=true"
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: {
        code: 0,
      },
      [downloadCommand]: {
        code: 0,
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", sensitiveUrl, { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    const download = ssh.execCalls.find((call) => call.command === downloadCommand)

    expect(result.status).toBe("changed")
    expect(download?.command).not.toContain("s3cr3t")
    expect(download?.command).not.toContain("token=abc123")
    expect(download?.options?.input).toBe(`url = "${sensitiveUrl}"\n`)
    expect(download?.options?.secrets).toStrictEqual([sensitiveUrl, "apt-user", "s3cr3t"])
  })

  it("throws when the key URL contains a newline", () => {
    expect(() => {
      apt.key("docker", 'https://example.com/key.gpg\nurl = "https://evil.example/key.gpg"', {
        fingerprint,
      })
    }).toThrow("apt.key URL must not contain CR, LF, or NUL characters")
  })

  it("does not echo unsafe key URL values in validation errors", () => {
    expect(() => {
      apt.key("docker", 'https://example.com/key.gpg\nheader = "X-Token: secret-token"', {
        fingerprint,
      })
    }).toThrow(/^(?!.*secret-token).*$/v)
  })

  it("returns a failed result when the downloaded key fingerprint mismatches", async () => {
    const ssh = createMockSsh({
      [downloadCommand]: {
        code: 0,
      },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[apt.key] fingerprint mismatch for docker")
  })

  it("rejects downloaded key material with extra primary keys", async () => {
    const ssh = createMockSsh({
      [downloadCommand]: {
        code: 0,
      },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout:
          "pub:-:255:22:::\n" +
          "fpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n" +
          "sub:-:255:22:::\n" +
          "fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n" +
          "pub:-:255:22:::\n" +
          "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] key material for docker contains 2 primary keys"
    )
    expect(ssh.calls).not.toContain(dearmorCommand)
  })

  it("returns a failed result with error details when key import fails", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: {
        code: 2,
        stderr: "gpg: dearmor failed: No such file or directory",
      },
      [downloadCommand]: {
        code: 0,
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[apt.key] failed to import docker")
  })

  it("ignores non-zero temp file cleanup exit codes", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: {
        code: 2,
        stderr: "gpg: dearmor failed: No such file or directory",
      },
      [downloadCommand]: {
        code: 0,
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 1 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    const cleanup = ssh.execCalls.find(
      (call) => call.command === "rm -f '/tmp/apt-key-docker.ABCDEF'"
    )

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[apt.key] failed to import docker")
    expect(cleanup?.options).toMatchObject({ ignoreExitCode: true, silent: true })
  })

  // R-0000066 regression: applyAptKey must validate the path returned by
  // `mktemp` before embedding it in the curl, gpg --dearmor and rm -f
  // subcommands. Multi-line output or a path that does not match the
  // expected `/tmp/apt-key-${name}.` prefix must be rejected before any
  // download or gpg operation runs.
  it("returns failed without invoking curl or gpg when mktemp produces multi-line output", async () => {
    const ssh = createMockSsh({
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": {
        stdout: "warning: locale not set\n/tmp/apt-key-docker.ABCDEF\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] mktemp produced an unexpected path for docker"
    )
    expect(ssh.calls).not.toContain(downloadCommand)
    expect(ssh.calls).not.toContain(showKeysCommand("/tmp/apt-key-docker.ABCDEF"))
    expect(ssh.calls).not.toContain(dearmorCommand)
  })

  it("returns failed without invoking curl or gpg when mktemp produces a path outside the expected prefix", async () => {
    const ssh = createMockSsh({
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/etc/passwd\n" },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] mktemp produced an unexpected path for docker"
    )
    expect(ssh.calls).not.toContain(
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/etc/passwd'"
    )
    expect(ssh.calls).not.toContain(showKeysCommand("/etc/passwd"))
  })

  it("throws for non-https URLs", () => {
    expect(() =>
      apt.key("docker", "http://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    ).toThrow(/requires an https URL/v)
  })

  it("redacts URL credentials from validation errors", () => {
    const secretUrl = "http://apt-user:s3cr3t@example.com/key.gpg"
    const message = aptKeyValidationMessage(secretUrl)

    expect(message).toContain("REDACTED")
    expect(message).not.toMatch(/apt-user|s3cr3t/v)
  })

  it("redacts sensitive query values from validation errors", () => {
    const secretUrl = "http://example.com/key.gpg?token=abc123&download=true"
    const message = aptKeyValidationMessage(secretUrl)

    expect(message).toContain("token=REDACTED")
    expect(message).not.toContain("abc123")
  })

  it("does not echo malformed URLs in validation errors", () => {
    const secretUrl = "https://example .com/key.gpg?token=abc123"
    const message = aptKeyValidationMessage(secretUrl)

    expect(message).toBe("apt.key requires a valid URL")
    expect(message).not.toMatch(/abc123|example \.com/v)
  })

  it("throws when fingerprint is invalid", () => {
    expect(() =>
      apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint: "abc" })
    ).toThrow(/requires an OpenPGP fingerprint/v)
  })

  // R-0000098 regression: name lands directly in
  // `/etc/apt/keyrings/${name}.gpg` and must reject path-traversal
  // segments (`..`, slashes, empty string) before any shell command
  // is constructed.
  it("throws when name contains '..' (path traversal)", () => {
    expect(() => apt.key("../../tmp/evil", "https://example.com/key.gpg", { fingerprint })).toThrow(
      /must not contain '\.\.'/v
    )
  })

  it("throws when name contains a path separator", () => {
    expect(() => apt.key("foo/bar", "https://example.com/key.gpg", { fingerprint })).toThrow(
      /must match/v
    )
  })

  it("throws when name is empty", () => {
    expect(() => apt.key("", "https://example.com/key.gpg", { fingerprint })).toThrow(/must match/v)
  })

  // R-0000134 regression: a symlink at the keyring path must be treated as
  // "not present" by check (so apply runs) and rejected by apply before any
  // gpg --dearmor call truncates or overwrites the link target.
  it("check returns needs-apply when the keyring path is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -f '/etc/apt/keyrings/docker.gpg' ] && [ ! -L '/etc/apt/keyrings/docker.gpg' ]": {
        code: 1,
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain(showKeysCommand("/etc/apt/keyrings/docker.gpg"))
  })

  it("apply refuses to dearmor through a symlinked keyring path", async () => {
    const ssh = createMockSsh({
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 0 },
      [downloadCommand]: { code: 0 },
      [gpgHomedirCleanupCmd]: { code: 0 },
      [gpgHomedirMktempCmd]: { stdout: `${gpgHomedir}\n` },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] refuses to write through symlink at /etc/apt/keyrings/docker.gpg"
    )
    expect(ssh.calls).not.toContain(dearmorCommand)
  })

  it("apply refuses a symlinked keyring directory chain before mkdir", async () => {
    const ssh = createMockSsh({
      [aptKeyringDirectoryRealpathCommand]: { code: 0, stdout: "/tmp/attacker-keyrings\n" },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] keyring directory for docker resolves to /tmp/attacker-keyrings"
    )
    expect(ssh.calls).not.toContain("mkdir -p /etc/apt/keyrings")
    expect(ssh.calls).not.toContain(dearmorStagingMktempCmd)
  })

  it("apply revalidates the keyring directory chain after mkdir", async () => {
    const ssh = createMockSsh({
      "mkdir -p /etc/apt/keyrings": { code: 0 },
    })
    const realpathCallCount = installSequencedOutputForExec(
      ssh,
      aptKeyringDirectoryRealpathCommand,
      ["/etc/apt/keyrings\n", "/tmp/attacker-keyrings\n"]
    )
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(realpathCallCount()).toBe(2)
    expect(String(result.error)).toContain(
      "[apt.key] keyring directory for docker resolves to /tmp/attacker-keyrings"
    )
    expect(ssh.calls).not.toContain("mktemp '/tmp/apt-key-docker.XXXXXX'")
  })

  // R-0000709: dearmor must stage the keyring next to the final path, chmod
  // the staging file, then publish atomically via `mv -T`. The shell guard
  // also fails fast on a symlink swap that materialises between the apply-
  // time `isSymlink` check and the publish step.
  it("R-0000709: stages the keyring, chmods, then publishes atomically via mv -T", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: { code: 0 },
      [downloadCommand]: { code: 0 },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result).toStrictEqual({ status: "changed" })
    const dearmorIndex = ssh.calls.indexOf(dearmorCommand)
    const chmodIndex = ssh.calls.indexOf(dearmorChmodCommand)
    const publishIndex = ssh.calls.indexOf(dearmorPublishCommand)
    // dearmor → chmod on staging → atomic publish via mv -T
    expect(dearmorIndex).toBeGreaterThan(-1)
    expect(chmodIndex).toBeGreaterThan(dearmorIndex)
    expect(publishIndex).toBeGreaterThan(chmodIndex)
    expect(ssh.calls.filter((call) => call === aptKeyringDirectoryRealpathCommand)).toHaveLength(3)
    expect(dearmorPublishCommand).toContain("command -p realpath -m -- '/etc/apt/keyrings'")
    // Direct chmod on the final keyring path must never run — the staging
    // file already carried 0644 before the rename landed it.
    expect(ssh.calls).not.toContain(`chmod 0644 '${dearmorKeyringPath}'`)
  })

  // R-0000709: when the inline publish guard detects a symlink that
  // materialised after the apply-time check, the shell exits with code 73
  // and the helper surfaces a clear "refuses to write through symlink"
  // diagnostic.
  it("R-0000709: surfaces refuse-symlink failure when the publish guard fires", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: { code: 0 },
      // R-0000709: publish guard exits with code 73 when a symlink appeared
      // between the apply-time check and the inline `[ -L … ]` probe inside
      // the publish shell pipeline.
      [dearmorPublishCommand]: { code: 73 },
      [downloadCommand]: { code: 0 },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] refuses to write through symlink at /etc/apt/keyrings/docker.gpg"
    )
  })

  it("surfaces a keyring directory revalidation failure from the publish guard", async () => {
    const ssh = createMockSsh({
      ...aptKeyDearmorBaseStubs(),
      "[ -L '/etc/apt/keyrings/docker.gpg' ]": { code: 1 },
      [dearmorCommand]: { code: 0 },
      [dearmorPublishCommand]: { code: 74 },
      [downloadCommand]: { code: 0 },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
      [showKeysCommand("/tmp/apt-key-docker.ABCDEF")]: {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "[apt.key] keyring directory for docker is no longer symlink-free at /etc/apt/keyrings"
    )
  })
})

describe("apt.distUpgrade", () => {
  it("check returns ok when flag file exists", async () => {
    const ssh = createMockSsh({
      "[ -f /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15' ]": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when flag is missing", async () => {
    const ssh = createMockSsh({
      "[ -f /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15' ]": { code: 1 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("apply returns changed and runs the three-step pipeline", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-dist-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y")
  })

  // R-0000055 regression: the pipeline order must be
  // `dpkg --configure -a` → `apt-get update` → `apt-get dist-upgrade -y`
  // so a dpkg-broken host gets configure -a a chance to run before the
  // first apt-get step that would otherwise fail. Mirrors the order used
  // by the package.ts apt-upgrade pipeline.
  it("apply runs dpkg --configure -a before apt-get update and apt-get dist-upgrade", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-dist-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    await mod.apply(ssh, emptyEnv)

    const configureIdx = ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    const updateIdx = ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive apt-get update")
    const upgradeIdx = ssh.calls.indexOf("DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y")

    expect(configureIdx).toBeGreaterThan(-1)
    expect(updateIdx).toBeGreaterThan(-1)
    expect(upgradeIdx).toBeGreaterThan(-1)
    expect(configureIdx).toBeLessThan(updateIdx)
    expect(updateIdx).toBeLessThan(upgradeIdx)
  })

  it("apply without options does not set a timeout key", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-dist-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    await mod.apply(ssh, emptyEnv)
    const distUpgradeCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"
    )
    expect(distUpgradeCall?.options).not.toHaveProperty("timeout")
  })

  it("apply forwards options.timeout to every step", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-dist-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15", { timeout: 1_200_000 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })

    for (const command of [
      "DEBIAN_FRONTEND=noninteractive apt-get update",
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a",
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y",
    ]) {
      const call = ssh.execCalls.find((c) => c.command === command)
      expect(call).toBeDefined()
      expect(call?.options?.timeout).toBe(1_200_000)
    }
  })

  it("apply with options.timeout=undefined does not set a timeout key", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-dist-upgrade-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
        { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15", { timeout: undefined })
    await mod.apply(ssh, emptyEnv)
    const distUpgradeCall = ssh.execCalls.find(
      (c) => c.command === "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"
    )
    expect(distUpgradeCall?.options).not.toHaveProperty("timeout")
  })

  it("apply stops at the first failing step and reports it", async () => {
    const ssh = createMockSsh({
      ...distUpgradeApplyLockResponses(),
      // R-0000055: dpkg --configure -a now runs first; an apt-get update
      // failure must therefore still abort the dist-upgrade step but
      // dpkg --configure -a is expected to have already run.
      "DEBIAN_FRONTEND=noninteractive apt-get update": {
        code: 100,
        stderr: "E: Could not get lock /var/lib/dpkg/lock-frontend",
      },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[apt.distUpgrade] apt-get update failed")
    expect(ssh.calls).toContain("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y")
  })

  it("direct apply returns ok without running the pipeline when the flag already exists", async () => {
    const ssh = createMockSsh({
      [`[ -f /var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}' ]`]: { code: 0 },
    })
    const mod = apt.distUpgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "ok" })
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    expect(ssh.calls).not.toContain(`mkdir /var/lib/paratix/flags/'${DIST_UPGRADE_FLAG}.lock'`)
  })
})

describe("apt.repository (PPA form)", () => {
  const launchpadContentHost = ["ppa.launchpad", "content.net"].join("")
  const activeSourceLinesCommand =
    "grep -RshE -- '^[[:space:]]*deb(-src)?[[:space:]]' /etc/apt/sources.list.d/ 2>/dev/null"
  const ppaCheckCommand = `${activeSourceLinesCommand} | grep -Fqs -- '/${launchpadContentHost}/nginx/stable/' || ${activeSourceLinesCommand} | grep -Fqs -- '/ppa.launchpad.net/nginx/stable/'`

  it("check returns ok when PPA is found in sources", async () => {
    const ssh = createMockSsh({
      [ppaCheckCommand]: { code: 0 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when PPA is not found", async () => {
    const ssh = createMockSsh({
      [ppaCheckCommand]: { code: 1 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check only searches active source lines", async () => {
    const ssh = createMockSsh({
      [ppaCheckCommand]: { code: 1 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).toStrictEqual([ppaCheckCommand])
    expect(ppaCheckCommand).toContain("^[[:space:]]*deb")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("throws when a PPA identifier contains regex metacharacters", () => {
    expect(() => apt.repository("ppa:nginx/.+")).toThrow(
      "PPA identifier must use Launchpad owner/name form"
    )
  })

  it("throws when a PPA identifier does not use owner/name form", () => {
    expect(() => apt.repository("ppa:nginx")).toThrow(
      "PPA identifier must use Launchpad owner/name form"
    )
  })

  it("apply adds a valid PPA", async () => {
    const ssh = createMockSsh({
      "add-apt-repository -y 'ppa:nginx/stable'": { code: 0 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
  })
})

describe("apt.repository (standard form)", () => {
  const source = "deb https://download.docker.com/linux/ubuntu noble stable"
  const filePath = "/etc/apt/sources.list.d/docker.list"
  const expectedContentWithSignedBy =
    "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable"
  const updateFlag = `apt-repository-${sha256String("docker").slice(0, 16)}-${sha256String(expectedContentWithSignedBy).slice(0, 16)}`
  const updateFlagCheck = `[ -f /var/lib/paratix/flags/'${updateFlag}' ]`

  it("check returns ok when file exists with correct content (auto signed-by)", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when file does not exist", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 1 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.repository("docker", source)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("auto-derives signed-by from the repository name", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when content has no signed-by but auto-derivation is active", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when signedBy is false and file matches source without signed-by", async () => {
    const signedByFalseFlag = `apt-repository-${sha256String("docker").slice(0, 16)}-${sha256String(source).slice(0, 16)}`
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f /var/lib/paratix/flags/'${signedByFalseFlag}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
    })
    const mod = apt.repository("docker", source, { signedBy: false })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("throws when source contains multiple lines", () => {
    expect(() => apt.repository("docker", `${source}\n${source}`)).toThrow(
      "apt.repository: source must be exactly one line"
    )
  })

  it("throws when signedBy is false and source contains multiple lines", () => {
    expect(() =>
      apt.repository("docker", `${source}\n# additional repository`, { signedBy: false })
    ).toThrow("apt.repository: source must be exactly one line")
  })

  it("throws when signedBy is enabled for a non-deb source line", () => {
    expect(() => apt.repository("docker", `# ${source}`)).toThrow(
      "apt.repository: source must start with deb or deb-src when signedBy is enabled"
    )
  })

  it("check returns ok when explicit signedBy uses custom key path", async () => {
    const customContent =
      "deb [signed-by=/etc/apt/keyrings/custom.gpg] https://download.docker.com/linux/ubuntu noble stable"
    const customFlag = `apt-repository-${sha256String("docker").slice(0, 16)}-${sha256String(customContent).slice(0, 16)}`
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f /var/lib/paratix/flags/'${customFlag}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: customContent },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
    })
    const mod = apt.repository("docker", source, { signedBy: "custom" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when bracketed content uses a different signed-by path", async () => {
    const sourceWithForeignSignedBy =
      "deb [arch=amd64 signed-by=/etc/apt/keyrings/foreign.gpg] https://download.docker.com/linux/ubuntu noble stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: sourceWithForeignSignedBy },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply replaces a foreign signed-by path in bracketed source content", async () => {
    const sourceWithForeignSignedBy =
      "deb [arch=amd64 signed-by=/etc/apt/keyrings/foreign.gpg] https://download.docker.com/linux/ubuntu noble stable"
    const expectedContent =
      "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable"
    const expectedFlag = `apt-repository-${sha256String("docker").slice(0, 16)}-${sha256String(expectedContent).slice(0, 16)}`
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 1 },
      [`[ -f '${filePath}' ]`]: { code: 1 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-repository-${sha256String("docker").slice(0, 16)}-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${expectedFlag}'`]:
        { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
    })
    const mod = apt.repository("docker", sourceWithForeignSignedBy)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.writeFileCalls).toStrictEqual([
      {
        content: `${expectedContent}\n`,
        options: { mode: "0644" },
        remotePath: filePath,
      },
    ])
  })

  // R-0000051 regression: tabs / multiple spaces / trailing whitespace are
  // semantically equivalent to single-space-separated fields in apt source
  // lines and must not flap the check between `ok` and `needs-apply`.
  it("check returns ok when on-disk content uses tabs as separators", async () => {
    const tabbed =
      "deb\t[signed-by=/etc/apt/keyrings/docker.gpg]\thttps://download.docker.com/linux/ubuntu\tnoble\tstable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: tabbed },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when on-disk content uses multiple spaces between fields", async () => {
    const spaced =
      "deb   [signed-by=/etc/apt/keyrings/docker.gpg]   https://download.docker.com/linux/ubuntu   noble   stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: spaced },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when on-disk content has trailing whitespace", async () => {
    const trailing = `${expectedContentWithSignedBy}   \t  `
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: trailing },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when content semantically differs (different suite)", async () => {
    const driftedContent =
      "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: driftedContent },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when repository file mode drifted", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
      [`stat -c '%a' '${filePath}'`]: { stdout: "600" },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when update marker is missing", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
      [updateFlagCheck]: { code: 1 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply sets update marker only after apt-get update succeeds", async () => {
    const markerCommand = `find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-repository-${sha256String("docker").slice(0, 16)}-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${updateFlag}'`
    const updateCommand = "DEBIAN_FRONTEND=noninteractive apt-get update"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 1 },
      [`[ -f '${filePath}' ]`]: { code: 1 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [markerCommand]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      [updateCommand]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)
    const updateIndex = ssh.calls.indexOf(updateCommand)
    const markerIndex = ssh.calls.indexOf(markerCommand)

    expect(result.status).toBe("changed")
    expect(updateIndex).toBeGreaterThan(-1)
    expect(markerIndex).toBeGreaterThan(-1)
    expect(updateIndex).toBeLessThan(markerIndex)
  })

  it("apply does not set update marker when apt-get update fails", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 1 },
      [`[ -f '${filePath}' ]`]: { code: 1 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`rm -f '${filePath}'`]: { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain(
      `find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-repository-${sha256String("docker").slice(0, 16)}-*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${updateFlag}'`
    )
  })

  it("apply rolls back the repository file when apt-get update fails", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    // R-0000753: after writeFile, the on-disk content is the new applied
    // content; the rollback drift check reads sha256sum at that point and
    // expects it to match the applied hash.
    const appliedContent = `${expectedContentWithSignedBy}\n`
    const appliedContentSha = sha256String(appliedContent)
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      // R-0000702: stat probe reports a stable device:inode pair so the
      // snapshot identity matches on re-probe inside the integrity check.
      [`stat -c '%d:%i' '${filePath}'`]: { code: 0, stdout: "42:1234\n" },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 1 },
    })
    // First sha256 read happens during the pre-write integrity check (file
    // still has the previous content); the second read happens during the
    // rollback drift check (file now has the applied content).
    let shaCallIndex = 0
    ssh.sha256 = async () => {
      await Promise.resolve()
      shaCallIndex += 1
      // oxlint-disable-next-line no-conditional-in-test -- sequential read returning different values for pre-write integrity vs rollback drift is exactly the scenario under test
      return shaCallIndex === 1 ? previousContentSha : appliedContentSha
    }
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.writeFileCalls).toStrictEqual([
      {
        content: appliedContent,
        options: { mode: "0644" },
        remotePath: filePath,
      },
      {
        content: previousContent,
        options: { mode: "0644" },
        remotePath: filePath,
      },
    ])
  })

  // R-0000163: after a failed `apt-get update` the on-disk source list is
  // restored, but apt's cache still reflects the failed update. The module
  // must run `apt-get update` again to bring the in-memory cache back into
  // sync with the restored source list.
  it("R-0000163: re-runs apt-get update after a successful rollback to refresh the cache", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    // R-0000753: rollback drift check reads sha256 after writeFile; supply
    // the applied content hash for that second read so the rollback proceeds.
    const appliedContentSha = sha256String(`${expectedContentWithSignedBy}\n`)
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      // R-0000702: stat probe reports a stable device:inode pair so the
      // snapshot identity matches on re-probe inside the integrity check.
      [`stat -c '%d:%i' '${filePath}'`]: { code: 0, stdout: "42:1234\n" },
    })
    let shaCallIndex = 0
    ssh.sha256 = async () => {
      await Promise.resolve()
      shaCallIndex += 1
      // oxlint-disable-next-line no-conditional-in-test -- sequential read returning different values for pre-write integrity vs rollback drift is exactly the scenario under test
      return shaCallIndex === 1 ? previousContentSha : appliedContentSha
    }
    // Override apt-get update so the first invocation (with the new repo)
    // fails and the second (post-rollback, with the restored sources)
    // succeeds — this is the precise sequence required by R-0000163.
    // The original mock exec is reused as passthrough so the stat probe
    // (R-0000702) and other stubbed commands still resolve.
    const originalExec = ssh.exec
    const sequencedAptGetUpdate = createSequencedAptGetUpdateExec(async (command) =>
      originalExec(command, { ignoreExitCode: true })
    )
    ssh.exec = sequencedAptGetUpdate.exec

    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(sequencedAptGetUpdate.callCount()).toBe(2)
    // The error reflects the original update failure, not the rollback update.
    expect(String(result.error)).toContain("apt-get update failed")
    expect(String(result.error)).not.toContain("rollback succeeded but apt-get update")
  })

  // R-0000753: when the sources.list has drifted between writeFile and
  // rollback (operator hotfix, another agent, packaging script), refuse to
  // overwrite the drifted content with the snapshot. The original update
  // failure must still be surfaced.
  it("R-0000753: refuses rollback when sources.list has drifted since snapshot", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    const driftedSha = sha256String("operator-hotfix\n")
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%d:%i' '${filePath}'`]: { code: 0, stdout: "42:1234\n" },
      "DEBIAN_FRONTEND=noninteractive apt-get update": {
        code: 1,
        stderr: "E: Repository not signed",
      },
    })
    // First sha256 read is the pre-write integrity check (matches snapshot);
    // second read is the rollback drift check and returns a hash that
    // matches neither snapshot nor applied content — operator hotfix.
    let shaCallIndex = 0
    ssh.sha256 = async () => {
      await Promise.resolve()
      shaCallIndex += 1
      // oxlint-disable-next-line no-conditional-in-test -- sequential read returning different values for pre-write integrity vs rollback drift is exactly the scenario under test
      return shaCallIndex === 1 ? previousContentSha : driftedSha
    }
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("apt-get update failed for docker")
    expect(String(result.error)).toContain("rollback refused")
    expect(String(result.error)).toContain("file has drifted since snapshot")
    // The drift refusal must abort before the snapshot content is written
    // back: only the first (apply-time) writeFile call should have happened.
    expect(ssh.writeFileCalls).toStrictEqual([
      {
        content: `${expectedContentWithSignedBy}\n`,
        options: { mode: "0644" },
        remotePath: filePath,
      },
    ])
  })

  it("R-0000163: surfaces both errors when the post-rollback apt-get update also fails", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    // R-0000753: rollback drift check reads sha256 after writeFile; supply
    // the applied content hash for that second read so the rollback proceeds.
    const appliedContentSha = sha256String(`${expectedContentWithSignedBy}\n`)
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      // R-0000702: stat probe reports a stable device:inode pair so the
      // snapshot identity matches on re-probe inside the integrity check.
      [`stat -c '%d:%i' '${filePath}'`]: { code: 0, stdout: "42:1234\n" },
      "DEBIAN_FRONTEND=noninteractive apt-get update": {
        code: 100,
        stderr: "E: Could not resolve 'broken.example.com'",
      },
    })
    let shaCallIndex = 0
    ssh.sha256 = async () => {
      await Promise.resolve()
      shaCallIndex += 1
      // oxlint-disable-next-line no-conditional-in-test -- sequential read returning different values for pre-write integrity vs rollback drift is exactly the scenario under test
      return shaCallIndex === 1 ? previousContentSha : appliedContentSha
    }
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("apt-get update failed")
    expect(String(result.error)).toContain(
      "rollback succeeded but apt-get update on the restored sources also failed"
    )
  })

  // R-0000702: a concurrent writer could atomically replace the sources.list
  // with byte-identical content sitting on a new inode (e.g. mktemp + mv -T).
  // The hash-only guard would let this slip past — the inode comparison
  // detects the swap and refuses to proceed.
  it("R-0000702: refuses to proceed when the sources.list inode changed between snapshot and write", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    let statCallIndex = 0
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`sha256sum '${filePath}'`]: { stdout: `${previousContentSha}  ${filePath}\n` },
    })
    const originalExec = ssh.exec
    ssh.exec = async (command, options) => {
      // oxlint-disable-next-line no-conditional-in-test -- command dispatch in the mock; the test asserts the integrity check refuses on inode change
      if (command === `stat -c '%d:%i' '${filePath}'`) {
        statCallIndex += 1
        // oxlint-disable-next-line no-conditional-in-test -- two sequential stat probes returning different inode identities is exactly the scenario under test
        return statCallIndex === 1
          ? { code: 0, stderr: "", stdout: "42:1234\n" }
          : { code: 0, stderr: "", stdout: "42:9999\n" }
      }
      return originalExec(command, options)
    }
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("inode changed between snapshot and write")
    // The integrity check must abort before any write call.
    expect(ssh.writeFileCalls).toStrictEqual([])
  })

  // R-0000702: a symlink that appears between the apply-time guard and the
  // integrity re-check must abort apply rather than letting `ssh.writeFile`
  // follow the link to an attacker-controlled target.
  it("R-0000702: refuses to proceed when a symlink appears between snapshot and write", async () => {
    const previousContent = "deb https://download.docker.com/linux/ubuntu jammy stable\n"
    const previousContentSha = sha256String(previousContent)
    let symlinkCallIndex = 0
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 0 },
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`sha256sum '${filePath}'`]: { stdout: `${previousContentSha}  ${filePath}\n` },
      [`stat -c '%d:%i' '${filePath}'`]: { code: 0, stdout: "42:1234\n" },
    })
    const originalTest = ssh.test
    ssh.test = async (command) => {
      // oxlint-disable-next-line no-conditional-in-test -- mock dispatcher selecting the symlink probe to flip on second call
      if (command === `[ -L '${filePath}' ]`) {
        symlinkCallIndex += 1
        // First probe (apply-time guard) reports no symlink, the second
        // probe (inside ensureAptRepositorySnapshotStillCurrent) reports a
        // freshly planted symlink — apply must refuse.
        return symlinkCallIndex >= 2
      }
      return originalTest(command)
    }
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("became a symlink between snapshot and write")
    expect(ssh.writeFileCalls).toStrictEqual([])
  })

  // R-0000098 regression: name lands directly in
  // `/etc/apt/sources.list.d/${name}.list` and must reject path-traversal
  // segments (`..`, slashes, empty string) before any shell command
  // is constructed.
  it("throws when name contains '..' (path traversal)", () => {
    expect(() => apt.repository("../../tmp/evil", source)).toThrow(/must not contain '\.\.'/v)
  })

  it("throws when name contains a path separator", () => {
    expect(() => apt.repository("foo/bar", source)).toThrow(/must match/v)
  })

  it("throws when name is empty", () => {
    expect(() => apt.repository("", source)).toThrow(/must match/v)
  })

  // R-0000235 regression: a symlink at the sources.list path must be treated
  // as "not present" by check (so apply runs) and rejected by apply before
  // any writeFile call follows the link to an attacker-controlled target.
  // Mirrors the apt.key (R-0000134) hardening.
  it("check returns needs-apply when the sources.list path is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ] && [ ! -L '${filePath}' ]`]: { code: 1 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain(`cat '${filePath}'`)
  })

  it("apply refuses to write through a symlinked sources.list path", async () => {
    const ssh = createMockSsh({
      [`[ -L '${filePath}' ]`]: { code: 0 },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      `[apt.repository] refuses to write through symlink at ${filePath}`
    )
    expect(ssh.writeFileCalls).toStrictEqual([])
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get update")
  })
})

describe("apt.debconf", () => {
  const selections = { "postfix/main_mailer_type": "Internet Site" }
  const dpkgInstalled = { code: 0, stdout: "install ok installed" }
  const dpkgNotInstalled = { code: 1, stdout: "" }

  it("check returns ok when debconf-show output matches selections", async () => {
    const ssh = createMockSsh({
      "debconf-show 'postfix'": {
        code: 0,
        stdout: "* postfix/main_mailer_type: Internet Site",
      },
      "dpkg-query -W -f='${Status}' 'postfix'": dpkgInstalled,
    })
    const mod = apt.debconf("postfix", selections)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when values do not match", async () => {
    const ssh = createMockSsh({
      "debconf-show 'postfix'": {
        code: 0,
        stdout: "* postfix/main_mailer_type: Local only",
      },
      "dpkg-query -W -f='${Status}' 'postfix'": dpkgInstalled,
    })
    const mod = apt.debconf("postfix", selections)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.debconf("postfix", selections)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when debconf-show fails on an installed package", async () => {
    const ssh = createMockSsh({
      "debconf-show 'postfix'": { code: 1, stdout: "" },
      "dpkg-query -W -f='${Status}' 'postfix'": dpkgInstalled,
    })
    const mod = apt.debconf("postfix", selections)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns a failed result with error details when selections contain newlines", async () => {
    const mod = apt.debconf("postfix", { "postfix/main_mailer_type": "Internet\nSite" })
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("must not contain CR or LF characters")
  })

  it("returns a failed result when a selection value contains carriage returns", async () => {
    const mod = apt.debconf("postfix", { "postfix/main_mailer_type": "Internet\rSite" })
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("must not contain CR or LF characters")
  })

  it("returns a failed result when packageName contains whitespace", async () => {
    const mod = apt.debconf("postfix injected", selections)
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "packageName must not be empty, start with '-', or contain whitespace"
    )
    expect(ssh.calls).not.toContain("debconf-set-selections")
  })

  it("returns a failed result when packageName contains CR or LF characters", async () => {
    const mod = apt.debconf("postfix\ninjected", selections)
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "packageName must not be empty, start with '-', or contain whitespace"
    )
    expect(ssh.calls).not.toContain("debconf-set-selections")
  })

  it("check returns needs-apply without probing dpkg when packageName starts with a dash", async () => {
    const ssh = createMockSsh({})
    const mod = apt.debconf("--status-fd=2", selections)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("dpkg-query -W -f='${Status}' '--status-fd=2'")
  })

  it("returns a failed result when packageName starts with a dash", async () => {
    const mod = apt.debconf("--status-fd=2", selections)
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "packageName must not be empty, start with '-', or contain whitespace"
    )
    expect(ssh.calls).not.toContain("debconf-set-selections")
  })

  it("returns a failed result when a debconf question contains whitespace", async () => {
    const mod = apt.debconf("postfix", { "postfix/main mailer type": "Internet Site" })
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "question for postfix must not be empty or contain whitespace"
    )
    expect(ssh.calls).not.toContain("debconf-set-selections")
  })

  it("returns a failed result when a debconf question contains CR or LF characters", async () => {
    const mod = apt.debconf("postfix", { "postfix/main_mailer_type\nowner": "Internet Site" })
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "question for postfix must not be empty or contain whitespace"
    )
    expect(ssh.calls).not.toContain("debconf-set-selections")
  })

  it("apply passes selections starting with a dash through stdin", async () => {
    const secretValue = "-n"
    const selectionsText = "pkg pkg/dash-value string -n"
    const packageHash = sha256String("pkg").slice(0, 16)
    const selectionsHash = sha256String(`pkg\n${selectionsText}`).slice(0, 16)
    const flagPath = `/var/lib/paratix/flags/'apt-debconf-${packageHash}-${selectionsHash}'`
    const ssh = createMockSsh({
      [`find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-debconf-${packageHash}-*' ! -name '*.lock' -delete && touch ${flagPath}`]:
        { code: 0 },
      "debconf-set-selections": { code: 0 },
      "echo 'METAGET pkg/dash-value type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.debconf("pkg", { "pkg/dash-value": secretValue })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result).toStrictEqual({ status: "changed" })
    expectDebconfSetSelectionsExecCall(ssh.execCalls, selectionsText, [secretValue])
    expect(ssh.calls).not.toContain("echo 'pkg pkg/dash-value string -n' | debconf-set-selections")
  })

  it("apply passes backslash sequences to debconf-set-selections through stdin", async () => {
    const secretValue = String.raw`a\tb\nc`
    const selectionsText = "pkg pkg/backslash-value string a\\tb\\nc"
    const packageHash = sha256String("pkg").slice(0, 16)
    const selectionsHash = sha256String(`pkg\n${selectionsText}`).slice(0, 16)
    const flagPath = `/var/lib/paratix/flags/'apt-debconf-${packageHash}-${selectionsHash}'`
    const ssh = createMockSsh({
      [`find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-debconf-${packageHash}-*' ! -name '*.lock' -delete && touch ${flagPath}`]:
        { code: 0 },
      "debconf-set-selections": { code: 0 },
      "echo 'METAGET pkg/backslash-value type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const mod = apt.debconf("pkg", { "pkg/backslash-value": secretValue })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result).toStrictEqual({ status: "changed" })
    expectDebconfSetSelectionsExecCall(ssh.execCalls, selectionsText, [secretValue])
    expectNoExecCommandLeaksSecrets(ssh.execCalls, [secretValue])
    expect(ssh.calls).not.toContain(
      "echo 'pkg pkg/backslash-value string a\\tb\\nc' | debconf-set-selections"
    )
  })

  it("apply masks selection values when debconf-set-selections fails", async () => {
    const ssh = createMockSsh({
      "debconf-set-selections": {
        code: 1,
        stderr: "invalid value super-secret-answer",
      },
      "echo 'METAGET pkg/secret type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
    })
    const mod = apt.debconf("pkg", { "pkg/secret": "super-secret-answer" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expectDebconfSetSelectionsExecCall(ssh.execCalls, "pkg pkg/secret string super-secret-answer", [
      "super-secret-answer",
    ])
    expectNoExecCommandLeaksSecrets(ssh.execCalls, ["super-secret-answer"])
    expect(String(result.error)).toContain("invalid value [REDACTED]")
    expect(String(result.error)).not.toContain("super-secret-answer")
    expect(result.error).toMatchObject({
      fullStderr: "invalid value [REDACTED]",
      fullStdout: "",
    })
  })

  // R-0000104 regression: when the package is not yet installed, the
  // first run reports `needs-apply`, `apply` writes a versioned marker
  // flag, and a subsequent `check` (still with the package not
  // installed) returns `ok`. Without the marker this would loop forever
  // because `debconf-show` exits non-zero for uninstalled packages.
  it("check returns ok on the second run after apply when the package is not installed", async () => {
    const packageName = "postfix"
    const selectionsText = "postfix postfix/main_mailer_type string Internet Site"
    const packageHash = sha256String(packageName).slice(0, 16)
    const selectionsHash = sha256String(`${packageName}\n${selectionsText}`).slice(0, 16)
    const flagPath = `/var/lib/paratix/flags/'apt-debconf-${packageHash}-${selectionsHash}'`
    const dpkgQuery = "dpkg-query -W -f='${Status}' 'postfix'"

    // First check: package not installed and marker absent.
    const ssh1 = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 1 },
      [dpkgQuery]: dpkgNotInstalled,
      "echo 'METAGET postfix/main_mailer_type type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
    })
    const mod = apt.debconf(packageName, selections)
    expect(await mod.check(ssh1, emptyEnv)).toBe("needs-apply")

    // Apply: package still not installed, debconf-set-selections
    // succeeds, marker flag is written via setVersionedFlag.
    const ssh2 = createMockSsh({
      [`find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-debconf-${packageHash}-*' ! -name '*.lock' -delete && touch ${flagPath}`]:
        { code: 0 },
      "debconf-set-selections": { code: 0 },
      [dpkgQuery]: dpkgNotInstalled,
      "echo 'METAGET postfix/main_mailer_type type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    expect(await mod.apply(ssh2, emptyEnv)).toStrictEqual({ status: "changed" })
    expectDebconfSetSelectionsExecCall(ssh2.execCalls, selectionsText, ["Internet Site"])
    expectNoExecCommandLeaksSecrets(ssh2.execCalls, ["Internet Site"])
    expect(ssh2.calls).toContain(
      `find /var/lib/paratix/flags -maxdepth 1 -type f -name 'apt-debconf-${packageHash}-*' ! -name '*.lock' -delete && touch ${flagPath}`
    )

    // Second check: package still not installed, marker flag exists →
    // must return ok instead of looping back into needs-apply.
    const ssh3 = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 0 },
      [dpkgQuery]: dpkgNotInstalled,
      "echo 'METAGET postfix/main_mailer_type type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
    })
    expect(await mod.check(ssh3, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when the package is not installed and no marker flag exists", async () => {
    const packageName = "postfix"
    const selectionsText = "postfix postfix/main_mailer_type string Internet Site"
    const packageHash = sha256String(packageName).slice(0, 16)
    const selectionsHash = sha256String(`${packageName}\n${selectionsText}`).slice(0, 16)
    const flagPath = `/var/lib/paratix/flags/'apt-debconf-${packageHash}-${selectionsHash}'`
    const ssh = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 1 },
      "dpkg-query -W -f='${Status}' 'postfix'": dpkgNotInstalled,
      "echo 'METAGET postfix/main_mailer_type type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
    })
    const mod = apt.debconf("postfix", selections)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })
})
