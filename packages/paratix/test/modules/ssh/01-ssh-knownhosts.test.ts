/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it } from "vitest"

import { computeFingerprint } from "../../../src/knownHosts.js"
import { ssh } from "../../../src/modules/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const knownHostsHome = "/home/paratix"
const knownHostsSshDirectory = `${knownHostsHome}/.ssh`
const knownHostsPath = `${knownHostsSshDirectory}/known_hosts`
const knownHostsTemporaryPath = `${knownHostsSshDirectory}/.paratix-known-hosts.ABC123`

const successfulSshApplyResponseStubs: NonNullable<MockSshOptions["responseStubs"]> = [
  { command: "printf '%s' \"$HOME\"", result: { stdout: knownHostsHome } },
  {
    command:
      "[ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/paratix/.ssh' ]; then [ -d '/home/paratix/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/paratix/.ssh'; fi; [ -d '/home/paratix/.ssh' ] && [ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/paratix/.ssh'",
    result: { code: 0 },
  },
  {
    command:
      "[ ! -L '/home/paratix/.ssh/known_hosts' ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }",
    result: { code: 0 },
  },
  { command: "[ -e '/home/paratix/.ssh/known_hosts' ]", result: { code: 1 } },
  { command: "[ -L '/home/paratix/.ssh' ]", result: { code: 1 } },
  { command: "[ -L '/home/paratix/.ssh/known_hosts' ]", result: { code: 1 } },
  {
    command: /^grep -qxF '[^']+' '\/home\/paratix\/\.ssh\/known_hosts'$/v,
    result: { code: 1 },
  },
  {
    command: "mktemp -p '/home/paratix/.ssh' -- '.paratix-known-hosts.XXXXXX'",
    result: { stdout: knownHostsTemporaryPath },
  },
  {
    command: /^ssh-keygen -F '[^']+' -f '\/home\/paratix\/\.ssh\/known_hosts'$/v,
    result: { code: 1 },
  },
  {
    command:
      /^\{ if \[ -e '\/home\/paratix\/\.ssh\/known_hosts' \]; then .+\.paratix-known-hosts\.ABC123.+; \}$/v,
    result: { code: 0 },
  },
  {
    command: /^printf '%s\\n' .+ > '\/home\/paratix\/\.ssh\/\.paratix-known-hosts\.ABC123'$/v,
    result: { code: 0 },
  },
  {
    command:
      /^chmod 600 '\/home\/paratix\/\.ssh\/\.paratix-known-hosts\.ABC123' && \{ expected_known_hosts_hash=/v,
    result: { code: 0 },
  },
  { command: "rm -f '/home/paratix/.ssh/.paratix-known-hosts.ABC123'", result: { code: 0 } },
  { command: /^ssh-keygen -F '[^']+'$/v, result: { code: 1 } },
  { command: /^ssh-keygen -R '[^']+'$/v, result: { code: 0 } },
  {
    command: /^ssh-keygen -R '[^']+' -f '\/home\/paratix\/\.ssh\/known_hosts'$/v,
    result: { code: 0 },
  },
  {
    command:
      /^\[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must not be a symlink' >&2; exit 1; \}; if \[ -e '[^']+\/\.ssh' \]; then \[ -d '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a directory' >&2; exit 1; \}; else mkdir -p '[^']+\/\.ssh'; fi; \[ -d '[^']+\/\.ssh' \] && \[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a real directory' >&2; exit 1; \}; chmod 700 '[^']+\/\.ssh' && chown '[^']+':'[^']+' '[^']+\/\.ssh'$/v,
    result: { code: 0 },
  },
  {
    command:
      /^\[ ! -L '[^']+\/\.ssh\/authorized_keys' \] \|\| \{ echo 'authorized_keys must not be a symlink' >&2; exit 1; \}$/v,
    result: { code: 0 },
  },
  { command: "install -d -m 700 -o root -g root '/run/paratix'", result: { code: 0 } },
  {
    command: /^\{ if \[ -f '[^']+\/\.ssh\/authorized_keys' \]; then .+; fi; \}$/v,
    result: { code: 0 },
  },
  {
    command: /^chmod 600 '\/run\/paratix\/authorized-keys\.[^']+' && chown /v,
    result: { code: 0 },
  },
  { command: /^rm -f '\/run\/paratix\/authorized-keys\.[^']+'$/v, result: { code: 0 } },
]

const successfulSshApplyOptions: MockSshOptions = {
  responseStubs: successfulSshApplyResponseStubs,
}

// R-0000: resolveKnownHostsPaths now queries the remote $HOME via
// `printf '%s' "$HOME"`. Inject a default stub so individual tests do not
// have to repeat this boilerplate. Caller-provided responseStubs are merged
// after the default and take precedence on their own commands.
const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    responseStubs: [
      { command: "printf '%s' \"$HOME\"", result: { stdout: knownHostsHome } },
      ...(options?.responseStubs ?? []),
    ],
  })

function createSshApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulSshApplyOptions)
}

const emptyEnv = {}

// Helper used by R-0000044 regression: locate the authorized_keys rewrite
// command (the one that pipes grep into the staging path). Lifted out of
// the test body so eslint-plugin-jest's `no-conditional-in-test` rule
// does not flag the predicate.
function includesGrepRewrite(command: string): boolean {
  return command.includes(" > '") && command.includes("grep")
}

function isKnownHostsAppend(command: string): boolean {
  return (
    command.startsWith("printf '%s\\n' ") && command.endsWith(" >> /home/paratix/.ssh/known_hosts")
  )
}

function isKnownHostsRewriteStage(command: string): boolean {
  return (
    command.startsWith("{ if [ -e '/home/paratix/.ssh/known_hosts' ];") ||
    command.startsWith("printf '%s\\n' ")
  )
}

function isKnownHostsFinalReplace(command: string): boolean {
  return command.startsWith("chmod 600 '/home/paratix/.ssh/.paratix-known-hosts.ABC123'")
}

function makeHostKeyBuffer(algo: string, keyData = Buffer.from("fake-host-key-data")): Buffer {
  const algoBytes = Buffer.from(algo)
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(algoBytes.length)
  return Buffer.concat([lengthBuffer, algoBytes, keyData])
}

function presentAuthorizedKeysRewriteCommand(
  authorizedKeysPath: string,
  temporaryPath: string,
  key: string
): string {
  return `{ if [ -f ${authorizedKeysPath} ]; then awk '1' ${authorizedKeysPath} > '${temporaryPath}' || exit $?; grep -qxF -- '${key}' ${authorizedKeysPath}; grep_status=$?; if [ "$grep_status" -eq 0 ]; then :; elif [ "$grep_status" -eq 1 ]; then printf '%s\\n' '${key}' >> '${temporaryPath}'; else exit "$grep_status"; fi; else printf '%s\\n' '${key}' > '${temporaryPath}'; fi; }`
}

function absentAuthorizedKeysRewriteCommand(
  authorizedKeysPath: string,
  temporaryPath: string,
  key: string
): string {
  return `{ if [ -f ${authorizedKeysPath} ]; then grep -vxF -- '${key}' ${authorizedKeysPath} > '${temporaryPath}'; grep_status=$?; if [ "$grep_status" -eq 0 ] || [ "$grep_status" -eq 1 ]; then :; else exit "$grep_status"; fi; else : > '${temporaryPath}'; fi; }`
}

function authorizedKeysFinalReplaceCommand(parameters: {
  authorizedKeysPath: string
  expectedSshDirectoryState: string
  group: string
  sshDirectoryPath: string
  temporaryPath: string
  user: string
}): string {
  const {
    authorizedKeysPath,
    expectedSshDirectoryState,
    group,
    sshDirectoryPath,
    temporaryPath,
    user,
  } = parameters
  return `chmod 600 '${temporaryPath}' && chown '${user}':'${group}' '${temporaryPath}' && { [ ! -L ${sshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; [ -d ${sshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }; ssh_directory_state=$(stat -c '%a %U %G %F' ${sshDirectoryPath}) || exit $?; [ "$ssh_directory_state" = '${expectedSshDirectoryState}' ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }; [ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }; mv -T '${temporaryPath}' ${authorizedKeysPath}; }`
}

/**
 * Wrap a fresh mock SSH connection that reflects a virtual
 * `/home/paratix/.ssh/known_hosts` file across two apply runs so the R-0000038
 * regression test can assert idempotent behaviour without using
 * conditionals inside the test body. The grep test reflects whether the
 * tracked line is present; the printf-append exec records the line as added.
 *
 * @param line - The verified host-key line that the test simulates.
 * @param baseResponses - Base responses for unrelated commands (e.g.
 *   `ssh-keyscan`).
 * @returns A mock SSH connection whose `test` and `exec` track the virtual
 *   known_hosts state.
 */
function createKnownHostsTrackingMock(
  line: string,
  baseResponses: Record<string, { code?: number; stderr?: string; stdout?: string }>
): ReturnType<typeof createMockSsh> {
  const grepCommand = `grep -qxF '${line}' '/home/paratix/.ssh/known_hosts'`
  // R-0000626: the append-branch reads the existing known_hosts via
  // `dd ... iflag=nofollow` so the open(2) uses `O_NOFOLLOW` and the
  // TOCTOU window between the `[ ! -L ]` probe and the read is closed.
  const stageCommand = `{ if [ -e '/home/paratix/.ssh/known_hosts' ]; then [ ! -L '/home/paratix/.ssh/known_hosts' ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }; [ -f '/home/paratix/.ssh/known_hosts' ] || { echo 'known_hosts must be a regular file' >&2; exit 1; }; dd if='/home/paratix/.ssh/known_hosts' iflag=nofollow status=none of='/home/paratix/.ssh/.paratix-known-hosts.ABC123' || exit $?; else : > '/home/paratix/.ssh/.paratix-known-hosts.ABC123'; fi; grep -qxF '${line}' '/home/paratix/.ssh/.paratix-known-hosts.ABC123'; grep_status=$?; if [ "$grep_status" -eq 0 ]; then :; elif [ "$grep_status" -eq 1 ]; then printf '%s\\n' '${line}' >> '/home/paratix/.ssh/.paratix-known-hosts.ABC123'; else exit "$grep_status"; fi; }`
  let present = false
  const base = createSshApplyMockSsh(baseResponses)
  return {
    ...base,
    async exec(command: string, options?: Parameters<typeof base.exec>[1]) {
      const result = await base.exec(command, options)
      if (command === stageCommand) present = true
      return result
    },
    test: async (command: string): Promise<boolean> =>
      command === grepCommand ? present : base.test(command),
  }
}

describe("ssh.knownHosts", () => {
  const hostKeyBuffer = makeHostKeyBuffer("ssh-ed25519")
  const hostKeyBase64 = hostKeyBuffer.toString("base64")
  const hostPublicKey = `ssh-ed25519 ${hostKeyBase64}`
  const hostFingerprint = computeFingerprint(hostKeyBuffer)
  const scannedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${hostKeyBase64}`

  it("check returns ok when host is already known and trust anchor matches (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when the known_hosts entry matches the expected fingerprint", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the known_hosts entry mismatches the expected public key", async () => {
    const mismatchedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("different-host-key"))
    const mismatchedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${mismatchedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${mismatchedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: hostPublicKey })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the known_hosts entry has drifted from the expected fingerprint", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${driftedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when known_hosts contains the pinned key plus an unpinned key", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("extra-host-key"))
    const extraLine = `|1|hashed-host|hashed-extra ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${scannedLine}\n${extraLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when an older entry exists even if one line matches the expected fingerprint", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-old ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${driftedLine}\n${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when another algorithm exists even if one line matches the expected public key", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("legacy-rsa-key"))
    const extraLine = `|1|hashed-host|hashed-rsa ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${extraLine}\n${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: hostPublicKey })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  // R-0000252: `lineMatchesTrustAnchor` previously called `scannedLinePublicKey`
  // directly, which throws when a known_hosts entry has fewer than three
  // whitespace-separated fields (truncated write, partial corruption, garbage
  // appended after a crash). That uncaught exception escaped past `check`,
  // breaking the entire module on a single damaged line. The fix swallows
  // parse errors and treats malformed lines as drift so the apply-path can
  // replace them via ssh-keygen -R.
  it("R-0000252: check returns needs-apply when a known_hosts line is malformed", async () => {
    const malformedLine = "garbage-only-one-field"
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${malformedLine}\n${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  // R-0000252 (companion): an entirely corrupt known_hosts file (no parseable
  // lines) must also resolve to a boolean needs-apply rather than throwing.
  it("R-0000252: check returns needs-apply when every known_hosts line is malformed", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: "garbage\nmore garbage\n",
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check uses a bracketed known_hosts lookup target for non-standard ports", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F '[github.com]:2222' -f '${knownHostsPath}'`]: {
        code: 0,
        stdout: `${scannedLine}\n`,
      },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: hostFingerprint,
      port: 2222,
    })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns needs-apply when host is not known (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.execCalls).toContainEqual({
      command: `ssh-keygen -F 'github.com' -f '${knownHostsPath}'`,
      options: { ignoreExitCode: true, silent: true },
    })
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when host is not known (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when host is known (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check surfaces ssh-keygen lookup failures for absent state", async () => {
    const mockSsh = createMockSsh({
      [`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`]: {
        code: 255,
        stderr: "ssh-keygen: failed to parse known_hosts: corrupt entry\n",
      },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })

    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(
      "ssh-keygen -F exited with unexpected code 255"
    )
  })

  it("apply verifies a scanned host key against the expected fingerprint before appending it", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      "[ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/paratix/.ssh' ]; then [ -d '/home/paratix/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/paratix/.ssh'; fi; [ -d '/home/paratix/.ssh' ] && [ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/paratix/.ssh'"
    )
    expect(mockSsh.calls).toContain("ssh-keyscan -H 'github.com'")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(true)
    expect(mockSsh.calls.some(isKnownHostsFinalReplace)).toBe(true)
  })

  it("apply verifies a scanned host key against the expected public key before appending it", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: `${hostPublicKey} github.com` })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(true)
    expect(mockSsh.calls.some(isKnownHostsFinalReplace)).toBe(true)
  })

  it("apply scans the configured non-standard port before appending a verified host key", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
      "ssh-keyscan -p 2222 -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: hostFingerprint,
      port: 2222,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keyscan -p 2222 -H 'github.com'")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(true)
    expect(mockSsh.calls.some(isKnownHostsFinalReplace)).toBe(true)
  })

  it("apply persists only the scanned line that matches the configured trust anchor", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("extra-host-key"))
    const extraLine = `|1|hashed-host|hashed-extra ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n${extraLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.filter(isKnownHostsRewriteStage)).toHaveLength(1)
    expect(mockSsh.calls.some((command) => command.includes(extraLine))).toBe(false)
  })

  it("apply replaces mixed known_hosts entries with verified host key lines", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-old ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'": {
        code: 0,
        stdout: `${driftedLine}\n${scannedLine}\n`,
      },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain("ssh-keygen -R 'github.com'")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(true)
    expect(mockSsh.calls.some(isKnownHostsFinalReplace)).toBe(true)
  })

  it("apply skips appending lines already present in known_hosts (R-0000038 idempotency)", async () => {
    // Regression for R-0000038: when the verified line is already in
    // /home/paratix/.ssh/known_hosts (grep -qxF returns code 0), the apply path must not
    // append it again. A second consecutive run therefore produces neither
    // duplicates nor a second `printf >> known_hosts` call, and reports ok.
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 0 },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    const printfCalls = mockSsh.calls.filter((c) => c.startsWith("printf '%s\\n'"))
    expect(printfCalls).toHaveLength(0)
  })

  it("running apply twice does not duplicate entries in known_hosts (R-0000038 regression)", async () => {
    // Regression for R-0000038: simulate a known_hosts file that starts empty,
    // then becomes populated after the first apply. The second apply must
    // detect the line as already present and skip the append, so each line
    // appears exactly once across runs.
    const mockSsh = createKnownHostsTrackingMock(scannedLine, {
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })

    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const firstResult = await mod.apply(mockSsh, emptyEnv)
    expect(firstResult.status).toBe("changed")

    const secondResult = await mod.apply(mockSsh, emptyEnv)
    expect(secondResult.status).toBe("ok")

    const stageCalls = mockSsh.calls.filter(isKnownHostsRewriteStage)
    expect(stageCalls).toHaveLength(1)
  })

  // R-0000173: when ssh-keygen -F exits with an unexpected code (corrupt
  // known_hosts → 255, argument error → 2), apply must surface a failed
  // ModuleResult. Treating these as "host not found" would silently apply
  // on a damaged file without telling the operator.
  it("apply returns failed when ssh-keygen -F exits with code 255 (corrupted known_hosts)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      [`ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'`]: {
        code: 255,
        stderr: "ssh-keygen: failed to parse known_hosts: corrupt entry\n",
      },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: hostFingerprint,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ssh-keygen -F exited with unexpected code 255")
  })

  // R-0000170: trust-anchor mismatches must surface as a failed
  // ModuleResult, not an uncaught exception, so callers see a maskable
  // failure consistent with other modules.
  it("apply returns failed when scanned keys do not match the expected fingerprint", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    })

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("could not verify the scanned host key")
    expect(result.error?.message).toContain("[ssh.knownHosts: github.com (present)]")
  })

  it("rejects present state without a fingerprint or public key trust anchor at construction time", () => {
    expect(() => ssh.knownHosts("github.com")).toThrow("requires expectedFingerprint or publicKey")
  })

  it("rejects present state with an empty options object at construction time", () => {
    expect(() => ssh.knownHosts("github.com", {})).toThrow(
      "requires expectedFingerprint or publicKey"
    )
  })

  it("rejects present state with only a port option at construction time", () => {
    expect(() => ssh.knownHosts("github.com", { port: 2222 })).toThrow(
      "requires expectedFingerprint or publicKey"
    )
  })

  it.each(["", "-H github.com", "github.com other", "github.com\nother"])(
    "rejects unsafe known_hosts hosts for present state: %s",
    (host) => {
      expect(() =>
        ssh.knownHosts(host, {
          expectedFingerprint: hostFingerprint,
        })
      ).toThrow(
        "ssh.knownHosts host must not be empty, start with '-', or contain whitespace/control characters"
      )
    }
  )

  it.each(["", "-R github.com", "github.com other", "github.com\nother"])(
    "rejects unsafe known_hosts hosts for absent state: %s",
    (host) => {
      expect(() => ssh.knownHosts(host, { state: "absent" })).toThrow(
        "ssh.knownHosts host must not be empty, start with '-', or contain whitespace/control characters"
      )
    }
  )

  it.each([0, 65_536, 22.5, Number.NaN, "22"])(
    "rejects invalid known_hosts ports for present state: %s",
    (port) => {
      expect(() =>
        ssh.knownHosts("github.com", {
          expectedFingerprint: hostFingerprint,
          port: port as never,
        })
      ).toThrow("ssh.knownHosts(github.com) port must be an integer between 1 and 65535")
    }
  )

  it.each([0, 65_536, 22.5, Number.NaN, "22"])(
    "rejects invalid known_hosts ports for absent state: %s",
    (port) => {
      expect(() => ssh.knownHosts("github.com", { port: port as never, state: "absent" })).toThrow(
        "ssh.knownHosts(github.com) port must be an integer between 1 and 65535"
      )
    }
  )

  it("does not reject the construction-time call when state is absent and no trust anchor is set", () => {
    expect(() => ssh.knownHosts("github.com", { state: "absent" })).not.toThrow()
  })

  it("accepts known_hosts present state", () => {
    expect(() =>
      ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint, state: "present" })
    ).not.toThrow()
  })

  it("accepts known_hosts absent state", () => {
    expect(() => ssh.knownHosts("github.com", { state: "absent" })).not.toThrow()
  })

  it.each(["remove", "", "present "] as const)(
    "rejects invalid known_hosts string state: %s",
    (state) => {
      expect(() => ssh.knownHosts("github.com", { state: state as never })).toThrow(
        'ssh.knownHosts state must be "present" or "absent"'
      )
    }
  )

  it.each([false, 0, null] as const)("rejects non-string known_hosts state: %s", (state) => {
    expect(() => ssh.knownHosts("github.com", { state: state as never })).toThrow(
      'ssh.knownHosts state must be "present" or "absent"'
    )
  })

  it("apply removes host via ssh-keygen -R (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      "ssh-keygen -R 'github.com' -f '/home/paratix/.ssh/known_hosts'"
    )
  })

  it("apply returns ok and skips ssh-keygen -R when the host is not in known_hosts (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'": { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain(
      "ssh-keygen -R 'github.com' -f '/home/paratix/.ssh/known_hosts'"
    )
  })

  it("apply returns failed and skips ssh-keygen -R when absent lookup fails", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'": {
        code: 255,
        stderr: "ssh-keygen: failed to parse known_hosts: corrupt entry\n",
      },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ssh-keygen -F exited with unexpected code 255")
    expect(mockSsh.calls).not.toContain(
      "ssh-keygen -R 'github.com' -f '/home/paratix/.ssh/known_hosts'"
    )
  })

  it("apply removes a non-standard-port host entry via a bracketed ssh-keygen -R target", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F '[github.com]:2222' -f '/home/paratix/.ssh/known_hosts'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { port: 2222, state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      "ssh-keygen -R '[github.com]:2222' -f '/home/paratix/.ssh/known_hosts'"
    )
  })

  // R-0000212: the absent path previously called `conn.exec` without
  // `ignoreExitCode`, so a permission-denied or corrupted-known_hosts error
  // would propagate as an uncaught exception. The fix mirrors R-0000170 for
  // the present-state path: surface a failedCommand result instead.
  it("R-0000212: apply returns failedCommand when ssh-keygen -R fails (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ -e '/home/paratix/.ssh/known_hosts' ]": { code: 0 },
      "ssh-keygen -F 'github.com' -f '/home/paratix/.ssh/known_hosts'": { code: 0 },
      "ssh-keygen -R 'github.com' -f '/home/paratix/.ssh/known_hosts'": {
        code: 255,
        stderr: "/root/.ssh/known_hosts: Permission denied",
      },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[ssh.knownHosts: github.com (absent)]")
    expect(String(result.error)).toContain("ssh-keygen -R failed")
  })

  // R-0000215: the final known_hosts write can fail (permission denied,
  // ENOSPC). Surface a failedCommand result instead of throwing.
  it("R-0000215: apply returns failedCommand when the known_hosts stage fails", async () => {
    const mockSsh = createMockSsh(
      {
        [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
        "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
      },
      {
        responseStubs: [
          {
            command:
              /^\{ if \[ -e '\/home\/paratix\/\.ssh\/known_hosts' \]; then .+\.paratix-known-hosts\.ABC123.+; \}$/v,
            result: {
              code: 1,
              stderr: "sh: 1: cannot create known_hosts staging file: No space left on device",
            },
          },
          ...successfulSshApplyResponseStubs,
        ],
      }
    )
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[ssh.knownHosts: github.com (present)]")
    expect(String(result.error)).toContain("failed to stage known_hosts rewrite")
  })

  it("apply rejects a symlinked known_hosts file before staging", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ ! -L '/home/paratix/.ssh/known_hosts' ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }":
        {
          code: 1,
          stderr: "known_hosts must not be a symlink",
        },
      [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("known_hosts symlink check failed")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(false)
  })

  it("apply rejects a symlinked .ssh directory before staging", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/paratix/.ssh' ]; then [ -d '/home/paratix/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/paratix/.ssh'; fi; [ -d '/home/paratix/.ssh' ] && [ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/paratix/.ssh'":
        {
          code: 1,
          stderr: ".ssh must not be a symlink",
        },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to prepare .ssh directory")
    expect(mockSsh.calls.some(isKnownHostsRewriteStage)).toBe(false)
  })

  it("apply returns failedCommand when the final known_hosts recheck fails", async () => {
    const mockSsh = createMockSsh(
      {
        [`grep -qxF '${scannedLine}' '/home/paratix/.ssh/known_hosts'`]: { code: 1 },
        "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
      },
      {
        responseStubs: [
          {
            command:
              /^chmod 600 '\/home\/paratix\/\.ssh\/\.paratix-known-hosts\.ABC123' && \{ expected_known_hosts_hash=/v,
            result: {
              code: 1,
              stderr: "known_hosts was recreated during replace; refusing to clobber",
            },
          },
          ...successfulSshApplyResponseStubs,
        ],
      }
    )
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to replace known_hosts")
  })

  // R-0000214: ssh-keyscan exits non-zero when the host is unreachable, the
  // port is closed, or DNS fails. The previous `conn.output` call propagated
  // that as an uncaught exception even though `2>/dev/null` suppressed the
  // diagnostic. Surface a failedCommand result instead.
  it("R-0000214: apply returns failedCommand when ssh-keyscan exits non-zero", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keyscan -H 'github.com'": {
        code: 1,
        stderr: "ssh-keyscan: getaddrinfo: github.com: Name or service not known",
      },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[ssh.knownHosts: github.com (present)]")
    expect(String(result.error)).toContain("ssh-keyscan failed")
  })

  // R-0000245: `[ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/paratix/.ssh' ]; then [ -d '/home/paratix/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/paratix/.ssh'; fi; [ -d '/home/paratix/.ssh' ] && [ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/paratix/.ssh'` previously ran without
  // `ignoreExitCode`, so a symlinked ~/.ssh or a permission error would
  // surface as an uncaught exception. Mirror R-0000212/213/214/215 by
  // surfacing a failedCommand result instead.
  it("R-0000245: apply returns failedCommand when ~/.ssh preparation fails", async () => {
    const mockSsh = createSshApplyMockSsh({
      "[ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/paratix/.ssh' ]; then [ -d '/home/paratix/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/paratix/.ssh'; fi; [ -d '/home/paratix/.ssh' ] && [ ! -L '/home/paratix/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/paratix/.ssh'":
        {
          code: 1,
          stderr: "mkdir: cannot create directory '/home/user/.ssh': Permission denied",
        },
      "ssh-keyscan -H 'github.com'": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[ssh.knownHosts: github.com (present)]")
    expect(String(result.error)).toContain("failed to prepare .ssh directory")
    // Neither the trust-anchor lookup nor the append should run after the
    // mkdir failure.
    expect(mockSsh.calls).not.toContain(`ssh-keygen -F 'github.com' -f '${knownHostsPath}'`)
    expect(mockSsh.calls.some((c) => c.startsWith("printf '%s\\n'"))).toBe(false)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
