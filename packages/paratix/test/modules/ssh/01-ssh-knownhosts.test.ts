/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it } from "vitest"

import { computeFingerprint } from "../../../src/knownHosts.js"
import { ssh } from "../../../src/modules/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const successfulSshApplyOptions: MockSshOptions = {
  responseStubs: [
    { command: "mkdir -p ~/.ssh && chmod 700 ~/.ssh", result: { code: 0 } },
    { command: /^ssh-keygen -F '[^']+'$/v, result: { code: 1 } },
    { command: /^ssh-keygen -R '[^']+'$/v, result: { code: 0 } },
    {
      command: /^printf '%s\\n' '[^']+' >> ~\/\.ssh\/known_hosts$/v,
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
  ],
}

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
  return command.startsWith("printf '%s\\n' ") && command.endsWith(" >> ~/.ssh/known_hosts")
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
 * `~/.ssh/known_hosts` file across two apply runs so the R-0000038
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
  const grepCommand = `grep -qxF '${line}' ~/.ssh/known_hosts`
  const printfCommand = `printf '%s\\n' '${line}' >> ~/.ssh/known_hosts`
  let present = false
  const base = createSshApplyMockSsh(baseResponses)
  return {
    ...base,
    async exec(command: string, options?: Parameters<typeof base.exec>[1]) {
      const result = await base.exec(command, options)
      if (command === printfCommand) present = true
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
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when the known_hosts entry matches the expected fingerprint", async () => {
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the known_hosts entry mismatches the expected public key", async () => {
    const mismatchedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("different-host-key"))
    const mismatchedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${mismatchedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${mismatchedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: hostPublicKey })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the known_hosts entry has drifted from the expected fingerprint", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${driftedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when known_hosts contains the pinned key plus an unpinned key", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("extra-host-key"))
    const extraLine = `|1|hashed-host|hashed-extra ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${scannedLine}\n${extraLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when an older entry exists even if one line matches the expected fingerprint", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-old ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${driftedLine}\n${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when another algorithm exists even if one line matches the expected public key", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("legacy-rsa-key"))
    const extraLine = `|1|hashed-host|hashed-rsa ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${extraLine}\n${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: hostPublicKey })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check uses a bracketed known_hosts lookup target for non-standard ports", async () => {
    const mockSsh = createMockSsh({
      "ssh-keygen -F '[github.com]:2222'": { code: 0, stdout: `${scannedLine}\n` },
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
      "ssh-keygen -F 'github.com'": { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.execCalls).toContainEqual({
      command: "ssh-keygen -F 'github.com'",
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
      "ssh-keygen -F 'github.com'": { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when host is known (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply verifies a scanned host key against the expected fingerprint before appending it", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' ~/.ssh/known_hosts`]: { code: 1 },
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    expect(mockSsh.calls).toContain("ssh-keyscan -H 'github.com' 2>/dev/null")
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
  })

  it("apply verifies a scanned host key against the expected public key before appending it", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' ~/.ssh/known_hosts`]: { code: 1 },
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: `${hostPublicKey} github.com` })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
  })

  it("apply scans the configured non-standard port before appending a verified host key", async () => {
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' ~/.ssh/known_hosts`]: { code: 1 },
      "ssh-keyscan -p 2222 -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: hostFingerprint,
      port: 2222,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keyscan -p 2222 -H 'github.com' 2>/dev/null")
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
  })

  it("apply persists only the scanned line that matches the configured trust anchor", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("extra-host-key"))
    const extraLine = `|1|hashed-host|hashed-extra ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' ~/.ssh/known_hosts`]: { code: 1 },
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n${extraLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.filter(isKnownHostsAppend)).toStrictEqual([
      `printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`,
    ])
  })

  it("apply replaces mixed known_hosts entries with verified host key lines", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-old ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createSshApplyMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${driftedLine}\n${scannedLine}\n` },
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R 'github.com'")
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
  })

  it("apply skips appending lines already present in known_hosts (R-0000038 idempotency)", async () => {
    // Regression for R-0000038: when the verified line is already in
    // ~/.ssh/known_hosts (grep -qxF returns code 0), the apply path must not
    // append it again. A second consecutive run therefore produces neither
    // duplicates nor a second `printf >> known_hosts` call, and reports ok.
    const mockSsh = createSshApplyMockSsh({
      [`grep -qxF '${scannedLine}' ~/.ssh/known_hosts`]: { code: 0 },
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
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
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })

    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const firstResult = await mod.apply(mockSsh, emptyEnv)
    expect(firstResult.status).toBe("changed")

    const secondResult = await mod.apply(mockSsh, emptyEnv)
    expect(secondResult.status).toBe("ok")

    // Across both runs the printf-append happened exactly once.
    const printfCalls = mockSsh.calls.filter(
      (c) => c === `printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`
    )
    expect(printfCalls).toHaveLength(1)
  })

  it("apply rejects scanned keys that do not match the expected fingerprint", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "could not verify the scanned host key"
    )
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

  it("apply removes host via ssh-keygen -R (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R 'github.com'")
  })

  it("apply returns ok and skips ssh-keygen -R when the host is not in known_hosts (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keygen -F 'github.com'": { code: 1 },
    })
    const mod = ssh.knownHosts("github.com", { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain("ssh-keygen -R 'github.com'")
  })

  it("apply removes a non-standard-port host entry via a bracketed ssh-keygen -R target", async () => {
    const mockSsh = createSshApplyMockSsh({
      "ssh-keygen -F '[github.com]:2222'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com", { port: 2222, state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R '[github.com]:2222'")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
