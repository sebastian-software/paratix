import { describe, expect, it, vi } from "vitest"

import { computeFingerprint } from "../../src/knownHosts.js"
import { ssh } from "../../src/modules/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

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
    {
      command:
        /^\{ if \[ -f '[^']+\/\.ssh\/authorized_keys' \]; then .+; fi; \} > '[^']+\/\.ssh\/\.authorized-keys\.[^']+'$/v,
      result: { code: 0 },
    },
    {
      command:
        /^chmod 600 '[^']+\/\.ssh\/\.authorized-keys\.[^']+' && chown '[^']+':'[^']+' '[^']+\/\.ssh\/\.authorized-keys\.[^']+' && mv '[^']+\/\.ssh\/\.authorized-keys\.[^']+' '[^']+\/\.ssh\/authorized_keys' && chmod 600 '[^']+\/\.ssh\/authorized_keys' && chown '[^']+':'[^']+' '[^']+\/\.ssh\/authorized_keys'$/v,
      result: { code: 0 },
    },
    { command: /^rm -f '[^']+\/\.ssh\/\.authorized-keys\.[^']+'$/v, result: { code: 0 } },
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

function makeHostKeyBuffer(algo: string, keyData = Buffer.from("fake-host-key-data")): Buffer {
  const algoBytes = Buffer.from(algo)
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(algoBytes.length)
  return Buffer.concat([lengthBuffer, algoBytes, keyData])
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
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
    expect(mockSsh.calls).not.toContain(
      `printf '%s\\n' '${scannedLine}' '${extraLine}' >> ~/.ssh/known_hosts`
    )
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

describe("ssh.authorizedKeys", () => {
  const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-key"

  // resolveHome calls conn.output() which returns the home path
  const getentAlice = "getent passwd 'alice' | cut -d: -f6"
  // R-0000065: resolvePrimaryGroup runs `id -gn` for both apply and check
  // to derive the user's actual primary group.
  const idGroupAlice = "id -gn 'alice'"
  const aliceHome = "/home/alice"
  const aliceDir = `'/home/alice/.ssh'`
  const aliceKeys = `'/home/alice/.ssh/authorized_keys'`
  const aliceMktempPattern = "mktemp '/home/alice/.ssh/.authorized-keys.XXXXXX'"
  const tempPath = "/home/alice/.ssh/.authorized-keys.ABCDEF"
  const aliceSshDirectoryGuard =
    "[ ! -L '/home/alice/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/alice/.ssh' ]; then [ -d '/home/alice/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/alice/.ssh'; fi; [ -d '/home/alice/.ssh' ] && [ ! -L '/home/alice/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/alice/.ssh' && chown 'alice':'alice' '/home/alice/.ssh'"

  function aliceResponses(
    extra?: Record<string, Partial<{ code: number; stderr: string; stdout: string }>>
  ) {
    return {
      [getentAlice]: { stdout: aliceHome },
      [idGroupAlice]: { stdout: "alice" },
      ...extra,
    }
  }

  it("check returns ok when key exists in authorized_keys (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key is missing (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression — check returns needs-apply when authorized_keys does not exist for a fresh user", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`grep -qxF -- '${testKey}' ${aliceKeys}`)
    expect(mockSsh.calls).not.toContain("stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'")
  })

  it("returns needs-apply in check when the target user does not exist yet", async () => {
    const mockSsh = createMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey)

    await expect(mod.check(mockSsh, emptyEnv)).resolves.toBe("needs-apply")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("returns ok in check for absent state when the target user does not exist", async () => {
    const mockSsh = createMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey, { state: "absent" })

    await expect(mod.check(mockSsh, emptyEnv)).resolves.toBe("ok")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("returns ok in apply for absent state when the target user does not exist", async () => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain(
      "mkdir -p '/.ssh' && chmod 700 '/.ssh' && chown 'ghost':'ghost' '/.ssh'"
    )
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when key is missing (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key exists (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when authorized_keys is a symlink", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when .ssh ownership or mode has drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "755 root root directory" },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when authorized_keys ownership or mode has drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "644 root root regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("apply creates directory, adds key with correct permissions (state: present)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain("install -d -m 700 /run/paratix")
    expect(mockSsh.calls).toContain(
      `[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`
    )
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then awk '1' ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    expect(mockSsh.calls).not.toContain(`printf '%s\\n' '${testKey}' >> ${aliceKeys}`)
    expect(mockSsh.calls).toContain(
      `chmod 600 '${tempPath}' && chown 'alice':'alice' '${tempPath}' && mv '${tempPath}' ${aliceKeys} && chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`
    )
    expect(mockSsh.calls).toContain(`rm -f '${tempPath}'`)
  })

  it("regression: apply does not append a duplicate key when only permissions have drifted", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        [aliceMktempPattern]: { stdout: tempPath },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "644 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const checkResult = await mod.check(mockSsh, emptyEnv)
    expect(checkResult).toBe("needs-apply")

    const applyResult = await mod.apply(mockSsh, emptyEnv)
    expect(applyResult.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then awk '1' ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    expect(mockSsh.calls).not.toContain(
      `{ if [ -f ${aliceKeys} ]; then cat ${aliceKeys}; fi; printf '%s\\n' '${testKey}'; } > '${tempPath}'`
    )
  })

  it("regression: present rewrite terminates existing authorized_keys before appending", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then awk '1' ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
  })

  it("apply removes key with grep -vxF || true pattern (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // R-0000044: whole-line match so an entry whose body is a substring of
    // an unrelated authorized_keys line is not collateral-damage-deleted.
    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then grep -vxF -- '${testKey}' ${aliceKeys} || true; fi; } > '${tempPath}'`
    )
  })

  // R-0000044: in real life, a `grep -vF -- '<key body>'` filter matches any
  // line containing the key body as a substring — this is wrong when the same
  // key body also appears in another entry that has an `options=...` prefix or
  // a different comment. The fix is `grep -vxF` (whole-line). This regression
  // test asserts the absent path renders the whole-line filter, never the
  // substring filter.
  it("regression: absent apply uses whole-line filter so it cannot delete keys that share a substring", async () => {
    const sharedKeyBody = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI shared-body"
    const exactKeyToRemove = sharedKeyBody
    const collateralEntry = `command="/usr/bin/restricted" ${sharedKeyBody}`

    // Sanity: in the unfixed implementation, `grep -vF -- '<body>' ...` would
    // also match the collateral entry because it contains `<body>` as a
    // substring. The fixed implementation uses `grep -vxF` (whole-line),
    // which only matches the exact `exactKeyToRemove` line.
    expect(collateralEntry.includes(sharedKeyBody)).toBe(true)
    expect(collateralEntry).not.toBe(exactKeyToRemove)

    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", exactKeyToRemove, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // The rendered command must use `grep -vxF`, never the broader `grep -vF`.
    const rewriteCall = mockSsh.calls.find(includesGrepRewrite)
    expect(rewriteCall).toBeDefined()
    expect(rewriteCall).toContain("grep -vxF")
    expect(rewriteCall).not.toMatch(/grep -vF\s/v)
  })

  it("regression: apply resets ownership and mode after removing a key (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `chmod 600 '${tempPath}' && chown 'alice':'alice' '${tempPath}' && mv '${tempPath}' ${aliceKeys} && chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`
    )
  })

  it("rejects when authorized_keys is a symlink", async () => {
    const base = createMockSsh(
      aliceResponses({
        [`[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`]:
          {
            code: 1,
            stderr: "authorized_keys must not be a symlink",
          },
      })
    )
    const mockSsh = {
      ...base,
      exec: vi
        .fn()
        .mockImplementationOnce(async (command: string) => {
          base.calls.push(command)
          await Promise.resolve()
          return { code: 0, stderr: "", stdout: "" }
        })
        .mockImplementationOnce(async (command: string) => {
          base.calls.push(command)
          await Promise.resolve()
          throw new Error("Command failed")
        }),
    }
    const mod = ssh.authorizedKeys("alice", testKey)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Command failed")
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
  })

  it("rejects when .ssh is a symlink before chmod, chown, mktemp, or rewrite", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceSshDirectoryGuard]: {
          code: 1,
          stderr: ".ssh must not be a symlink",
        },
      }),
      {
        rejectNonZeroExit: true,
      }
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(".ssh must not be a symlink")
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(
      `mkdir -p ${aliceDir} && chmod 700 ${aliceDir} && chown 'alice':'alice' ${aliceDir}`
    )
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls).not.toContain(
      `{ if [ -f ${aliceKeys} ]; then awk '1' ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    expect(mockSsh.calls).not.toContain(
      `chmod 600 '${tempPath}' && chown 'alice':'alice' '${tempPath}' && mv '${tempPath}' ${aliceKeys} && chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`
    )
  })

  it("stages the authorized_keys rewrite inside the target user's .ssh directory, not under /run", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Staging path lives under the target user's home directory, not under /run/paratix.
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.calls).not.toContain("install -d -m 700 /run/paratix")
    expect(mockSsh.calls).not.toContain("mktemp /run/paratix/authorized-keys.XXXXXX")
    expect(tempPath.startsWith(`${aliceHome}/.ssh/`)).toBe(true)
    expect(tempPath.startsWith("/run")).toBe(false)
    // Older legacy paths are not used.
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.tmp.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`${aliceHome}/.ssh/authorized_keys.tmp`)
  })

  it.each([
    ["empty output", ""],
    ["multiline output", `${tempPath}\n${aliceHome}/.ssh/.authorized-keys.EVIL`],
    ["outside .ssh", "/tmp/.authorized-keys.ABCDEF"],
    ["wrong prefix", `${aliceHome}/.ssh/not-authorized-keys.ABCDEF`],
  ])("rejects unsafe authorized_keys mktemp output: %s", async (_caseName, stdout) => {
    const foreignPath = "/tmp/.authorized-keys.ABCDEF"
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Unexpected mktemp output")
    expect(mockSsh.calls).not.toContain(
      `{ if [ -f ${aliceKeys} ]; then awk '1' ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${foreignPath}'`
    )
    expect(mockSsh.calls).not.toContain(
      `chmod 600 '${foreignPath}' && chown 'alice':'alice' '${foreignPath}' && mv '${foreignPath}' ${aliceKeys} && chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`
    )
    expect(mockSsh.calls).not.toContain(`rm -f '${foreignPath}'`)
  })

  it("keeps temporary authorized_keys rewrites in the target user's .ssh directory for absent state", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.calls).not.toContain("mktemp /run/paratix/authorized-keys.XXXXXX")
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.tmp.XXXXXX`)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("fails closed in apply when the user does not exist and resolveHome returns an empty string", async () => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "[ssh.authorizedKeys: ghost] failed to resolve a safe home directory"
    )
    expect(mockSsh.calls).not.toContain(
      "mkdir -p '/.ssh' && chmod 700 '/.ssh' && chown 'ghost':'ghost' '/.ssh'"
    )
    expect(mockSsh.calls).not.toContain(
      "[ ! -L '/.ssh/authorized_keys' ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }"
    )
  })

  it("resolves home directory dynamically for root user", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/root/.ssh' ]": { code: 0 },
      "[ -e '/root/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/root/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/root/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'root' | cut -d: -f6": { stdout: "/root" },
      "id -gn 'root'": { stdout: "root" },
      "stat -c '%a %U %G %F' '/root/.ssh'": { stdout: "700 root root directory" },
      "stat -c '%a %U %G %F' '/root/.ssh/authorized_keys'": {
        stdout: "600 root root regular file",
      },
    })
    const mod = ssh.authorizedKeys("root", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("resolves home directory dynamically for non-root user", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/deploy/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "deploy" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh'": { stdout: "700 deploy deploy directory" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh/authorized_keys'": {
        stdout: "600 deploy deploy regular file",
      },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("regression: home path with spaces is correctly shell-quoted in check", async () => {
    const spaceyHome = "/home/my user"
    const mockSsh = createMockSsh({
      "[ -e '/home/my user/.ssh' ]": { code: 0 },
      "[ -e '/home/my user/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/my user/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
      "stat -c '%a %U %G %F' '/home/my user/.ssh'": { stdout: "700 alice alice directory" },
      "stat -c '%a %U %G %F' '/home/my user/.ssh/authorized_keys'": {
        stdout: "600 alice alice regular file",
      },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    // Verify that the path containing a space was passed as a quoted argument
    expect(mockSsh.calls).toContain(
      `grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`
    )
  })

  it("regression: home path with spaces is correctly shell-quoted in apply", async () => {
    const spaceyHome = "/home/my user"
    const spaceyTemp = "/home/my user/.ssh/.authorized-keys.ABCDEF"
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
      "mktemp '/home/my user/.ssh/.authorized-keys.XXXXXX'": { stdout: spaceyTemp },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // Directory creation must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `[ ! -L '/home/my user/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/my user/.ssh' ]; then [ -d '/home/my user/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/my user/.ssh'; fi; [ -d '/home/my user/.ssh' ] && [ ! -L '/home/my user/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/my user/.ssh' && chown 'alice':'alice' '/home/my user/.ssh'`
    )
    // mktemp must operate inside the quoted .ssh directory
    expect(mockSsh.calls).toContain("mktemp '/home/my user/.ssh/.authorized-keys.XXXXXX'")
    // Temp rewrite command must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `{ if [ -f '/home/my user/.ssh/authorized_keys' ]; then awk '1' '/home/my user/.ssh/authorized_keys'; grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys' || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${spaceyTemp}'`
    )
    // Chmod must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `chmod 600 '${spaceyTemp}' && chown 'alice':'alice' '${spaceyTemp}' && mv '${spaceyTemp}' '/home/my user/.ssh/authorized_keys' && chmod 600 '/home/my user/.ssh/authorized_keys' && chown 'alice':'alice' '/home/my user/.ssh/authorized_keys'`
    )
  })

  // R-0000065 regression: when the user's primary group is not equal to the
  // username (e.g. `deploy:users`, a service user like `www-data:www-data`,
  // or an operator in `paratix:wheel`), apply must chown to the user's
  // actual primary group and check must compare against that same group so
  // a stable check-ok state is reachable without overwriting the
  // semantically correct group ownership.
  it("R-0000065: apply uses the user's resolved primary group for chown when it differs from the username", async () => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
      "mktemp '/home/deploy/.ssh/.authorized-keys.XXXXXX'": {
        stdout: "/home/deploy/.ssh/.authorized-keys.ABCDEF",
      },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Directory chown uses the resolved primary group, not the username.
    expect(mockSsh.calls).toContain(
      `[ ! -L '/home/deploy/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/deploy/.ssh' ]; then [ -d '/home/deploy/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/deploy/.ssh'; fi; [ -d '/home/deploy/.ssh' ] && [ ! -L '/home/deploy/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/deploy/.ssh' && chown 'deploy':'users' '/home/deploy/.ssh'`
    )
    // The authorized_keys chown must also use the resolved primary group.
    expect(mockSsh.calls).toContain(
      `chmod 600 '/home/deploy/.ssh/.authorized-keys.ABCDEF' && chown 'deploy':'users' '/home/deploy/.ssh/.authorized-keys.ABCDEF' && mv '/home/deploy/.ssh/.authorized-keys.ABCDEF' '/home/deploy/.ssh/authorized_keys' && chmod 600 '/home/deploy/.ssh/authorized_keys' && chown 'deploy':'users' '/home/deploy/.ssh/authorized_keys'`
    )
    // The legacy `${user}:${user}` chown must not be issued.
    expect(mockSsh.calls).not.toContain(
      `mkdir -p '/home/deploy/.ssh' && chmod 700 '/home/deploy/.ssh' && chown 'deploy':'deploy' '/home/deploy/.ssh'`
    )
  })

  it("R-0000065: check returns ok when the primary group differs from the username and matches stat output", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/deploy/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh'": {
        stdout: "700 deploy users directory",
      },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh/authorized_keys'": {
        stdout: "600 deploy users regular file",
      },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("rejects keys containing newlines at construction time", () => {
    const malicious = `${testKey}\nssh-ed25519 INJECTED extra-key`
    expect(() => ssh.authorizedKeys("alice", malicious)).toThrow(/must not contain newlines/v)
  })

  it("rejects keys containing carriage returns at construction time", () => {
    const malicious = `${testKey}\rssh-ed25519 INJECTED extra-key`
    expect(() => ssh.authorizedKeys("alice", malicious)).toThrow(/must not contain newlines/v)
  })

  it("rejects an empty key at construction time", () => {
    expect(() => ssh.authorizedKeys("alice", "")).toThrow(/must not be empty/v)
  })

  it.each(["", "--name", "-r", "bad user", "1alice", "älice"])(
    "rejects invalid usernames at construction time: %s",
    (user) => {
      expect(() => ssh.authorizedKeys(user, testKey)).toThrow(
        `user name ${JSON.stringify(user)} is invalid`
      )
    }
  )
})
