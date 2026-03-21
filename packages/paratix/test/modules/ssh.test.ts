import { describe, expect, it, vi } from "vitest"

import { computeFingerprint } from "../../src/knownHosts.js"
import { ssh } from "../../src/modules/ssh.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

function makeHostKeyBuffer(algo: string, keyData = Buffer.from("fake-host-key-data")): Buffer {
  const algoBytes = Buffer.from(algo)
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(algoBytes.length)
  return Buffer.concat([lengthBuffer, algoBytes, keyData])
}

describe("ssh.knownHosts", () => {
  const hostKeyBuffer = makeHostKeyBuffer("ssh-ed25519")
  const hostKeyBase64 = hostKeyBuffer.toString("base64")
  const hostPublicKey = `ssh-ed25519 ${hostKeyBase64}`
  const hostFingerprint = computeFingerprint(hostKeyBuffer)
  const scannedLine = `|1|hashed-host|hashed-value ssh-ed25519 ${hostKeyBase64}`

  it("check returns ok when host is already known (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com")
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

  it("check returns ok when known_hosts contains the pinned key plus additional keys for the same host", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("extra-host-key"))
    const extraLine = `|1|hashed-host|hashed-extra ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${scannedLine}\n${extraLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns ok when an older entry exists as long as one line matches the expected fingerprint", async () => {
    const driftedKey = makeHostKeyBuffer("ssh-ed25519", Buffer.from("drifted-host-key"))
    const driftedLine = `|1|hashed-host|hashed-old ssh-ed25519 ${driftedKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${driftedLine}\n${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { expectedFingerprint: hostFingerprint })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns ok when another algorithm exists as long as one line matches the expected public key", async () => {
    const extraKey = makeHostKeyBuffer("ssh-rsa", Buffer.from("legacy-rsa-key"))
    const extraLine = `|1|hashed-host|hashed-rsa ssh-rsa ${extraKey.toString("base64")}`
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0, stdout: `${extraLine}\n${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: hostPublicKey })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
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
    const mod = ssh.knownHosts("github.com")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ssh.knownHosts("github.com")
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
    const mockSsh = createMockSsh({
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
    const mockSsh = createMockSsh({
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", { publicKey: `${hostPublicKey} github.com` })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${scannedLine}' >> ~/.ssh/known_hosts`)
  })

  it("apply scans the configured non-standard port before appending a verified host key", async () => {
    const mockSsh = createMockSsh({
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
    const mockSsh = createMockSsh({
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

  it("apply rejects scanned keys that do not match the expected fingerprint", async () => {
    const mockSsh = createMockSsh({
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com", {
      expectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "could not verify the scanned host key"
    )
  })

  it("apply rejects present state without a fingerprint or public key trust anchor", async () => {
    const mockSsh = createMockSsh({
      "ssh-keyscan -H 'github.com' 2>/dev/null": { stdout: `${scannedLine}\n` },
    })
    const mod = ssh.knownHosts("github.com")

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "requires expectedFingerprint or publicKey"
    )
  })

  it("apply removes host via ssh-keygen -R (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R 'github.com'")
  })

  it("apply removes a non-standard-port host entry via a bracketed ssh-keygen -R target", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.knownHosts("github.com", { port: 2222, state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R '[github.com]:2222'")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.knownHosts("github.com")
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("ssh.authorizedKeys", () => {
  const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-key"

  // resolveHome calls conn.output() which returns the home path
  const getentAlice = "getent passwd 'alice' | cut -d: -f6"
  const aliceHome = "/home/alice"
  const aliceDir = `'/home/alice/.ssh'`
  const aliceKeys = `'/home/alice/.ssh/authorized_keys'`
  const tempPath = "/run/paratix/authorized-keys.ABCDEF"

  function aliceResponses(
    extra?: Record<string, Partial<{ code: number; stderr: string; stdout: string }>>
  ) {
    return {
      [getentAlice]: { stdout: aliceHome },
      ...extra,
    }
  }

  it("check returns ok when key exists in authorized_keys (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
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
    expect(mockSsh.calls).not.toContain(`grep -qF -- '${testKey}' ${aliceKeys}`)
    expect(mockSsh.calls).not.toContain("stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'")
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
    const mockSsh = createMockSsh(
      aliceResponses({
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `mkdir -p ${aliceDir} && chmod 700 ${aliceDir} && chown 'alice':'alice' ${aliceDir}`
    )
    expect(mockSsh.calls).toContain("install -d -m 700 /run/paratix")
    expect(mockSsh.calls).toContain(
      `[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`
    )
    expect(mockSsh.calls).toContain("mktemp /run/paratix/authorized-keys.XXXXXX")
    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then cat ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    expect(mockSsh.calls).not.toContain(`printf '%s\\n' '${testKey}' >> ${aliceKeys}`)
    expect(mockSsh.calls).toContain(
      `chmod 600 '${tempPath}' && chown 'alice':'alice' '${tempPath}' && mv '${tempPath}' ${aliceKeys} && chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`
    )
    expect(mockSsh.calls).toContain(`rm -f '${tempPath}'`)
  })

  it("regression: apply does not append a duplicate key when only permissions have drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
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
      `{ if [ -f ${aliceKeys} ]; then cat ${aliceKeys}; grep -qxF -- '${testKey}' ${aliceKeys} || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    expect(mockSsh.calls).not.toContain(
      `{ if [ -f ${aliceKeys} ]; then cat ${aliceKeys}; fi; printf '%s\\n' '${testKey}'; } > '${tempPath}'`
    )
  })

  it("apply removes key with grep -vF || true pattern (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `{ if [ -f ${aliceKeys} ]; then grep -vF -- '${testKey}' ${aliceKeys} || true; fi; } > '${tempPath}'`
    )
  })

  it("regression: apply resets ownership and mode after removing a key (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
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
    expect(mockSsh.calls).not.toContain("mktemp /run/paratix/authorized-keys.XXXXXX")
  })

  it("uses a root-controlled mktemp path instead of a fixed authorized_keys.tmp file", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.tmp.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`${aliceHome}/.ssh/authorized_keys.tmp`)
    expect(mockSsh.calls).toContain("install -d -m 700 /run/paratix")
    expect(mockSsh.calls).toContain("mktemp /run/paratix/authorized-keys.XXXXXX")
  })

  it("keeps temporary authorized_keys rewrites out of the user-controlled .ssh directory", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.XXXXXX`)
    expect(mockSsh.calls).not.toContain(`mktemp ${aliceHome}/.ssh/authorized_keys.tmp.XXXXXX`)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("resolves home directory dynamically for root user", async () => {
    const mockSsh = createMockSsh({
      "[ -L '/root/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qF -- '${testKey}' '/root/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'root' | cut -d: -f6": { stdout: "/root" },
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
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qF -- '${testKey}' '/home/deploy/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
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
      "[ -L '/home/my user/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`]: { code: 0 },
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "stat -c '%a %U %G %F' '/home/my user/.ssh'": { stdout: "700 alice alice directory" },
      "stat -c '%a %U %G %F' '/home/my user/.ssh/authorized_keys'": {
        stdout: "600 alice alice regular file",
      },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    // Verify that the path containing a space was passed as a quoted argument
    expect(mockSsh.calls).toContain(`grep -qF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`)
  })

  it("regression: home path with spaces is correctly shell-quoted in apply", async () => {
    const spaceyHome = "/home/my user"
    const mockSsh = createMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "mktemp /run/paratix/authorized-keys.XXXXXX": { stdout: tempPath },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // Directory creation must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `mkdir -p '/home/my user/.ssh' && chmod 700 '/home/my user/.ssh' && chown 'alice':'alice' '/home/my user/.ssh'`
    )
    // Temp rewrite command must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `{ if [ -f '/home/my user/.ssh/authorized_keys' ]; then cat '/home/my user/.ssh/authorized_keys'; grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys' || printf '%s\\n' '${testKey}'; else printf '%s\\n' '${testKey}'; fi; } > '${tempPath}'`
    )
    // Chmod must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `chmod 600 '${tempPath}' && chown 'alice':'alice' '${tempPath}' && mv '${tempPath}' '/home/my user/.ssh/authorized_keys' && chmod 600 '/home/my user/.ssh/authorized_keys' && chown 'alice':'alice' '/home/my user/.ssh/authorized_keys'`
    )
  })
})
