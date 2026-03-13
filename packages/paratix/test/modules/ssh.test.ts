import { describe, expect, it } from "vitest"

import { ssh } from "../../src/modules/ssh.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("ssh.knownHosts", () => {
  it("check returns ok when host is already known (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ssh-keygen -F 'github.com'": { code: 0 },
    })
    const mod = ssh.knownHosts("github.com")
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

  it("apply ensures ~/.ssh exists and adds host via ssh-keyscan (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.knownHosts("github.com")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    expect(mockSsh.calls).toContain("ssh-keyscan -H 'github.com' >> ~/.ssh/known_hosts 2>/dev/null")
  })

  it("apply removes host via ssh-keygen -R (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.knownHosts("github.com", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("ssh-keygen -R 'github.com'")
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

  // The home directory is resolved dynamically via getent passwd
  const aliceHome = "$(getent passwd 'alice' | cut -d: -f6)"
  const aliceDir = `${aliceHome}/.ssh`
  const aliceKeys = `${aliceDir}/authorized_keys`

  it("check returns ok when key exists in authorized_keys (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key is missing (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when key is missing (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
    })
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
    })
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply creates directory, adds key with correct permissions (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `mkdir -p ${aliceDir} && chmod 700 ${aliceDir} && chown 'alice':'alice' ${aliceDir}`
    )
    expect(mockSsh.calls).toContain(`printf '%s\\n' '${testKey}' >> ${aliceKeys}`)
    expect(mockSsh.calls).toContain(`chmod 600 ${aliceKeys} && chown 'alice':'alice' ${aliceKeys}`)
  })

  it("apply removes key with grep -vF || true pattern (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `{ grep -vF -- '${testKey}' ${aliceKeys} || true; } > ${aliceKeys}.tmp && mv ${aliceKeys}.tmp ${aliceKeys}`
    )
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("resolves home directory dynamically for root user", async () => {
    const rootHome = "$(getent passwd 'root' | cut -d: -f6)"
    const rootKeys = `${rootHome}/.ssh/authorized_keys`
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${rootKeys}`]: { code: 0 },
    })
    const mod = ssh.authorizedKeys("root", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("resolves home directory dynamically for non-root user", async () => {
    const deployHome = "$(getent passwd 'deploy' | cut -d: -f6)"
    const deployKeys = `${deployHome}/.ssh/authorized_keys`
    const mockSsh = createMockSsh({
      [`grep -qF -- '${testKey}' ${deployKeys}`]: { code: 0 },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })
})
