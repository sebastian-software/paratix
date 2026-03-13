import { describe, expect, it } from "vitest"

import { apt } from "../../src/modules/apt.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("apt.installed", () => {
  it("check returns ok when all packages are installed", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 0 },
    })
    const mod = apt.installed("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when a package is not installed", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 1 },
    })
    const mod = apt.installed("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.installed("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when one of multiple packages is missing", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'curl'": { code: 1 },
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 0 },
    })
    const mod = apt.installed("nginx", "curl")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("apt.key", () => {
  it("check returns ok when key file exists", async () => {
    const ssh = createMockSsh({
      "[ -f /etc/apt/keyrings/'docker'.gpg ]": { code: 0 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key file is missing", async () => {
    const ssh = createMockSsh({
      "[ -f /etc/apt/keyrings/'docker'.gpg ]": { code: 1 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply calls curl and gpg with the correct commands", async () => {
    const ssh = createMockSsh({
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' | gpg --dearmor --yes -o /etc/apt/keyrings/'docker'.gpg":
        { code: 0 },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("mkdir -p /etc/apt/keyrings")
    expect(ssh.calls).toContain(
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' | gpg --dearmor --yes -o /etc/apt/keyrings/'docker'.gpg"
    )
  })
})

describe("apt.repository (PPA form)", () => {
  it("check returns ok when PPA is found in sources", async () => {
    const ssh = createMockSsh({
      "grep -rq 'nginx/stable' /etc/apt/sources.list.d/": { code: 0 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when PPA is not found", async () => {
    const ssh = createMockSsh({
      "grep -rq 'nginx/stable' /etc/apt/sources.list.d/": { code: 1 },
    })
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.repository("ppa:nginx/stable")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("apt.repository (standard form)", () => {
  const source = "deb https://download.docker.com/linux/ubuntu noble stable"
  const filePath = "/etc/apt/sources.list.d/docker.list"
  const expectedContentWithSignedBy =
    "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable"

  it("check returns ok when file exists with correct content (auto signed-by)", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when file does not exist", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 1 },
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
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when content has no signed-by but auto-derivation is active", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when signedBy is false and file matches source without signed-by", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
    })
    const mod = apt.repository("docker", source, { signedBy: false })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when explicit signedBy uses custom key path", async () => {
    const customContent =
      "deb [signed-by=/etc/apt/keyrings/custom.gpg] https://download.docker.com/linux/ubuntu noble stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: customContent },
    })
    const mod = apt.repository("docker", source, { signedBy: "custom" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })
})

describe("apt.debconf", () => {
  const selections = { "postfix/main_mailer_type": "Internet Site" }

  it("check returns ok when debconf-show output matches selections", async () => {
    const ssh = createMockSsh({
      "debconf-show 'postfix'": {
        code: 0,
        stdout: "* postfix/main_mailer_type: Internet Site",
      },
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

  it("check returns needs-apply when debconf-show fails", async () => {
    const ssh = createMockSsh({
      "debconf-show 'postfix'": { code: 1, stdout: "" },
    })
    const mod = apt.debconf("postfix", selections)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("apt.upgrade", () => {
  const date = "2024-01-15"
  const flagPath = `/var/lib/paratix/flags/'apt-upgrade-${date}'`

  it("check returns ok when the upgrade flag file exists", async () => {
    const ssh = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 0 },
    })
    const mod = apt.upgrade(date)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the upgrade flag file is missing", async () => {
    const ssh = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 1 },
    })
    const mod = apt.upgrade(date)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.upgrade(date)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
