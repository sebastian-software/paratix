import { describe, expect, it } from "vitest"

import { apt } from "../../src/modules/apt.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("apt.key", () => {
  const fingerprint = "1234567890ABCDEF1234567890ABCDEF12345678"

  it("check returns ok when key file exists", async () => {
    const ssh = createMockSsh({
      "[ -f /etc/apt/keyrings/'docker'.gpg ]": { code: 0 },
      "gpg --show-keys --with-colons '/etc/apt/keyrings/docker.gpg'": {
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
      "[ -f /etc/apt/keyrings/'docker'.gpg ]": { code: 1 },
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
      "[ -f /etc/apt/keyrings/'docker'.gpg ]": { code: 0 },
      "gpg --show-keys --with-colons '/etc/apt/keyrings/docker.gpg'": {
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
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
      },
      "gpg --dearmor --yes -o '/etc/apt/keyrings/docker.gpg' '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
      },
      "gpg --show-keys --with-colons '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain("mkdir -p /etc/apt/keyrings")
    expect(ssh.calls).toContain("mktemp '/tmp/apt-key-docker.XXXXXX'")
    expect(ssh.calls).toContain(
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/tmp/apt-key-docker.ABCDEF'"
    )
    expect(ssh.calls).toContain("gpg --show-keys --with-colons '/tmp/apt-key-docker.ABCDEF'")
    expect(ssh.calls).toContain(
      "gpg --dearmor --yes -o '/etc/apt/keyrings/docker.gpg' '/tmp/apt-key-docker.ABCDEF'"
    )
  })

  it("returns a failed result when the downloaded key fingerprint mismatches", async () => {
    const ssh = createMockSsh({
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
      },
      "gpg --show-keys --with-colons '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n",
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[apt.key] fingerprint mismatch for docker")
  })

  it("returns a failed result with error details when key import fails", async () => {
    const ssh = createMockSsh({
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
      },
      "gpg --dearmor --yes -o '/etc/apt/keyrings/docker.gpg' '/tmp/apt-key-docker.ABCDEF'": {
        code: 2,
        stderr: "gpg: dearmor failed: No such file or directory",
      },
      "gpg --show-keys --with-colons '/tmp/apt-key-docker.ABCDEF'": {
        code: 0,
        stdout: "pub:-:255:22:::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:\n",
      },
      "mkdir -p /etc/apt/keyrings": { code: 0 },
      "mktemp '/tmp/apt-key-docker.XXXXXX'": { stdout: "/tmp/apt-key-docker.ABCDEF\n" },
      "rm -f '/tmp/apt-key-docker.ABCDEF'": { code: 0 },
    })
    const mod = apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[apt.key] failed to import docker")
  })

  it("throws for non-https URLs", () => {
    expect(() =>
      apt.key("docker", "http://download.docker.com/linux/ubuntu/gpg", { fingerprint })
    ).toThrow(/requires an https URL/v)
  })

  it("throws when fingerprint is invalid", () => {
    expect(() =>
      apt.key("docker", "https://download.docker.com/linux/ubuntu/gpg", { fingerprint: "abc" })
    ).toThrow(/requires an OpenPGP fingerprint/v)
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
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -name 'apt-dist-upgrade-*' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
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

  it("apply without options does not set a timeout key", async () => {
    const ssh = createMockSsh({
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -name 'apt-dist-upgrade-*' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
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
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -name 'apt-dist-upgrade-*' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
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
      "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive apt-get update": { code: 0 },
      "DEBIAN_FRONTEND=noninteractive dpkg --configure -a": { code: 0 },
      "find /var/lib/paratix/flags -maxdepth 1 -name 'apt-dist-upgrade-*' -delete && touch /var/lib/paratix/flags/'apt-dist-upgrade-2024-01-15'":
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
      "DEBIAN_FRONTEND=noninteractive apt-get update": {
        code: 100,
        stderr: "E: Could not get lock /var/lib/dpkg/lock-frontend",
      },
    })
    const mod = apt.distUpgrade("2024-01-15")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[apt.distUpgrade] apt-get update failed")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive dpkg --configure -a")
    expect(ssh.calls).not.toContain("DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y")
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

  // R-0000051 regression: tabs / multiple spaces / trailing whitespace are
  // semantically equivalent to single-space-separated fields in apt source
  // lines and must not flap the check between `ok` and `needs-apply`.
  it("check returns ok when on-disk content uses tabs as separators", async () => {
    const tabbed =
      "deb\t[signed-by=/etc/apt/keyrings/docker.gpg]\thttps://download.docker.com/linux/ubuntu\tnoble\tstable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: tabbed },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when on-disk content uses multiple spaces between fields", async () => {
    const spaced =
      "deb   [signed-by=/etc/apt/keyrings/docker.gpg]   https://download.docker.com/linux/ubuntu   noble   stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: spaced },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when on-disk content has trailing whitespace", async () => {
    const trailing = `${expectedContentWithSignedBy}   \t  `
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: trailing },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when content semantically differs (different suite)", async () => {
    const driftedContent =
      "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable"
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: driftedContent },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
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

  it("returns a failed result with error details when selections contain newlines", async () => {
    const mod = apt.debconf("postfix", { "postfix/main_mailer_type": "Internet\nSite" })
    const ssh = createMockSsh({})
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("must not contain newline characters")
  })
})
