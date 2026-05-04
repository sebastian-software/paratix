/* eslint-disable no-template-curly-in-string -- Shell dpkg-query format strings, not JS templates */
import { describe, expect, it } from "vitest"

import { apt } from "../../src/modules/apt.js"
import { sha256String } from "../../src/modules/fileHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, { strict: false, ...options })

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
    expect(ssh.calls).not.toContain(
      "curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' -o '/tmp/apt-key-docker.ABCDEF'"
    )
    expect(ssh.calls).not.toContain("gpg --show-keys --with-colons '/tmp/apt-key-docker.ABCDEF'")
    expect(ssh.calls).not.toContain(
      "gpg --dearmor --yes -o '/etc/apt/keyrings/docker.gpg' '/tmp/apt-key-docker.ABCDEF'"
    )
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
    expect(ssh.calls).not.toContain("gpg --show-keys --with-colons '/etc/passwd'")
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

  // R-0000055 regression: the pipeline order must be
  // `dpkg --configure -a` → `apt-get update` → `apt-get dist-upgrade -y`
  // so a dpkg-broken host gets configure -a a chance to run before the
  // first apt-get step that would otherwise fail. Mirrors the order used
  // by the package.ts apt-upgrade pipeline.
  it("apply runs dpkg --configure -a before apt-get update and apt-get dist-upgrade", async () => {
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when content has no signed-by but auto-derivation is active", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when signedBy is false and file matches source without signed-by", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: source },
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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
      [`stat -c '%a' '${filePath}'`]: { stdout: "644" },
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

  it("check returns needs-apply when repository file mode drifted", async () => {
    const ssh = createMockSsh({
      [`[ -f '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: expectedContentWithSignedBy },
      [`stat -c '%a' '${filePath}'`]: { stdout: "600" },
    })
    const mod = apt.repository("docker", source)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
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
    expect(String(result.error)).toContain("must not contain newline characters")
  })

  // R-0000063 regression: the apply pipe must use `printf '%s' …` instead of
  // `echo …` so values that begin with `-` (which some echo implementations
  // interpret as flags) and values containing backslash sequences (which
  // POSIX echo may interpret) are forwarded to debconf-set-selections
  // verbatim regardless of which shell `/bin/sh` resolves to.
  it("apply uses printf '%s' to pipe selections starting with a dash verbatim", async () => {
    const ssh = createMockSsh({
      "echo 'METAGET pkg/dash-value type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "printf '%s' 'pkg pkg/dash-value string -n' | debconf-set-selections": { code: 0 },
    })
    const mod = apt.debconf("pkg", { "pkg/dash-value": "-n" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(
      "printf '%s' 'pkg pkg/dash-value string -n' | debconf-set-selections"
    )
    expect(ssh.calls).not.toContain("echo 'pkg pkg/dash-value string -n' | debconf-set-selections")
  })

  it("apply uses printf '%s' so backslash sequences reach debconf-set-selections verbatim", async () => {
    const ssh = createMockSsh({
      "echo 'METAGET pkg/backslash-value type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "printf '%s' 'pkg pkg/backslash-value string a\\tb\\nc' | debconf-set-selections": {
        code: 0,
      },
    })
    const mod = apt.debconf("pkg", { "pkg/backslash-value": String.raw`a\tb\nc` })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result).toStrictEqual({ status: "changed" })
    expect(ssh.calls).toContain(
      "printf '%s' 'pkg pkg/backslash-value string a\\tb\\nc' | debconf-set-selections"
    )
    expect(ssh.calls).not.toContain(
      "echo 'pkg pkg/backslash-value string a\\tb\\nc' | debconf-set-selections"
    )
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
      [dpkgQuery]: dpkgNotInstalled,
      "echo 'METAGET postfix/main_mailer_type type' | debconf-communicate": {
        code: 0,
        stdout: "0 string\n",
      },
      "printf '%s' 'postfix postfix/main_mailer_type string Internet Site' | debconf-set-selections":
        { code: 0 },
    })
    expect(await mod.apply(ssh2, emptyEnv)).toStrictEqual({ status: "changed" })
    expect(ssh2.calls).toContain(
      `find /var/lib/paratix/flags -maxdepth 1 -name 'apt-debconf-${packageHash}-*' -delete && touch ${flagPath}`
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
