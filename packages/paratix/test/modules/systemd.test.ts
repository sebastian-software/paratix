import { describe, expect, it } from "vitest"

import { systemd } from "../../src/modules/systemd.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("systemd.daemonReload", () => {
  it("check always returns needs-apply with a valid ssh connection", async () => {
    const ssh = createMockSsh()
    const mod = systemd.daemonReload()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check always returns needs-apply when ssh is null", async () => {
    const mod = systemd.daemonReload()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl daemon-reload and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    const mod = systemd.daemonReload()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply returns failed when daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 1 },
    })
    const mod = systemd.daemonReload()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.daemonReload()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.masked", () => {
  it("check returns ok when unit is already masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 0, stdout: "masked\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when unit is enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when unit is disabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 1, stdout: "disabled\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl mask and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl mask 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl mask 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl mask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl mask 'apt-daily.timer'": { code: 1 },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.masked("apt-daily.timer")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.unit", () => {
  const unitName = "my-app.service"
  // Content without trailing newline so mock output matches after trim()
  const unitContent = "[Unit]\nDescription=My App\n\n[Service]\nExecStart=/usr/bin/my-app"
  const filePath = `/etc/systemd/system/${unitName}`

  it("check returns ok when file exists and content matches", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: unitContent },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when file does not exist", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when file content differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: "[Unit]\nDescription=Old Content\n" },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply writes the file and runs daemon-reload returning changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply returns failed when daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 1 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.unit(unitName, unitContent)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.unit — input validation", () => {
  it("throws when name contains path traversal (../../etc/passwd)", () => {
    expect(() => systemd.unit("../../etc/passwd", "[Unit]")).toThrow(/name must match/v)
  })

  it("throws when name contains a forward slash (foo/bar.service)", () => {
    expect(() => systemd.unit("foo/bar.service", "[Unit]")).toThrow(/name must match/v)
  })

  it("throws when name contains a space", () => {
    expect(() => systemd.unit("my service.service", "[Unit]")).toThrow(/name must match/v)
  })

  it("throws when name contains shell metacharacters (semicolon)", () => {
    expect(() => systemd.unit("app;rm.service", "[Unit]")).toThrow(/name must match/v)
  })

  it("allows valid service names with letters, digits, dots, hyphens, and underscores", () => {
    expect(() => systemd.unit("my-app.service", "[Unit]")).not.toThrow()
  })

  it("allows valid timer names", () => {
    expect(() => systemd.unit("backup.timer", "[Unit]")).not.toThrow()
  })

  it("allows names with the @ instance specifier", () => {
    expect(() => systemd.unit("app@instance.service", "[Unit]")).not.toThrow()
  })
})

describe("systemd.unmasked", () => {
  it("check returns ok when unit is not masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when unit is disabled but not masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 1, stdout: "disabled\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when unit is masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled 'apt-daily.timer'": { code: 1, stdout: "masked\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl unmask and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl unmask 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl unmask 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl unmask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl unmask 'apt-daily.timer'": { code: 1 },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.unmasked("apt-daily.timer")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
