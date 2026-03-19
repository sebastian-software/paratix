import { describe, expect, it } from "vitest"

import { ufw } from "../../src/modules/ufw.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("ufw.enabled", () => {
  it("check returns ok when ufw is active", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "Status: active" },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when ufw is inactive", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "Status: inactive" },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ufw.enabled()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when ufw enable succeeds", async () => {
    const ssh = createMockSsh({
      "echo 'y' | ufw enable": { code: 0 },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("echo 'y' | ufw enable")
  })

  it("apply returns failed when ufw enable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "echo 'y' | ufw enable": { code: 1 },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ufw.enabled()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("ufw.rule", () => {
  it("check returns ok for an allow rule on a single port", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "80                         ALLOW       Anywhere" },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok for a deny rule on a single port", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "22                         DENY        Anywhere" },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when one port in a multi-port rule is missing", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "80                         ALLOW       Anywhere" },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when a single-port allow rule succeeds", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '80'": { code: 0 },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("ufw 'allow' '80'")
  })

  it("apply runs all commands for a multi-port rule in order", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0 },
      "ufw 'allow' '80'": { code: 0 },
      "ufw 'allow' '8080'": { code: 0 },
    })
    const mod = ufw.rule("allow", [80, 443, 8080])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual(["ufw 'allow' '80'", "ufw 'allow' '443'", "ufw 'allow' '8080'"])
  })

  it("apply returns failed and stops when one port command fails", async () => {
    const ssh = createMockSsh({
      "ufw 'deny' '22'": { code: 0 },
      "ufw 'deny' '25'": { code: 1 },
      "ufw 'deny' '465'": { code: 0 },
    })
    const mod = ufw.rule("deny", [22, 25, 465])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual(["ufw 'deny' '22'", "ufw 'deny' '25'"])
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ufw.rule("allow", [80, 443])
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("uses the expected module name for multiple ports", () => {
    const mod = ufw.rule("allow", [80, 443])
    expect(mod.name).toBe("ufw.rule: allow 80,443")
  })
})
