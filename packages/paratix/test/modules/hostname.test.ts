import { describe, expect, it } from "vitest"

import { hostname } from "../../src/modules/hostname.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("hostname.set", () => {
  it.each(["my-server", "web01", "web-01.example.com"])("accepts valid hostname %s", (name) => {
    expect(() => hostname.set(name)).not.toThrow()
  })

  it.each([
    ["", "must not be empty"],
    ["-my-server", "must not start"],
    ["my server", "invalid hostname label"],
    ["my_server", "invalid hostname label"],
    [".my-server", "empty labels"],
    ["my-server.", "empty labels"],
    ["my..server", "empty labels"],
    ["my-server.-example", "invalid hostname label"],
    ["my-server.example-", "invalid hostname label"],
    ["a".repeat(64), "labels must be at most 63 characters"],
    [[...Array.from({ length: 127 }, () => "a"), "aa"].join("."), "at most 253 characters"],
  ])("rejects invalid hostname %s", (name, message) => {
    expect(() => hostname.set(name)).toThrow(message)
  })

  it("check returns ok when the persisted hostname matches the desired name", async () => {
    const ssh = createMockSsh({
      "hostnamectl --static": { code: 0, stdout: "my-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the persisted hostname differs from the desired name", async () => {
    const ssh = createMockSsh({
      "hostnamectl --static": { code: 0, stdout: "old-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = hostname.set("my-server")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check uses the persisted hostname so an FQDN kernel hostname does not cause drift loops", async () => {
    // Kernel hostname (resolved via /etc/hosts + nsswitch.conf) returns the FQDN,
    // while `hostnamectl --static` returns the short name written to /etc/hostname.
    // The check must rely on the persistent value to avoid endless apply/check loops.
    const ssh = createMockSsh({
      hostname: { code: 0, stdout: "my-server.example.com" },
      "hostnamectl --static": { code: 0, stdout: "my-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
    expect(ssh.calls).toContain("hostnamectl --static")
    expect(ssh.calls).not.toContain("hostname")
  })

  it("apply returns changed when hostnamectl succeeds", async () => {
    const ssh = createMockSsh({
      "hostnamectl set-hostname 'my-server'": { code: 0 },
    })
    const mod = hostname.set("my-server")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when hostnamectl fails", async () => {
    const ssh = createMockSsh({
      "hostnamectl set-hostname 'my-server'": { code: 1, stderr: "permission denied" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain(
      "[hostname.set: my-server] hostnamectl set-hostname failed"
    )
    expect(result.error?.message).toContain("permission denied")
  })

  it("declares itself as a dry-run diff producer", () => {
    const mod = hostname.set("my-server")
    expect(mod._dryRunDiffProducer).toBe(true)
    expect(typeof mod._applyDryRun).toBe("function")
  })

  it("_applyDryRun returns a key-value diff when the persisted hostname differs", async () => {
    const ssh = createMockSsh({
      "hostnamectl --static": { code: 0, stdout: "old-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toBe("-hostname = old-server\n+hostname = my-server")
  })

  it("_applyDryRun surfaces the error code via _dryRunDetail when the probe throws", async () => {
    // R-0001018: the catch around the dry-run probe used to swallow every
    // exception silently. Mock the inner ssh.exec to throw an Error-with-code
    // and assert the detail is surfaced so the operator sees *why* no diff
    // could be produced.
    const ssh = createMockSsh()
    ssh.exec = async () => {
      const error = new Error("transient SSH failure") as Error & { code: string }
      error.code = "ECONNRESET"
      throw error
    }
    const mod = hostname.set("my-server")
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toBeUndefined()
    expect(result._dryRunDetail).toBe("(dry-run, diff unavailable: ECONNRESET)")
  })
})
