import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import { sysctl } from "../../src/modules/sysctl.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/etc\/sysctl\.d\/99-paratix-.+\.conf$/v },
      ...(options?.allowWrites ?? []),
    ],
  })

const KEY = "net.ipv4.ip_forward"
const VALUE = "1"
const CONF_PATH = configPathForKey(KEY)
const CONF_CONTENT = "net.ipv4.ip_forward = 1\n"

function configPathForKey(key: string): string {
  const sanitizedKey = key.replaceAll(".", "-")
  const hash = createHash("sha256").update(key).digest("hex").slice(0, 12)
  return `/etc/sysctl.d/99-paratix-${sanitizedKey}-${hash}.conf`
}

// ─── sysctl.set — check ───────────────────────────────────────────────────────

describe("sysctl.set — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live value matches and config file exists with correct content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: CONF_CONTENT },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live value differs", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when sysctl -n exits non-zero (e.g. unknown key)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 255, stderr: "sysctl: cannot stat ...", stdout: "" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file has wrong content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: "net.ipv4.ip_forward = 0\n" },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // state: absent

  it("returns ok when config file does not exist (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when config file still exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // state: absent + resetValue

  it("returns ok when config file is gone and live value matches resetValue (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live value differs from resetValue (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "1" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live value cannot be read (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 255, stderr: "unknown key", stdout: "" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ─── sysctl.set — apply ───────────────────────────────────────────────────────

describe("sysctl.set — apply", () => {
  it("returns changed and executes sysctl -w and writes config file (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`sysctl -w '${KEY}=${VALUE}'`)
    expect(writeFileSpy).toHaveBeenCalledWith(CONF_PATH, CONF_CONTENT, { mode: "0644" })
  })

  it("returns failed when sysctl -w fails (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when conn is null (state: present)", async () => {
    const mod = sysctl.set(KEY, VALUE)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed and removes config file (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`rm -f '${CONF_PATH}'`)
  })

  it("returns failed when removing config file fails (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 1, stderr: "read-only file system" },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to remove config file")
  })

  it("removes file and writes resetValue to live kernel (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`rm -f '${CONF_PATH}'`)
    expect(mockSsh.calls).toContain(`sysctl -w '${KEY}=0'`)
    expect(mockSsh.calls).toContain(`sysctl -n '${KEY}'`)
  })

  it("returns failed when sysctl -w fails during reset (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
  })

  it("returns failed when live value did not converge after reset (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "1" },
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("did not converge")
  })

  it("does not run sysctl -w when resetValue is not given (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=${VALUE}'`)
  })
})

describe("sysctl.set — config path", () => {
  it("uses distinct persistence paths for keys that differ only by dot and hyphen", async () => {
    const dottedKey = "net.ipv4.test-key"
    const hyphenatedKey = "net-ipv4.test-key"
    const dottedPath = configPathForKey(dottedKey)
    const hyphenatedPath = configPathForKey(hyphenatedKey)
    const mockSsh = createMockSsh({
      [`sysctl -w '${dottedKey}=1'`]: { code: 0 },
      [`sysctl -w '${hyphenatedKey}=1'`]: { code: 0 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")

    await sysctl.set(dottedKey, "1").apply(mockSsh, emptyEnv)
    await sysctl.set(hyphenatedKey, "1").apply(mockSsh, emptyEnv)

    expect(dottedPath).not.toBe(hyphenatedPath)
    expect(writeFileSpy).toHaveBeenCalledWith(dottedPath, `${dottedKey} = 1\n`, {
      mode: "0644",
    })
    expect(writeFileSpy).toHaveBeenCalledWith(hyphenatedPath, `${hyphenatedKey} = 1\n`, {
      mode: "0644",
    })
  })
})

// ─── sysctl.set — name ────────────────────────────────────────────────────────

describe("sysctl.set — name", () => {
  it("has descriptive name for present state", () => {
    const mod = sysctl.set(KEY, VALUE)
    expect(mod.name).toBe(`sysctl.set: ${KEY}=${VALUE}`)
  })

  it("has descriptive name for absent state", () => {
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    expect(mod.name).toBe(`sysctl.set: absent ${KEY}`)
  })
})

// ─── sysctl.set — validation ──────────────────────────────────────────────────

describe("sysctl.set — validation", () => {
  it("throws when key is empty", () => {
    expect(() => sysctl.set("", VALUE)).toThrow(/key must not be empty/v)
  })

  it("throws when key contains a newline", () => {
    expect(() => sysctl.set(`${KEY}\nmalicious = 1`, VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a carriage return", () => {
    expect(() => sysctl.set(`${KEY}\rmalicious`, VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a path separator", () => {
    expect(() => sysctl.set("net/ipv4/ip_forward", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains whitespace", () => {
    expect(() => sysctl.set("net.ipv4 ip_forward", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a shell metacharacter", () => {
    expect(() => sysctl.set("net.ipv4.ip_forward;rm", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key starts with a short sysctl option", () => {
    expect(() => sysctl.set("-w", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key starts with a long sysctl option", () => {
    expect(() => sysctl.set("--system", VALUE)).toThrow(/key must match/v)
  })

  it("throws when value contains a newline", () => {
    expect(() => sysctl.set(KEY, "1\nkernel.hostname = pwned")).toThrow(
      /value must not contain newline/v
    )
  })

  it("throws when value contains a carriage return", () => {
    expect(() => sysctl.set(KEY, "1\rinjected")).toThrow(/value must not contain newline/v)
  })

  it("accepts a key with dots, underscores, hyphens, and digits", () => {
    expect(() => sysctl.set("net.ipv4.tcp_rmem-max_v2", "4096 87380 6291456")).not.toThrow()
  })
})
