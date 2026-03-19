import { describe, expect, it } from "vitest"

import { script } from "../../src/index.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("script.once — check", () => {
  it("returns needs-apply when flag does not exist", async () => {
    const mockSsh = createMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 1 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when flag exists", async () => {
    const mockSsh = createMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 0 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("uses correct flag path with custom version", async () => {
    const mockSsh = createMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-2' ]`]: { code: 0 },
    })
    const mod = script.once("setup", "/local/setup.sh", { version: "2" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain(`[ -f ${FLAGS_DIRECTORY}/'script-setup-2' ]`)
  })
})

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

describe("script.once — apply", () => {
  it("uploads script, makes it executable, runs it, cleans up, and sets flag", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")

    // mkdir -p for flags directory
    expect(mockSsh.calls).toContain(`mkdir -p ${FLAGS_DIRECTORY}`)

    // chmod +x on remote path
    expect(mockSsh.calls).toContain("chmod +x '/tmp/paratix-script-setup'")

    // script execution
    expect(mockSsh.calls).toContain("'/tmp/paratix-script-setup'")

    // cleanup of temp file
    expect(mockSsh.calls).toContain("rm -f '/tmp/paratix-script-setup'")

    // flag set
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
  })

  it("executes calls in correct order", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)

    const mkdirIdx = mockSsh.calls.indexOf(`mkdir -p ${FLAGS_DIRECTORY}`)
    const chmodIdx = mockSsh.calls.indexOf("chmod +x '/tmp/paratix-script-setup'")
    const execIdx = mockSsh.calls.indexOf("'/tmp/paratix-script-setup'")
    const flagIdx = mockSsh.calls.indexOf(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
    const rmIdx = mockSsh.calls.indexOf("rm -f '/tmp/paratix-script-setup'")

    expect(chmodIdx).toBeLessThan(execIdx)
    expect(execIdx).toBeLessThan(mkdirIdx)
    expect(mkdirIdx).toBeLessThan(flagIdx)
    // cleanup happens last (in finally block, after flag is set)
    expect(flagIdx).toBeLessThan(rmIdx)
  })

  it("returns failed when ssh is null", async () => {
    const mod = script.once("setup", "/local/setup.sh")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when script exits non-zero", async () => {
    const mockSsh = createMockSsh({
      "'/tmp/paratix-script-setup'": { code: 1 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("still cleans up temp file when script exits non-zero", async () => {
    const mockSsh = createMockSsh({
      "'/tmp/paratix-script-setup'": { code: 1 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("rm -f '/tmp/paratix-script-setup'")
  })

  it("does not set flag when script exits non-zero", async () => {
    const mockSsh = createMockSsh({
      "'/tmp/paratix-script-setup'": { code: 1 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeUndefined()
  })

  it("passes shell-quoted arguments to script", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh", { args: ["--env", "production"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("'/tmp/paratix-script-setup' '--env' 'production'")
  })

  it("does not append arguments when args is an empty array", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh", { args: [] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("'/tmp/paratix-script-setup'")
  })

  it("uses correct flag name with custom version", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh", { version: "2" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-2'`
    )
  })

  it("removes old version flags before setting new flag", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("setup", "/local/setup.sh", { version: "3" })
    await mod.apply(mockSsh, emptyEnv)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toContain(`find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete`)
    expect(flagCall).toContain(`touch ${FLAGS_DIRECTORY}/'script-setup-3'`)
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("script.once — name", () => {
  it("has correct name format: script.once: <name> (v<version>)", () => {
    const mod = script.once("setup", "/local/setup.sh")
    expect(mod.name).toBe("script.once: setup (v1)")
  })

  it("uses default version 1 in name", () => {
    const mod = script.once("setup", "/local/setup.sh")
    expect(mod.name).toBe("script.once: setup (v1)")
  })

  it("uses custom version in name", () => {
    const mod = script.once("setup", "/local/setup.sh", { version: "2" })
    expect(mod.name).toBe("script.once: setup (v2)")
  })
})

// ---------------------------------------------------------------------------
// flagPrefix shell-globbing (regression test for shellQuote bug)
// ---------------------------------------------------------------------------

describe("script.once — flagPrefix is shell-quoted to prevent injection", () => {
  it("find command uses shellQuote on flagPrefix to prevent command injection", async () => {
    const mockSsh = createMockSsh()
    const mod = script.once("my-script", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)

    // The find command that clears old version flags must shell-quote the prefix
    // to prevent command injection via crafted flag names. The glob star stays
    // outside the quotes so it still expands:
    //   find /var/lib/paratix/flags -maxdepth 1 -name 'script-my-script-*' -delete
    const expectedFindCmd = `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-my-script-*' -delete && touch ${FLAGS_DIRECTORY}/'script-my-script-1'`
    expect(mockSsh.calls).toContain(expectedFindCmd)
  })
})

// ---------------------------------------------------------------------------
// input validation
// ---------------------------------------------------------------------------

describe("script.once — input validation", () => {
  it("throws when name contains spaces", () => {
    expect(() => script.once("my setup", "/local/setup.sh")).toThrow(/name must match/v)
  })

  it("throws when name contains shell metacharacters", () => {
    expect(() => script.once("setup;rm", "/local/setup.sh")).toThrow(/name must match/v)
  })

  it("allows alphanumeric names with dots, hyphens, and underscores", () => {
    expect(() => script.once("my-setup_v1.0", "/local/setup.sh")).not.toThrow()
  })
})
