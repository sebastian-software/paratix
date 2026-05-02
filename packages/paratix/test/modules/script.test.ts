import { describe, expect, it } from "vitest"

import { script } from "../../src/index.js"
import { createStrictMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"

/**
 * Build the deterministic stdout that the mock returns for the per-run
 * `mktemp` invocation. Tests pin this to a known string so the rest of
 * the apply pipeline (chmod, exec, rm) matches predictable commands.
 *
 * @param name - The script name embedded in the temp path.
 * @param suffix - The 6-character random suffix; default "ABCDEF".
 * @returns The simulated mktemp path.
 */
function makeRemoteScriptPath(name: string, suffix = "ABCDEF"): string {
  return `/tmp/paratix-script-${name}.${suffix}`
}

function buildScriptCommand(remotePath: string, args?: string[]): string {
  const quotedArgs = args?.map((arg) => `'${arg}'`).join(" ") ?? ""
  if (quotedArgs === "") return `'${remotePath}'`
  return `'${remotePath}' ${quotedArgs}`
}

function createScriptMockSsh(options?: {
  args?: string[]
  name?: string
  remoteSuffix?: string
  responses?: Record<string, { code?: number; stderr?: string; stdout?: string }>
  version?: string
}) {
  const name = options?.name ?? "setup"
  const version = options?.version ?? "1"
  const remotePath = makeRemoteScriptPath(name, options?.remoteSuffix)
  const mktempCmd = `mktemp -p /tmp 'paratix-script-${name}.XXXXXX'`
  const scriptCommand = buildScriptCommand(remotePath, options?.args)
  const flagCommand = `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-${name}-*' -delete && touch ${FLAGS_DIRECTORY}/'script-${name}-${version}'`

  return createStrictMockSsh({
    [`chmod +x '${remotePath}'`]: { code: 0 },
    [`mkdir -p ${FLAGS_DIRECTORY}`]: { code: 0 },
    [`rm -f '${remotePath}'`]: { code: 0 },
    [flagCommand]: { code: 0 },
    [mktempCmd]: { code: 0, stdout: `${remotePath}\n` },
    [scriptCommand]: { code: 0 },
    ...options?.responses,
  })
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("script.once — check", () => {
  it("returns needs-apply when flag does not exist", async () => {
    const mockSsh = createStrictMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 1 },
    })
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when flag exists", async () => {
    const mockSsh = createStrictMockSsh({
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
    const mockSsh = createStrictMockSsh({
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
    const mockSsh = createScriptMockSsh()
    const remotePath = makeRemoteScriptPath("setup")
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")

    // mkdir -p for flags directory
    expect(mockSsh.calls).toContain(`mkdir -p ${FLAGS_DIRECTORY}`)

    // chmod +x on remote path
    expect(mockSsh.calls).toContain(`chmod +x '${remotePath}'`)

    // script execution
    expect(mockSsh.calls).toContain(`'${remotePath}'`)

    // cleanup of per-run temp file
    expect(mockSsh.calls).toContain(`rm -f '${remotePath}'`)

    // flag set
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
  })

  it("executes calls in correct order", async () => {
    const mockSsh = createScriptMockSsh()
    const remotePath = makeRemoteScriptPath("setup")
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)

    const mkdirIdx = mockSsh.calls.indexOf(`mkdir -p ${FLAGS_DIRECTORY}`)
    const chmodIdx = mockSsh.calls.indexOf(`chmod +x '${remotePath}'`)
    const execIdx = mockSsh.calls.indexOf(`'${remotePath}'`)
    const flagIdx = mockSsh.calls.indexOf(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
    const rmIdx = mockSsh.calls.indexOf(`rm -f '${remotePath}'`)

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
    expect(result.error).toBeInstanceOf(Error)
  })

  it("returns failed when script exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`'${remotePath}'`]: { code: 1, stderr: "boom" },
      },
    })
    const mod = script.once("setup", "/local/setup.sh")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[script.once: setup] script execution failed")
    expect(result.error?.message).toContain("boom")
  })

  it("still cleans up temp file when script exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`'${remotePath}'`]: { code: 1 },
      },
    })
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`rm -f '${remotePath}'`)
  })

  it("does not set flag when script exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`'${remotePath}'`]: { code: 1 },
      },
    })
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeUndefined()
  })

  it("passes shell-quoted arguments to script", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({ args: ["--env", "production"] })
    const mod = script.once("setup", "/local/setup.sh", { args: ["--env", "production"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`'${remotePath}' '--env' 'production'`)
  })

  it("does not append arguments when args is an empty array", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh()
    const mod = script.once("setup", "/local/setup.sh", { args: [] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`'${remotePath}'`)
  })

  // R-0000050 regression: two parallel applies of the same script must use
  // distinct per-run remote paths so they cannot race on the legacy
  // deterministic `/tmp/paratix-script-<name>` path.
  it("two parallel applies use distinct mktemp-allocated remote paths", async () => {
    const firstPath = makeRemoteScriptPath("setup", "AAAAAA")
    const secondPath = makeRemoteScriptPath("setup", "BBBBBB")
    const mockSshA = createScriptMockSsh({ remoteSuffix: "AAAAAA" })
    const mockSshB = createScriptMockSsh({ remoteSuffix: "BBBBBB" })

    const modA = script.once("setup", "/local/setup.sh")
    const modB = script.once("setup", "/local/setup.sh")

    const [resultA, resultB] = await Promise.all([
      modA.apply(mockSshA, emptyEnv),
      modB.apply(mockSshB, emptyEnv),
    ])

    expect(resultA.status).toBe("changed")
    expect(resultB.status).toBe("changed")
    expect(firstPath).not.toBe(secondPath)
    expect(mockSshA.calls).toContain(`'${firstPath}'`)
    expect(mockSshB.calls).toContain(`'${secondPath}'`)
    // The two runs must not share the same remote path.
    expect(mockSshA.calls).not.toContain(`'${secondPath}'`)
    expect(mockSshB.calls).not.toContain(`'${firstPath}'`)
  })

  it("creates the remote path via mktemp -p /tmp paratix-script-<name>.XXXXXX", async () => {
    const mockSsh = createScriptMockSsh()
    const mod = script.once("setup", "/local/setup.sh")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("mktemp -p /tmp 'paratix-script-setup.XXXXXX'")
  })

  it("uses correct flag name with custom version", async () => {
    const mockSsh = createScriptMockSsh({ version: "2" })
    const mod = script.once("setup", "/local/setup.sh", { version: "2" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -name 'script-setup-*' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-2'`
    )
  })

  it("removes old version flags before setting new flag", async () => {
    const mockSsh = createScriptMockSsh({ version: "3" })
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
    const mockSsh = createScriptMockSsh({ name: "my-script" })
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
