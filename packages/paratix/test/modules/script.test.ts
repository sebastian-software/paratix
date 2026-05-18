import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { script } from "../../src/index.js"
import { shellQuote } from "../../src/ssh.js"
import { createStrictMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"

// R-0000717: script.once now validates that `localPath` resolves to a
// regular file at module-construction time. Tests use a real fixture in a
// temp directory so the validation accepts the path. The fixture is
// created eagerly at module load (synchronous) so it is available for all
// top-level `script.once(...)` calls inside the various `describe` blocks
// below. Cleanup runs via Vitest's process-level `afterAll`-style hook
// using `process.on("beforeExit")`, which keeps the cleanup out of any
// individual `describe` block (so a sibling describe does not prematurely
// remove the fixture between tests) while still satisfying
// `eslint-plugin-vitest(require-top-level-describe)`.
const LOCAL_SCRIPT_DIRECTORY = mkdtempSync(join(tmpdir(), "paratix-script-test-"))
const LOCAL_SCRIPT_PATH = join(LOCAL_SCRIPT_DIRECTORY, "setup.sh")
writeFileSync(LOCAL_SCRIPT_PATH, "#!/bin/sh\nexit 0\n", { mode: 0o755 })
process.once("beforeExit", () => {
  rmSync(LOCAL_SCRIPT_DIRECTORY, { force: true, recursive: true })
})

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
  const quotedArgs = args?.map((arg) => shellQuote(arg)).join(" ") ?? ""
  if (quotedArgs === "") return shellQuote(remotePath)
  return `${shellQuote(remotePath)} ${quotedArgs}`
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
  const mktempCmd = `mktemp -p /tmp -- 'paratix-script-${name}.XXXXXX'`
  const scriptCommand = buildScriptCommand(remotePath, options?.args)
  const flagName = `script-${name}-${version}`
  const lockName = `${flagName}.lock`
  const flagCommand = `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-${name}-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-${name}-${version}'`

  return createStrictMockSsh(
    {
      [`[ -f ${FLAGS_DIRECTORY}/'${flagName}' ]`]: { code: 1 },
      [`chmod +x '${remotePath}'`]: { code: 0 },
      [`mkdir -p ${FLAGS_DIRECTORY}`]: { code: 0 },
      [`mkdir ${FLAGS_DIRECTORY}/'${lockName}'`]: { code: 0 },
      [`rm -f -- '${remotePath}'`]: { code: 0 },
      [`rmdir ${FLAGS_DIRECTORY}/'${lockName}'`]: { code: 0 },
      [flagCommand]: { code: 0 },
      [mktempCmd]: { code: 0, stdout: `${remotePath}\n` },
      [scriptCommand]: { code: 0 },
      ...options?.responses,
    },
    {
      allowFlagLockInternalDefaults: true,
      allowUploads: [
        {
          localPath: LOCAL_SCRIPT_PATH,
          options: undefined,
          remotePath: /^\/tmp\/paratix-script-[^.]+\.[^.]+$/v,
        },
      ],
    }
  )
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("script.once — check", () => {
  it("returns needs-apply when flag does not exist", async () => {
    const mockSsh = createStrictMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 1 },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when flag exists", async () => {
    const mockSsh = createStrictMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 0 },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("uses correct flag path with custom version", async () => {
    const mockSsh = createStrictMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-2' ]`]: { code: 0 },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { version: "2" })
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
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")

    // mkdir -p for flags directory
    expect(mockSsh.calls).toContain(`mkdir -p ${FLAGS_DIRECTORY}`)

    // chmod +x on remote path
    expect(mockSsh.calls).toContain(`chmod +x '${remotePath}'`)

    // script execution
    expect(mockSsh.calls).toContain(`'${remotePath}'`)

    // cleanup of per-run temp file
    expect(mockSsh.calls).toContain(`rm -f -- '${remotePath}'`)

    // flag set
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-setup-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
  })

  it("executes calls in correct order", async () => {
    const mockSsh = createScriptMockSsh()
    const remotePath = makeRemoteScriptPath("setup")
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    await mod.apply(mockSsh, emptyEnv)

    const mkdirIdx = mockSsh.calls.indexOf(`mkdir -p ${FLAGS_DIRECTORY}`)
    const chmodIdx = mockSsh.calls.indexOf(`chmod +x '${remotePath}'`)
    const execIdx = mockSsh.calls.indexOf(`'${remotePath}'`)
    const flagIdx = mockSsh.calls.indexOf(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-setup-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
    const rmIdx = mockSsh.calls.indexOf(`rm -f -- '${remotePath}'`)

    expect(chmodIdx).toBeLessThan(execIdx)
    expect(mkdirIdx).toBeLessThan(chmodIdx)
    expect(mkdirIdx).toBeLessThan(flagIdx)
    // cleanup happens last (in finally block, after flag is set)
    expect(flagIdx).toBeLessThan(rmIdx)
  })

  it("returns failed when ssh is null", async () => {
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
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
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
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
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`rm -f -- '${remotePath}'`)
  })

  it("returns failed and cleans up temp file when uploadFile throws after mktemp", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh()
    mockSsh.uploadFile = async (localPath, uploadRemotePath, options) => {
      mockSsh.uploadFileCalls.push({ localPath, options, remotePath: uploadRemotePath })
      await Promise.resolve()
      throw new Error("upload failed")
    }
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[script.once: setup] upload failed")
    expect(String(result.error)).toContain("upload failed")
    expect(mockSsh.calls).toContain(`rm -f -- '${remotePath}'`)
    expect(mockSsh.calls).not.toContain(`chmod +x '${remotePath}'`)
    expect(mockSsh.calls).not.toContain(`'${remotePath}'`)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeUndefined()
  })

  it("does not set flag when script exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`'${remotePath}'`]: { code: 1 },
      },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    await mod.apply(mockSsh, emptyEnv)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeUndefined()
  })

  // R-0000248 regression: chmod failures must surface as a structured
  // `failedCommand` ModuleResult and must not leak as an unstructured SSH
  // exception.
  it("R-0000248: returns failed when chmod +x exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`chmod +x '${remotePath}'`]: { code: 1, stderr: "chmod: Read-only file system" },
      },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("[script.once: setup] chmod failed")
    expect(String(result.error)).toContain("Read-only file system")
    // Script body must not run when chmod failed; cleanup still happens.
    expect(mockSsh.calls).not.toContain(`'${remotePath}'`)
    expect(mockSsh.calls).toContain(`rm -f -- '${remotePath}'`)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeUndefined()
  })

  it("preserves changed status when finally rm cleanup exits non-zero", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        [`rm -f -- '${remotePath}'`]: { code: 1, stderr: "rm: read-only file system" },
      },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.apply(mockSsh, emptyEnv)

    // The rm cleanup ran with ignoreExitCode, so the successful run is preserved.
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`rm -f -- '${remotePath}'`)
    // Versioned flag must still be set so the next run skips re-execution.
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toBeDefined()
  })

  it("direct apply returns ok without uploading when the flag already exists", async () => {
    const mockSsh = createStrictMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'script-setup-1' ]`]: { code: 0 },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result).toStrictEqual({ status: "ok" })
    expect(mockSsh.uploadFileCalls).toHaveLength(0)
    expect(mockSsh.calls).not.toContain("mktemp -p /tmp -- 'paratix-script-setup.XXXXXX'")
    expect(mockSsh.calls).not.toContain(`mkdir ${FLAGS_DIRECTORY}/'script-setup-1.lock'`)
  })

  it("passes shell-quoted arguments to script", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({ args: ["--env", "production"] })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { args: ["--env", "production"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`'${remotePath}' '--env' 'production'`)
  })

  it("shell-quotes arguments that contain quotes, backslashes, and command substitution", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const args = ["a'b", String.raw`x\y`, "$(id)"]
    const mockSsh = createScriptMockSsh({ args })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { args })

    await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.calls).toContain(
      `${shellQuote(remotePath)} ${args.map((arg) => shellQuote(arg)).join(" ")}`
    )
  })

  it("does not append arguments when args is an empty array", async () => {
    const remotePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh()
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { args: [] })
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

    const modA = script.once("setup", LOCAL_SCRIPT_PATH)
    const modB = script.once("setup", LOCAL_SCRIPT_PATH)

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
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("mktemp -p /tmp -- 'paratix-script-setup.XXXXXX'")
  })

  it.each([
    ["empty output", ""],
    ["multiline output", "/tmp/paratix-script-setup.ABCDEF\n/tmp/paratix-script-setup.EVIL"],
    ["outside /tmp", "/var/tmp/paratix-script-setup.ABCDEF"],
    ["wrong prefix", "/tmp/not-paratix-script-setup.ABCDEF"],
  ])("rejects unsafe mktemp output: %s", async (_caseName, stdout) => {
    const safePath = makeRemoteScriptPath("setup")
    const mockSsh = createScriptMockSsh({
      responses: {
        "mktemp -p /tmp -- 'paratix-script-setup.XXXXXX'": { code: 0, stdout },
      },
    })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).not.toContain(`chmod +x '${safePath}'`)
    expect(mockSsh.calls).not.toContain(`'${safePath}'`)
    expect(mockSsh.calls).not.toContain(`rm -f -- '${safePath}'`)
    expect(mockSsh.calls).not.toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-setup-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-1'`
    )
  })

  it("uses correct flag name with custom version", async () => {
    const mockSsh = createScriptMockSsh({ version: "2" })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { version: "2" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-setup-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-setup-2'`
    )
  })

  it("removes old version flags before setting new flag", async () => {
    const mockSsh = createScriptMockSsh({ version: "3" })
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { version: "3" })
    await mod.apply(mockSsh, emptyEnv)
    const flagCall = mockSsh.calls.find((c) => c.includes("touch"))
    expect(flagCall).toContain(
      `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-setup-*' ! -name '*.lock' -delete`
    )
    expect(flagCall).toContain(`touch ${FLAGS_DIRECTORY}/'script-setup-3'`)
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("script.once — name", () => {
  it("has correct name format: script.once: <name> (v<version>)", () => {
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    expect(mod.name).toBe("script.once: setup (v1)")
  })

  it("uses default version 1 in name", () => {
    const mod = script.once("setup", LOCAL_SCRIPT_PATH)
    expect(mod.name).toBe("script.once: setup (v1)")
  })

  it("uses custom version in name", () => {
    const mod = script.once("setup", LOCAL_SCRIPT_PATH, { version: "2" })
    expect(mod.name).toBe("script.once: setup (v2)")
  })
})

// ---------------------------------------------------------------------------
// flagPrefix shell-globbing (regression test for shellQuote bug)
// ---------------------------------------------------------------------------

describe("script.once — flagPrefix is shell-quoted to prevent injection", () => {
  it("find command uses shellQuote on flagPrefix to prevent command injection", async () => {
    const mockSsh = createScriptMockSsh({ name: "my-script" })
    const mod = script.once("my-script", LOCAL_SCRIPT_PATH)
    await mod.apply(mockSsh, emptyEnv)

    // The find command that clears old version flags must shell-quote the prefix
    // to prevent command injection via crafted flag names. The glob star stays
    // outside the quotes so it still expands:
    //   find /var/lib/paratix/flags -maxdepth 1 -type f -name 'script-my-script-*' ! -name '*.lock' -delete
    const expectedFindCmd = `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name 'script-my-script-*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'script-my-script-1'`
    expect(mockSsh.calls).toContain(expectedFindCmd)
  })
})

// ---------------------------------------------------------------------------
// input validation
// ---------------------------------------------------------------------------

describe("script.once — input validation", () => {
  it("throws when name contains spaces", () => {
    expect(() => script.once("my setup", LOCAL_SCRIPT_PATH)).toThrow(/name must match/v)
  })

  it("throws when name contains shell metacharacters", () => {
    expect(() => script.once("setup;rm", LOCAL_SCRIPT_PATH)).toThrow(/name must match/v)
  })

  it("allows alphanumeric names with dots, hyphens, and underscores", () => {
    expect(() => script.once("my-setup_v1.0", LOCAL_SCRIPT_PATH)).not.toThrow()
  })

  // R-0000717: localPath must point to a regular file. Misconfigured
  // playbooks (wrong path, accidentally pointing at a directory, dangling
  // symlink) must fail at module-construction time, not mid-apply.
  it("R-0000717: throws when localPath does not exist", () => {
    expect(() => script.once("setup", join(LOCAL_SCRIPT_DIRECTORY, "missing.sh"))).toThrow(
      /cannot read local script/v
    )
  })

  it("R-0000717: throws when localPath is a directory", () => {
    expect(() => script.once("setup", LOCAL_SCRIPT_DIRECTORY)).toThrow(/expected a regular file/v)
  })

  // R-0000717: cap the number of CLI arguments forwarded to the remote
  // process so command lines cannot silently exceed the kernel `ARG_MAX`
  // at execution time.
  it("R-0000717: throws when args length exceeds the documented cap", () => {
    const tooManyArgs = Array.from({ length: 1025 }, (_, index) => `arg-${String(index)}`)
    expect(() => script.once("setup", LOCAL_SCRIPT_PATH, { args: tooManyArgs })).toThrow(
      /args must contain at most 1024 entries/v
    )
  })

  it("R-0000717: throws when a single arg exceeds the per-argument length cap", () => {
    const longArg = "x".repeat(4097)
    expect(() => script.once("setup", LOCAL_SCRIPT_PATH, { args: [longArg] })).toThrow(
      /args\[0\] exceeds maximum length of 4096 characters/v
    )
  })

  it("R-0000717: accepts args at the maximum boundary", () => {
    const maxArgs = Array.from({ length: 1024 }, (_, index) => `arg-${String(index)}`)
    expect(() => script.once("setup", LOCAL_SCRIPT_PATH, { args: maxArgs })).not.toThrow()
    const maxLengthArg = "x".repeat(4096)
    expect(() => script.once("setup", LOCAL_SCRIPT_PATH, { args: [maxLengthArg] })).not.toThrow()
  })
})
