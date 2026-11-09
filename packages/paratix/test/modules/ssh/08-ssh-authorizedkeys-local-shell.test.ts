/* eslint-disable @typescript-eslint/require-await -- async interface methods of the local connection */
/* oxlint-disable jsdoc/require-param, jsdoc/require-returns -- inner connection methods of a test helper, not a public API */
/**
 * Shell-level tests for `ssh.authorizedKeys`: the production read, guard,
 * decode and replace scripts run through a real `/bin/sh` against a temporary
 * home directory, so a script that does not do what the mocks assume fails
 * here. The connection resolves `getent passwd` to the temporary home and
 * emulates the SFTP `writeFile`, including its refusal of a destination whose
 * directory resolves elsewhere. Needs GNU coreutils (`stat -c`,
 * `realpath -e`, `dd iflag=nofollow`), so it only runs on Linux.
 */
import { spawnSync } from "node:child_process"
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir, userInfo } from "node:os"
import { dirname, join } from "node:path"
import { afterEach, describe, expect, it } from "vitest"

import type {
  ExecOptions,
  ExecResult,
  Module,
  ModuleResult,
  SshConnection,
} from "../../../src/types.js"

import { ssh } from "../../../src/modules/ssh.js"

function sshString(value: Buffer | string): Buffer {
  const valueBytes = typeof value === "string" ? Buffer.from(value) : value
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(valueBytes.length)
  return Buffer.concat([lengthBuffer, valueBytes])
}

function ed25519Blob(fill: number): string {
  return Buffer.concat([sshString("ssh-ed25519"), sshString(Buffer.alloc(32, fill))]).toString(
    "base64"
  )
}

const blob = ed25519Blob(1)
const key = `ssh-ed25519 ${blob} test-key`
const otherLine = `ssh-ed25519 ${ed25519Blob(2)} other-key`
const USER = userInfo().username
const OCTAL_MODE_MASK = 0o777
const OWNER_ONLY_FILE_MODE = 0o600

function runShell(command: string): ExecResult {
  const result = spawnSync("/bin/sh", ["-c", command], { timeout: 10_000 })
  return {
    code: result.status ?? -1,
    stderr: result.stderr.toString("utf8"),
    stdout: result.stdout.toString("utf8"),
  }
}

function hasGnuShellTools(): boolean {
  if (process.platform !== "linux") return false
  const probe = runShell(
    "command -p realpath -e -- / >/dev/null && stat -c '%d:%i' -- / >/dev/null && printf '' | base64 -w 0 && dd if=/dev/null iflag=nofollow status=none && id -gn >/dev/null"
  )
  return probe.code === 0 && /^[a-z_][a-z0-9_\-]*$/v.test(USER)
}

type LocalHost = {
  connection: SshConnection
  keysPath: string
  sshDirectory: string
}

/**
 * A connection whose commands run on the local `/bin/sh`.
 *
 * @param home - The home directory `getent passwd` reports for the user.
 * @param beforeExec - Optional hook that runs before each exec, e.g. to
 *   simulate a concurrent edit right before the final replace.
 * @returns The connection and the literal `.ssh` paths.
 */
function createLocalHost(home: string, beforeExec?: (command: string) => void): LocalHost {
  async function exec(command: string, options?: ExecOptions): Promise<ExecResult> {
    beforeExec?.(command)
    const result = runShell(command)
    if (result.code !== 0 && options?.ignoreExitCode !== true) {
      throw new Error(`command failed (${String(result.code)}): ${result.stderr}`)
    }
    return result
  }
  async function output(command: string): Promise<string> {
    if (command === `getent passwd '${USER}' | cut -d: -f6`) return home
    const result = await exec(command)
    return result.stdout.trim()
  }
  async function test(command: string): Promise<boolean> {
    const result = await exec(command, { ignoreExitCode: true })
    return result.code === 0
  }
  const connection = {
    exec,
    async exists(path: string) {
      return test(`[ -e '${path}' ]`)
    },
    output,
    test,
    async writeFile(remotePath: string, content: string, options?: { mode?: string }) {
      // Mirrors the dirname symlink guard of the real SFTP writeFile.
      const directory = dirname(remotePath)
      const resolved = runShell(`command -p realpath -m -- '${directory}'`).stdout.trim()
      if (resolved !== directory) {
        throw new Error(`refusing to write through symlinked path component: ${resolved}`)
      }
      const temporary = `${remotePath}.write-tmp`
      writeFileSync(temporary, content, "utf8")
      chmodSync(temporary, Number.parseInt(options?.mode ?? "0600", 8))
      renameSync(temporary, remotePath)
    },
  } as unknown as SshConnection
  const sshDirectory = `${home}/.ssh`
  return { connection, keysPath: `${sshDirectory}/authorized_keys`, sshDirectory }
}

async function dryRun(module: Module, connection: SshConnection): Promise<ModuleResult> {
  const result = await module._applyDryRun?.(connection, {})
  if (result === undefined) throw new Error("module has no dry-run")
  return result
}

function leftoverStagingFiles(sshDirectory: string): string[] {
  return readdirSync(sshDirectory).filter((name) => name.startsWith(".paratix-authorized-keys"))
}

const roots: string[] = []

function makeRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "paratix-authorized-keys-shell-")))
  roots.push(root)
  return root
}

/**
 * Lay out `<root>/data/home/<user>` and the symlink `<root>/home -> data/home`,
 * like a host whose `/home` points to another volume.
 *
 * @returns The literal home path that contains the symlinked component.
 */
function makeSymlinkedHome(): string {
  const root = makeRoot()
  const realHome = join(root, "data", "home", USER)
  mkdirSync(realHome, { recursive: true })
  symlinkSync(join(root, "data", "home"), join(root, "home"))
  return join(root, "home", USER)
}

/**
 * Hook that appends `text` to `keysPath` right before the final replace runs.
 *
 * @param keysPath - The literal `authorized_keys` path.
 * @param text - The concurrently added content.
 * @returns The `beforeExec` hook.
 */
function appendBeforeReplace(keysPath: string, text: string): (command: string) => void {
  return (command) => {
    if (isFinalReplace(command)) writeFileSync(keysPath, text, { flag: "a" })
  }
}

function isFinalReplace(command: string): boolean {
  return command.includes("\nchown -h -- ")
}

function isDecode(command: string): boolean {
  return command.includes(" | base64 -d | ")
}

const STAGED_PATH_PATTERN = /'(?<path>[^']*\/\.paratix-authorized-keys\.[^'\/]+)'/v
const PAYLOAD_DIRECTORY_PATTERN =
  /'(?<path>\/tmp\/paratix-authorized-keys-payload\.[^'\/]+)\/payload\.base64'/v
const STAGED_FILE_REFUSAL =
  "authorized_keys staging file must be a regular single-link file owned by the staging user"
const STAGED_FILE_MODE_REFUSAL = "authorized_keys staging file must have mode 600"

/**
 * Hook that changes the mode of the staged file right before the final
 * replace runs, as a default ACL or the owner of `~/.ssh` could.
 *
 * @param mode - The mode the staged file gets.
 * @returns The `beforeExec` hook.
 */
function chmodStagedBeforeReplace(mode: number): (command: string) => void {
  return (command) => {
    const staged = STAGED_PATH_PATTERN.exec(command)?.groups?.path
    if (isFinalReplace(command) && staged !== undefined) chmodSync(staged, mode)
  }
}

/**
 * Give `directory` a default ACL that grants the owning group read and write
 * access, so files created in it ignore the umask for the group bits.
 *
 * @param directory - The directory that gets the default ACL.
 * @returns The `setfacl` result.
 */
function grantGroupWriteByDefaultAcl(directory: string): ExecResult {
  return runShell(`setfacl -d -m g::rw -- '${directory}'`)
}

/**
 * Whether `setfacl` exists and the temporary filesystem honours a default
 * ACL over the umask, probed once in a throwaway directory.
 *
 * @returns `true` when a file created under `umask 077` gets group bits.
 */
function defaultAclOverridesUmask(): boolean {
  if (runShell("command -v setfacl >/dev/null").code !== 0) return false
  const directory = mkdtempSync(join(tmpdir(), "paratix-authorized-keys-acl-"))
  try {
    if (grantGroupWriteByDefaultAcl(directory).code !== 0) return false
    const probe = join(directory, "acl-probe")
    const created = runShell(`umask 077 && : > '${probe}'`)
    return created.code === 0 && (statSync(probe).mode & OCTAL_MODE_MASK) !== 0o600
  } finally {
    rmSync(directory, { force: true, recursive: true })
  }
}

type StagedSwap = "hardlink" | "symlink"

/**
 * Hook that replaces the staged file in `~/.ssh` by a link to `victim` right
 * before the matching command runs, as the owner of `~/.ssh` could, and
 * records the payload directory named by the decode script.
 *
 * @param parameters - Swap kind, trigger and victim file.
 * @param parameters.kind - Whether the swap uses a symlink or a hard link.
 * @param parameters.payloadDirectories - Receives the payload directories seen.
 * @param parameters.trigger - Selects the command before which the swap happens.
 * @param parameters.victim - The file the swapped entry points to.
 * @returns The `beforeExec` hook.
 */
function swapStagedFile(parameters: {
  kind: StagedSwap
  payloadDirectories: string[]
  trigger: (command: string) => boolean
  victim: string
}): (command: string) => void {
  const { kind, payloadDirectories, trigger, victim } = parameters
  return (command) => {
    const payloadDirectory = PAYLOAD_DIRECTORY_PATTERN.exec(command)?.groups?.path
    if (payloadDirectory !== undefined) payloadDirectories.push(payloadDirectory)
    const staged = STAGED_PATH_PATTERN.exec(command)?.groups?.path
    if (!trigger(command) || staged === undefined) return
    rmSync(staged, { force: true })
    if (kind === "symlink") symlinkSync(victim, staged)
    else linkSync(victim, staged)
  }
}

const GNU_SHELL_TOOLS = hasGnuShellTools()
const DEFAULT_ACL_SUPPORTED = GNU_SHELL_TOOLS && defaultAclOverridesUmask()

describe.skipIf(!GNU_SHELL_TOOLS)("ssh.authorizedKeys on a local shell", () => {
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
  })

  it("rewrites through a symlinked /home and keeps non-UTF-8 bytes of foreign lines", async () => {
    const home = makeSymlinkedHome()
    const host = createLocalHost(home)
    const foreign = Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x80, 0x0a])
    const initial = Buffer.concat([foreign, Buffer.from(`${otherLine}\n`)])
    mkdirSync(host.sshDirectory, { mode: 0o700 })
    writeFileSync(host.keysPath, initial, { mode: OWNER_ONLY_FILE_MODE })
    const module = ssh.authorizedKeys(USER, key)

    await expect(dryRun(module, host.connection)).resolves.toStrictEqual({ status: "changed" })
    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "changed" })

    expect(readFileSync(host.keysPath)).toStrictEqual(
      Buffer.concat([initial, Buffer.from(`${key}\n`)])
    )
    expect(statSync(host.keysPath).mode & OCTAL_MODE_MASK).toBe(OWNER_ONLY_FILE_MODE)
    expect(leftoverStagingFiles(host.sshDirectory)).toStrictEqual([])
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "ok" })
  })

  it("creates .ssh and authorized_keys for a missing file", async () => {
    const home = makeSymlinkedHome()
    const host = createLocalHost(home)
    const module = ssh.authorizedKeys(USER, key, { options: { restrict: true } })

    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "changed" })

    expect(readFileSync(host.keysPath, "utf8")).toBe(`restrict ${key}\n`)
    expect(statSync(host.sshDirectory).mode & OCTAL_MODE_MASK).toBe(0o700)
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
  })

  it("fails without overwriting a concurrent change between read and replace", async () => {
    const home = join(makeRoot(), USER)
    const sshDirectory = `${home}/.ssh`
    const keysPath = `${sshDirectory}/authorized_keys`
    const concurrent = `ssh-ed25519 ${ed25519Blob(3)} added-concurrently\n`
    const host = createLocalHost(home, appendBeforeReplace(keysPath, concurrent))
    mkdirSync(sshDirectory, { mode: 0o700, recursive: true })
    writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })

    const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("authorized_keys changed during rewrite")
    expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n${concurrent}`)
    expect(readdirSync(sshDirectory).filter((name) => name !== "authorized_keys")).toStrictEqual([])
  })

  it("removes the key for absent and keeps a cert-authority line of the same blob", async () => {
    const home = join(makeRoot(), USER)
    const host = createLocalHost(home)
    const authority = `cert-authority ssh-ed25519 ${blob} user-ca`
    mkdirSync(host.sshDirectory, { mode: 0o700, recursive: true })
    writeFileSync(host.keysPath, `${authority}\r\n${key}\n${otherLine}\n`, {
      mode: OWNER_ONLY_FILE_MODE,
    })
    const module = ssh.authorizedKeys(USER, key, { state: "absent" })

    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "changed" })

    expect(readFileSync(host.keysPath, "utf8")).toBe(`${authority}\r\n${otherLine}\n`)
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
  })

  it.each([
    ["a symlink before the decode", "symlink", isDecode],
    ["a hard link before the decode", "hardlink", isDecode],
    ["a symlink before the replace", "symlink", isFinalReplace],
    ["a hard link before the replace", "hardlink", isFinalReplace],
  ] as const)(
    "refuses a staged file swapped for %s and leaves the link target untouched",
    async (_label, kind, trigger) => {
      const root = makeRoot()
      const home = join(root, USER)
      const sshDirectory = `${home}/.ssh`
      const keysPath = `${sshDirectory}/authorized_keys`
      const victim = join(root, "victim")
      const payloadDirectories: string[] = []
      writeFileSync(victim, "victim\n", { mode: 0o644 })
      chmodSync(victim, 0o644)
      mkdirSync(sshDirectory, { mode: 0o700, recursive: true })
      writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
      const host = createLocalHost(
        home,
        swapStagedFile({ kind, payloadDirectories, trigger, victim })
      )

      const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(STAGED_FILE_REFUSAL)
      expect(readFileSync(victim, "utf8")).toBe("victim\n")
      expect(statSync(victim).mode & OCTAL_MODE_MASK).toBe(0o644)
      expect(statSync(victim).nlink).toBe(1)
      expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n`)
      expect(leftoverStagingFiles(sshDirectory)).toStrictEqual([])
      expect(payloadDirectories.length).toBeGreaterThan(0)
      expect(payloadDirectories.filter((directory) => existsSync(directory))).toStrictEqual([])
    }
  )

  it("refuses a staged file without mode 600 before the replace publishes it", async () => {
    const home = join(makeRoot(), USER)
    const sshDirectory = `${home}/.ssh`
    const keysPath = `${sshDirectory}/authorized_keys`
    mkdirSync(sshDirectory, { mode: 0o700, recursive: true })
    writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
    const host = createLocalHost(home, chmodStagedBeforeReplace(0o640))

    const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(STAGED_FILE_MODE_REFUSAL)
    expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n`)
    expect(statSync(keysPath).mode & OCTAL_MODE_MASK).toBe(OWNER_ONLY_FILE_MODE)
    expect(readdirSync(sshDirectory)).toStrictEqual(["authorized_keys"])
  })

  // Needs `setfacl` and a temporary filesystem with default ACL support.
  it.skipIf(!DEFAULT_ACL_SUPPORTED)(
    "fails in the decode, without publishing, when a default ACL on .ssh overrides the umask",
    async () => {
      const home = join(makeRoot(), USER)
      const sshDirectory = `${home}/.ssh`
      const keysPath = `${sshDirectory}/authorized_keys`
      mkdirSync(sshDirectory, { mode: 0o700, recursive: true })
      writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
      expect(grantGroupWriteByDefaultAcl(sshDirectory).code).toBe(0)
      const commands: string[] = []
      const host = createLocalHost(home, (command) => {
        commands.push(command)
      })

      const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("failed to stage authorized_keys rewrite")
      expect(result.error?.message).toContain(STAGED_FILE_MODE_REFUSAL)
      expect(commands.some((command) => isFinalReplace(command))).toBe(false)
      expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n`)
      expect(readdirSync(sshDirectory)).toStrictEqual(["authorized_keys"])
    }
  )

  it("refuses a symlinked .ssh in dry-run and apply and leaves its target untouched", async () => {
    const root = makeRoot()
    const home = join(root, USER)
    const elsewhere = join(root, "elsewhere")
    mkdirSync(home)
    mkdirSync(elsewhere, { mode: 0o755 })
    writeFileSync(join(elsewhere, "authorized_keys"), `${otherLine}\n`, { mode: 0o644 })
    symlinkSync(elsewhere, join(home, ".ssh"))
    const host = createLocalHost(home)
    const module = ssh.authorizedKeys(USER, key)

    const dryRunResult = await dryRun(module, host.connection)
    const applyResult = await module.apply(host.connection, {})

    expect(dryRunResult.status).toBe("failed")
    expect(dryRunResult.error?.message).toContain(".ssh must not be a symlink")
    expect(applyResult.status).toBe("failed")
    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(readFileSync(join(elsewhere, "authorized_keys"), "utf8")).toBe(`${otherLine}\n`)
    expect(statSync(elsewhere).mode & OCTAL_MODE_MASK).toBe(0o755)
  })
})
