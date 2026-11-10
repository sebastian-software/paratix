/* eslint-disable @typescript-eslint/require-await -- async interface methods of the local connection */
/* oxlint-disable jsdoc/require-param, jsdoc/require-returns -- inner connection methods of a test helper, not a public API */
/**
 * Shell-level tests for `ssh.authorizedKeys`: the production account probe,
 * read, prepare, decode, replace and cleanup scripts run through a real
 * `/bin/sh` against a temporary home directory, so a script that does not do
 * what the mocks assume fails here. The connection resolves `getent passwd`
 * to the temporary home and emulates the SFTP `writeFile`, including its
 * refusal of a destination whose directory resolves elsewhere. The tests run
 * as the target user, so the account probe reports the same uid and the
 * privilege-drop prefix is empty; the `cd -P`, `pwd -P` and identity checks
 * run unchanged. Needs GNU coreutils (`stat -c`, `realpath -e`,
 * `dd iflag=nofollow`), so it only runs on Linux.
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
import {
  asAuthorizedKeysUser,
  asAuthorizedKeysUserReadingPipe,
  AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING,
  type AuthorizedKeysAccount,
} from "../../../src/modules/sshAuthorizedKeysAccount.js"

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

function runShell(
  command: string,
  env?: NodeJS.ProcessEnv,
  options: { input?: string; userNamespace?: boolean } = {}
): ExecResult {
  const [program, args] =
    options.userNamespace === true
      ? ["unshare", ["-r", "/bin/sh", "-c", command]]
      : ["/bin/sh", ["-c", command]]
  const result = spawnSync(program, args, { env, input: options.input, timeout: 10_000 })
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

type LocalHostOptions = {
  /** Environment of every remote command, e.g. a `PATH` without `setpriv`. */
  env?: NodeJS.ProcessEnv
  /** Text on the stdin of every remote command, like a sudo password on the channel. */
  stdin?: string
  /** The user whose `getent passwd` lookup reports `home`. */
  user?: string
  /** Whether commands run in a user namespace that maps the test user to root. */
  userNamespace?: boolean
}

/**
 * A connection whose commands run on the local `/bin/sh`.
 *
 * @param home - The home directory `getent passwd` reports for the user.
 * @param beforeExec - Optional hook that runs before each exec, e.g. to
 *   simulate a concurrent edit right before the final replace.
 * @param hostOptions - Optional environment and target user.
 * @returns The connection and the literal `.ssh` paths.
 */
function createLocalHost(
  home: string,
  beforeExec?: (command: string) => void,
  hostOptions: LocalHostOptions = {}
): LocalHost {
  const user = hostOptions.user ?? USER
  async function exec(command: string, execOptions?: ExecOptions): Promise<ExecResult> {
    beforeExec?.(command)
    const result = runShell(command, hostOptions.env, {
      input: hostOptions.stdin,
      userNamespace: hostOptions.userNamespace,
    })
    if (result.code !== 0 && execOptions?.ignoreExitCode !== true) {
      throw new Error(`command failed (${String(result.code)}): ${result.stderr}`)
    }
    return result
  }
  async function output(command: string): Promise<string> {
    if (command === `getent passwd '${user}' | cut -d: -f6`) return home
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
  return command.includes("mv -T -- ")
}

function isDecode(command: string): boolean {
  return command.includes("\ncommand -p base64 -d < ")
}

function isPrepare(command: string): boolean {
  return command.includes("\nchmod 700 .\n")
}

function isStagingMktemp(command: string): boolean {
  return command.includes("\nmktemp -- ")
}

// The relative staging name travels as a quoted positional argument.
const STAGED_NAME_PATTERN = /'(?<name>\.paratix-authorized-keys\.[A-Za-z0-9]+)'/v
const PAYLOAD_DIRECTORY_PATTERN =
  /'(?<path>\/tmp\/paratix-authorized-keys-payload\.[^'\/]+)\/payload\.base64'/v
const STAGED_FILE_REFUSAL =
  "authorized_keys staging file must be a regular single-link file owned by the staging user"
const STAGED_FILE_MODE_REFUSAL = "authorized_keys staging file must have mode 600"

/**
 * Absolute path of the staged file a command names, if any.
 *
 * @param sshDirectory - The `.ssh` directory the staged name lives in.
 * @param command - The remote command.
 * @returns The staged path, or `undefined` when the command names none.
 */
function stagedPathIn(sshDirectory: string, command: string): string | undefined {
  const name = STAGED_NAME_PATTERN.exec(command)?.groups?.name
  return name === undefined ? undefined : join(sshDirectory, name)
}

/**
 * Hook that changes the mode of the staged file right before the final
 * replace runs, as a default ACL or the owner of `~/.ssh` could.
 *
 * @param sshDirectory - The `.ssh` directory that holds the staged file.
 * @param mode - The mode the staged file gets.
 * @returns The `beforeExec` hook.
 */
function chmodStagedBeforeReplace(sshDirectory: string, mode: number): (command: string) => void {
  return (command) => {
    const staged = stagedPathIn(sshDirectory, command)
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
 * @param parameters.sshDirectory - The `.ssh` directory with the staged file.
 * @param parameters.trigger - Selects the command before which the swap happens.
 * @param parameters.victim - The file the swapped entry points to.
 * @returns The `beforeExec` hook.
 */
function swapStagedFile(parameters: {
  kind: StagedSwap
  payloadDirectories: string[]
  sshDirectory: string
  trigger: (command: string) => boolean
  victim: string
}): (command: string) => void {
  const { kind, payloadDirectories, sshDirectory, trigger, victim } = parameters
  return (command) => {
    const payloadDirectory = PAYLOAD_DIRECTORY_PATTERN.exec(command)?.groups?.path
    if (payloadDirectory !== undefined) payloadDirectories.push(payloadDirectory)
    const staged = stagedPathIn(sshDirectory, command)
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
        swapStagedFile({ kind, payloadDirectories, sshDirectory, trigger, victim })
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
    const host = createLocalHost(home, chmodStagedBeforeReplace(sshDirectory, 0o640))

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

type DirectorySnapshot = {
  entries: Array<{ content: string; mode: number; name: string; nlink: number; uid: number }>
  gid: number
  mode: number
  uid: number
}

/**
 * Mode, owner and the files of a directory (one level), to prove that a
 * failed apply left it untouched.
 *
 * @param directory - The directory to record.
 * @returns Its mode, owner and entries.
 */
function snapshotDirectory(directory: string): DirectorySnapshot {
  const stats = statSync(directory)
  return {
    entries: readdirSync(directory)
      .sort()
      .map((name) => {
        const path = join(directory, name)
        const entry = statSync(path)
        return {
          content: entry.isFile() ? readFileSync(path, "latin1") : "",
          mode: entry.mode & 0o7777,
          name,
          nlink: entry.nlink,
          uid: entry.uid,
        }
      }),
    gid: stats.gid,
    mode: stats.mode & 0o7777,
    uid: stats.uid,
  }
}

/**
 * Lay out `<root>/<user>/.ssh/authorized_keys` and a foreign directory
 * `<root>/foreign` (mode 0755, one 0644 file) the owner of the home could
 * point `~/.ssh` at.
 *
 * @returns The paths of the layout.
 */
function makeHomeWithForeignDirectory(): {
  foreign: string
  home: string
  keysPath: string
  root: string
  sshDirectory: string
} {
  const root = makeRoot()
  const home = join(root, USER)
  const sshDirectory = join(home, ".ssh")
  const keysPath = join(sshDirectory, "authorized_keys")
  const foreign = join(root, "foreign")
  mkdirSync(sshDirectory, { mode: 0o700, recursive: true })
  writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
  mkdirSync(foreign, { mode: 0o755 })
  chmodSync(foreign, 0o755)
  writeFileSync(join(foreign, "authorized_keys"), "foreign\n", { mode: 0o644 })
  chmodSync(join(foreign, "authorized_keys"), 0o644)
  return { foreign, home, keysPath, root, sshDirectory }
}

type SshDirectorySwap = "directory" | "symlink"

/**
 * Hook that, once, right before the first command `trigger` selects, moves
 * `~/.ssh` aside and puts a symlink to `foreign` (or a fresh directory) in
 * its place, as the owner of the home could at any moment.
 *
 * @param parameters - Paths, swap kind and trigger.
 * @param parameters.foreign - The symlink target.
 * @param parameters.kind - Whether `~/.ssh` becomes a symlink or a new real directory.
 * @param parameters.sshDirectory - The literal `~/.ssh` path.
 * @param parameters.trigger - Selects the command before which the swap happens.
 * @returns The `beforeExec` hook.
 */
function swapSshDirectory(parameters: {
  foreign: string
  kind: SshDirectorySwap
  sshDirectory: string
  trigger: (command: string) => boolean
}): (command: string) => void {
  const { foreign, kind, sshDirectory, trigger } = parameters
  let swapped = false
  return (command) => {
    if (swapped || !trigger(command)) return
    swapped = true
    if (existsSync(sshDirectory)) renameSync(sshDirectory, `${sshDirectory}-old`)
    if (kind === "symlink") symlinkSync(foreign, sshDirectory)
    else mkdirSync(sshDirectory, { mode: 0o700 })
  }
}

/**
 * Hook that, once, right before the first command `trigger` selects,
 * replaces `authorized_keys` by a symlink or a hard link to `victim`.
 *
 * @param parameters - Paths, link kind and trigger.
 * @param parameters.keysPath - The literal `authorized_keys` path.
 * @param parameters.kind - Whether the entry becomes a symlink or a hard link.
 * @param parameters.trigger - Selects the command before which the swap happens.
 * @param parameters.victim - The outside file the entry points to.
 * @returns The `beforeExec` hook.
 */
function swapAuthorizedKeys(parameters: {
  keysPath: string
  kind: StagedSwap
  trigger: (command: string) => boolean
  victim: string
}): (command: string) => void {
  const { keysPath, kind, trigger, victim } = parameters
  let swapped = false
  return (command) => {
    if (swapped || !trigger(command)) return
    swapped = true
    rmSync(keysPath, { force: true })
    if (kind === "symlink") symlinkSync(victim, keysPath)
    else linkSync(victim, keysPath)
  }
}

const SWAP_STEPS = [
  ["the prepare step", isPrepare],
  ["the staging mktemp", isStagingMktemp],
  ["the decode", isDecode],
  ["the replace", isFinalReplace],
] as const

// `nobody` must exist and differ from the test user for the drop to be needed.
const NOBODY_EXISTS =
  GNU_SHELL_TOOLS && USER !== "nobody" && runShell("id -u nobody >/dev/null").code === 0
// An unprivileged test user cannot switch to `nobody` with `setpriv`.
const SETPRIV_REFUSAL_TESTABLE =
  NOBODY_EXISTS && process.getuid?.() !== 0 && runShell("command -v setpriv >/dev/null").code === 0

describe.skipIf(!GNU_SHELL_TOOLS)("ssh.authorizedKeys on a local shell with a swapped .ssh", () => {
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
  })

  it.each(SWAP_STEPS)(
    "fails when .ssh becomes a symlink to a foreign directory before %s and leaves it untouched",
    async (_label, trigger) => {
      const { foreign, home, keysPath, sshDirectory } = makeHomeWithForeignDirectory()
      const before = snapshotDirectory(foreign)
      const host = createLocalHost(
        home,
        swapSshDirectory({ foreign, kind: "symlink", sshDirectory, trigger })
      )

      const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(".ssh must not be a symlink")
      expect(snapshotDirectory(foreign)).toStrictEqual(before)
      // The moved-aside directory still holds the unchanged original file.
      expect(readFileSync(keysPath.replace("/.ssh/", "/.ssh-old/"), "utf8")).toBe(`${otherLine}\n`)
    }
  )

  it("fails when .ssh is a symlink to a foreign directory before the apply and leaves it untouched", async () => {
    const { foreign, home, sshDirectory } = makeHomeWithForeignDirectory()
    rmSync(sshDirectory, { force: true, recursive: true })
    symlinkSync(foreign, sshDirectory)
    const before = snapshotDirectory(foreign)
    const host = createLocalHost(home)
    const module = ssh.authorizedKeys(USER, key)

    const results = [await dryRun(module, host.connection), await module.apply(host.connection, {})]

    for (const result of results) {
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(".ssh must not be a symlink")
    }
    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(snapshotDirectory(foreign)).toStrictEqual(before)
  })

  it.each([
    ["the decode", isDecode],
    ["the replace", isFinalReplace],
  ] as const)(
    "fails when .ssh is replaced by another real directory before %s",
    async (_label, trigger) => {
      const { foreign, home, sshDirectory } = makeHomeWithForeignDirectory()
      const host = createLocalHost(
        home,
        swapSshDirectory({ foreign, kind: "directory", sshDirectory, trigger })
      )

      const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(".ssh directory changed during rewrite")
      // Nothing is staged, published or cleaned up through the new directory.
      expect(readdirSync(sshDirectory)).toStrictEqual([])
    }
  )

  it("fails without preparing anything when .ssh appears as a symlink after a missing read", async () => {
    const { foreign, home, sshDirectory } = makeHomeWithForeignDirectory()
    rmSync(sshDirectory, { force: true, recursive: true })
    const before = snapshotDirectory(foreign)
    const host = createLocalHost(
      home,
      swapSshDirectory({ foreign, kind: "symlink", sshDirectory, trigger: isPrepare })
    )

    const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(".ssh must not be a symlink")
    expect(snapshotDirectory(foreign)).toStrictEqual(before)
  })

  it.each([
    ["a symlink", "symlink", "authorized_keys must not be a symlink"],
    ["a hard link", "hardlink", "authorized_keys changed during rewrite"],
  ] as const)(
    "never writes through authorized_keys swapped for %s to an outside file before the replace",
    async (_label, kind, message) => {
      const { home, keysPath, root, sshDirectory } = makeHomeWithForeignDirectory()
      const victim = join(root, "victim")
      writeFileSync(victim, "victim\n", { mode: 0o644 })
      chmodSync(victim, 0o644)
      const host = createLocalHost(
        home,
        swapAuthorizedKeys({ keysPath, kind, trigger: isFinalReplace, victim })
      )

      const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(message)
      expect(readFileSync(victim, "utf8")).toBe("victim\n")
      expect(statSync(victim).mode & OCTAL_MODE_MASK).toBe(0o644)
      expect(leftoverStagingFiles(sshDirectory)).toStrictEqual([])
      expect(existsSync(join(sshDirectory, "authorized_keys.paratix-backup"))).toBe(false)
    }
  )

  it("refuses an authorized_keys symlink to an outside file in dry-run and apply", async () => {
    const { home, keysPath, root } = makeHomeWithForeignDirectory()
    const victim = join(root, "victim")
    writeFileSync(victim, `${otherLine}\n`, { mode: 0o644 })
    chmodSync(victim, 0o644)
    rmSync(keysPath)
    symlinkSync(victim, keysPath)
    const host = createLocalHost(home)
    const module = ssh.authorizedKeys(USER, key)

    const results = [await dryRun(module, host.connection), await module.apply(host.connection, {})]

    for (const result of results) {
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("authorized_keys must not be a symlink")
    }
    expect(readFileSync(victim, "utf8")).toBe(`${otherLine}\n`)
    expect(statSync(victim).mode & OCTAL_MODE_MASK).toBe(0o644)
  })

  it.skipIf(!NOBODY_EXISTS)(
    "fails clearly for another target user when neither setpriv nor runuser is on the PATH",
    async () => {
      const root = makeRoot()
      const home = join(root, "nobody-home")
      const bin = join(root, "bin")
      mkdirSync(home)
      mkdirSync(bin)
      // Only `id` is reachable through PATH; `realpath` runs via `command -p`.
      symlinkSync(runShell("command -v id").stdout.trim(), join(bin, "id"))
      const host = createLocalHost(home, undefined, { env: { PATH: bin }, user: "nobody" })
      const module = ssh.authorizedKeys("nobody", key)

      const results = [
        await module.apply(host.connection, {}),
        await dryRun(module, host.connection),
      ]

      for (const result of results) {
        expect(result.status).toBe("failed")
        expect(result.error?.message).toBe(
          `[ssh.authorizedKeys: nobody (present)] ${AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING}`
        )
      }
      expect(readdirSync(home)).toStrictEqual([])
    }
  )

  it.skipIf(!SETPRIV_REFUSAL_TESTABLE)(
    "fails instead of running as the connection user when the privilege drop is refused",
    async () => {
      const root = makeRoot()
      const home = join(root, "nobody-home")
      mkdirSync(home)
      const commands: string[] = []
      const host = createLocalHost(
        home,
        (command) => {
          commands.push(command)
        },
        { user: "nobody" }
      )

      const result = await ssh.authorizedKeys("nobody", key).apply(host.connection, {})

      // An unprivileged connection cannot switch to `nobody`, so the user-side
      // create of the missing `.ssh` fails.
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("failed to prepare .ssh directory")
      expect(commands.some((command) => command.includes("setpriv' --reuid=65534 "))).toBe(true)
      expect(commands.some((command) => command.startsWith("sh -c "))).toBe(false)
      expect(readdirSync(home)).toStrictEqual([])
    }
  )
})

// Only a root shell can create a root-owned `.ssh` and switch to `nobody`.
const ROOT_REPAIR_TESTABLE =
  NOBODY_EXISTS && process.getuid?.() === 0 && runShell("command -v setpriv >/dev/null").code === 0

describe.skipIf(!GNU_SHELL_TOOLS)(
  "ssh.authorizedKeys on a local shell with a foreign-owned .ssh",
  () => {
    afterEach(() => {
      for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
    })

    it.skipIf(!NOBODY_EXISTS)(
      "refuses a .ssh owned by neither the target user nor root without switching users or changing it",
      async () => {
        const root = makeRoot()
        const home = join(root, "nobody-home")
        const sshDirectory = join(home, ".ssh")
        mkdirSync(sshDirectory, { mode: 0o755, recursive: true })
        chmodSync(sshDirectory, 0o755)
        writeFileSync(join(sshDirectory, "authorized_keys"), `${otherLine}\n`, { mode: 0o644 })
        chmodSync(join(sshDirectory, "authorized_keys"), 0o644)
        const before = snapshotDirectory(sshDirectory)
        const host = createLocalHost(home, undefined, { user: "nobody" })
        const module = ssh.authorizedKeys("nobody", key)

        const results = [
          await dryRun(module, host.connection),
          await module.apply(host.connection, {}),
        ]

        for (const result of results) {
          expect(result.status).toBe("failed")
          // The root-side inspection refuses it; an attempted drop to `nobody`
          // would fail with a `setpriv:` error in this unprivileged shell instead.
          expect(result.error?.message).toContain(".ssh must be owned by the target user or root")
          expect(result.error?.message).not.toContain("setpriv:")
        }
        expect(snapshotDirectory(sshDirectory)).toStrictEqual(before)
      }
    )

    it.skipIf(!ROOT_REPAIR_TESTABLE)(
      "repairs a root-owned .ssh and authorized_keys for the target user",
      async () => {
        const root = makeRoot()
        chmodSync(root, 0o755)
        const home = join(root, "nobody-home")
        const sshDirectory = join(home, ".ssh")
        const keysPath = join(sshDirectory, "authorized_keys")
        mkdirSync(home, { mode: 0o755 })
        runShell(`chown 65534 '${home}'`)
        mkdirSync(sshDirectory, { mode: 0o700 })
        writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
        const host = createLocalHost(home, undefined, { user: "nobody" })
        const module = ssh.authorizedKeys("nobody", key)

        await expect(module.apply(host.connection, {})).resolves.toStrictEqual({
          status: "changed",
        })

        expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n${key}\n`)
        expect(statSync(sshDirectory).uid).toBe(65_534)
        expect(statSync(sshDirectory).mode & OCTAL_MODE_MASK).toBe(0o700)
        expect(statSync(keysPath).uid).toBe(65_534)
        expect(statSync(keysPath).mode & OCTAL_MODE_MASK).toBe(OWNER_ONLY_FILE_MODE)
        await expect(module.check(host.connection, {})).resolves.toBe("ok")
      }
    )
  }
)

/**
 * A `PATH` whose `stat` reports the test user's uid as 0 for
 * `./authorized_keys`, so the user-side owner check of the read sees a
 * root-owned `authorized_keys` in the user's own `.ssh`. Root-side tools run
 * through `command -p` and never see the shim.
 *
 * @param root - Directory for the shim.
 * @returns The environment for `createLocalHost`.
 */
function rootOwnedKeysEnvironment(root: string): NodeJS.ProcessEnv {
  const bin = join(root, "shim-bin")
  mkdirSync(bin)
  const uid = String(process.getuid?.() ?? -1)
  const realStat = runShell("command -v stat").stdout.trim()
  writeFileSync(
    join(bin, "stat"),
    `#!/bin/sh
for last; do :; done
out=$('${realStat}' "$@") || exit $?
case "$last" in
  ./authorized_keys) printf '%s\\n' "$out" | sed -e 's/^${uid}$/0/' -e 's/^${uid} /0 /' ;;
  *) printf '%s\\n' "$out" ;;
esac
`,
    { mode: 0o755 }
  )
  return { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` }
}

// Root ignores file modes, so an unreadable file only fails for other users.
const RUNS_AS_ROOT = process.getuid?.() === 0
// `unshare -r` maps the test user to root in a user namespace, so files the
// test creates are root-owned for the commands and `nobody` is another user.
const USER_NAMESPACE_AVAILABLE =
  NOBODY_EXISTS && !RUNS_AS_ROOT && runShell("unshare -r true").code === 0

/**
 * Lay out a home for `nobody` whose `.ssh` holds `authorized_keys`; inside
 * the user namespace every entry is owned by root.
 *
 * @param mode - Permission bits for `.ssh`, for example 0o2775.
 * @returns The home, `.ssh` and `authorized_keys` paths and the temporary root.
 */
function makeRootOwnedSshDirectory(mode: number): {
  home: string
  keysPath: string
  root: string
  sshDirectory: string
} {
  const root = makeRoot()
  const home = join(root, "nobody-home")
  const sshDirectory = join(home, ".ssh")
  const keysPath = join(sshDirectory, "authorized_keys")
  mkdirSync(sshDirectory, { recursive: true })
  chmodSync(sshDirectory, mode)
  writeFileSync(keysPath, `${otherLine}\n`, { mode: OWNER_ONLY_FILE_MODE })
  return { home, keysPath, root, sshDirectory }
}

// Shown in the test names, so a run without user namespaces (for example on a
// CI runner that restricts them) says why the refusal cases did not run; the
// Docker suite covers the same refusals against a real root.
const USER_NAMESPACE_NOTE = USER_NAMESPACE_AVAILABLE
  ? ""
  : " (skipped: `unshare -r` is not permitted here; see the sshd.match Docker suite)"

describe.skipIf(!GNU_SHELL_TOOLS)(
  "ssh.authorizedKeys on a local shell with a root-owned .ssh",
  () => {
    afterEach(() => {
      for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
    })

    it.skipIf(!USER_NAMESPACE_AVAILABLE).each([
      {
        extra: [],
        label: "writable by its group",
        message: "a root-owned .ssh must not be writable by group or others",
        mode: 0o2775,
      },
      {
        extra: [],
        label: "writable by others",
        message: "a root-owned .ssh must not be writable by group or others",
        mode: 0o757,
      },
      {
        extra: ["cache"],
        label: "holding another entry",
        message: "a root-owned .ssh may only contain authorized_keys and known_hosts",
        mode: 0o755,
      },
    ] as const)(
      `refuses a root-owned .ssh $label in dry-run and apply and changes nothing${USER_NAMESPACE_NOTE}`,
      async ({ extra, message, mode }) => {
        const { home, sshDirectory } = makeRootOwnedSshDirectory(mode)
        for (const name of extra) writeFileSync(join(sshDirectory, name), "x\n")
        const before = snapshotDirectory(sshDirectory)
        const host = createLocalHost(home, undefined, { user: "nobody", userNamespace: true })
        const module = ssh.authorizedKeys("nobody", key)

        const results = [
          await dryRun(module, host.connection),
          await module.apply(host.connection, {}),
        ]

        for (const result of results) {
          expect(result.status).toBe("failed")
          expect(result.error?.message).toContain(message)
        }
        await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
        expect(snapshotDirectory(sshDirectory)).toStrictEqual(before)
      }
    )

    it.skipIf(!USER_NAMESPACE_AVAILABLE)(
      `refuses a root-owned .ssh whose authorized_keys has a second hard link${USER_NAMESPACE_NOTE}`,
      async () => {
        const { home, keysPath, root, sshDirectory } = makeRootOwnedSshDirectory(0o755)
        linkSync(keysPath, join(root, "second-link"))
        const before = snapshotDirectory(sshDirectory)
        const host = createLocalHost(home, undefined, { user: "nobody", userNamespace: true })

        const result = await ssh.authorizedKeys("nobody", key).apply(host.connection, {})

        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain(
          "authorized_keys in a root-owned .ssh must be a root-owned single-link regular file"
        )
        expect(snapshotDirectory(sshDirectory)).toStrictEqual(before)
      }
    )

    it.skipIf(!USER_NAMESPACE_AVAILABLE)(
      `reads a protected root-owned .ssh as root after the inspection${USER_NAMESPACE_NOTE}`,
      async () => {
        const { home } = makeRootOwnedSshDirectory(0o700)
        const host = createLocalHost(home, undefined, { user: "nobody", userNamespace: true })

        // The root branch reads the file, so the plan sees the existing line and
        // reports the needed change instead of a read failure.
        await expect(
          dryRun(ssh.authorizedKeys("nobody", key), host.connection)
        ).resolves.toStrictEqual({ status: "changed" })
        await expect(
          dryRun(ssh.authorizedKeys("nobody", otherLine, { state: "absent" }), host.connection)
        ).resolves.toStrictEqual({ status: "changed" })
      }
    )

    it("refuses a root-owned authorized_keys in a user-owned .ssh with an explicit message", async () => {
      const { home, keysPath, root } = makeHomeWithForeignDirectory()
      const host = createLocalHost(home, undefined, { env: rootOwnedKeysEnvironment(root) })
      const module = ssh.authorizedKeys(USER, key)

      const results = [
        await dryRun(module, host.connection),
        await module.apply(host.connection, {}),
      ]

      for (const result of results) {
        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain(
          "authorized_keys must be owned by the target user; chown it manually"
        )
      }
      expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n`)
    })

    it.skipIf(RUNS_AS_ROOT)(
      "keeps the dd error when the user cannot read authorized_keys",
      async () => {
        const { home, keysPath } = makeHomeWithForeignDirectory()
        chmodSync(keysPath, 0o000)
        const host = createLocalHost(home)

        const result = await ssh.authorizedKeys(USER, key).apply(host.connection, {})

        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain(
          "failed to read authorized_keys without following symlinks"
        )
        expect(result.error?.message).toContain("Permission denied")
      }
    )
  }
)

/**
 * The named descriptor targets one line of the probe output reports.
 *
 * @param pattern - A pattern with `stdin`, `stdout` and/or `stderr` groups.
 * @param text - The probe output.
 * @returns The matched groups; throws when the line is missing.
 */
function descriptorLine(pattern: RegExp, text: string): Record<string, string> {
  const groups = pattern.exec(text)?.groups
  if (groups === undefined) throw new Error(`no line matches ${String(pattern)} in ${text}`)
  return groups
}

describe.skipIf(!GNU_SHELL_TOOLS)("ssh.authorizedKeys privilege drop descriptors", () => {
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
  })

  const account: AuthorizedKeysAccount = {
    dropPrefix: "",
    expectedSshDirectory: null,
    gid: String(process.getgid?.() ?? 0),
    uid: String(process.getuid?.() ?? 0),
    user: USER,
  }
  // Prints what the dropped script holds on fds 0 to 2, which of fds 3 to 9
  // are open, what it reads, then exits 7.
  const probe = `printf 'inner %s %s %s\\n' "$(readlink /proc/$$/fd/0)" "$(readlink /proc/$$/fd/1)" "$(readlink /proc/$$/fd/2)"
for fd in 3 4 5 6 7 8 9; do
  if [ -e /proc/$$/fd/$fd ]; then printf 'open fd %s\\n' "$fd"; fi
done
printf 'read [%s]\\n' "$(cat)"
echo 'to stderr' >&2
exit 7`
  const outer = `printf 'outer %s %s\\n' "$(readlink /proc/$$/fd/1)" "$(readlink /proc/$$/fd/2)"`

  it("gives a dropped step /dev/null as stdin and its own output pipes, and keeps its exit status", () => {
    // Root holds extra descriptors 6 to 9, like a caller's shell could.
    const result = runShell(
      `exec 6</dev/null 7</dev/null 8</dev/null 9</dev/null; printf 'SECRET\\n' | { ${outer}; ${asAuthorizedKeysUser(account, probe, [])}; }`
    )

    expect(result.code).toBe(7)
    expect(result.stdout).not.toContain("SECRET")
    expect(result.stdout).not.toContain("open fd")
    expect(result.stdout).toContain("read []")
    expect(result.stderr).toBe("to stderr\n")
    const { stderr: outerStderr, stdout: outerStdout } = descriptorLine(
      /^outer (?<stdout>\S+) (?<stderr>\S+)$/mv,
      result.stdout
    )
    const {
      stderr: innerStderr,
      stdin: input,
      stdout: innerStdout,
    } = descriptorLine(/^inner (?<stdin>\S+) (?<stdout>\S+) (?<stderr>\S+)$/mv, result.stdout)
    expect(input).toBe("/dev/null")
    expect(innerStdout).toMatch(/^pipe:/v)
    expect(innerStderr).toMatch(/^pipe:/v)
    expect(innerStdout).not.toBe(outerStdout)
    expect(innerStderr).not.toBe(outerStderr)
  })

  // `set -e` stops the outer script after a failing step, like the module's scripts.
  it.each([
    { label: "exits 7", last: "exit 7", status: 7, stdout: "" },
    { label: "fails a command", last: "false", status: 1, stdout: "" },
    { label: "succeeds", last: "true", status: 0, stdout: "after\n" },
  ] as const)(
    "keeps the exact status under set -e when the dropped step $label, without extra stderr",
    ({ last, status, stdout }) => {
      const script = `echo 'to stderr' >&2\n${last}`
      const result = runShell(`set -e\n${asAuthorizedKeysUser(account, script, [])}\necho after`)

      expect(result.code).toBe(status)
      expect(result.stderr).toBe("to stderr\n")
      expect(result.stdout).toBe(stdout)
    }
  )

  it("passes only the connected pipe to the stage step, never the outer stdin", () => {
    const result = runShell(
      `printf 'SECRET\\n' | { exec </dev/null; printf 'payload' | { ${asAuthorizedKeysUserReadingPipe(account, probe, [])}; }; }`
    )

    expect(result.code).toBe(7)
    expect(result.stdout).toContain("read [payload]")
    expect(result.stdout).not.toContain("SECRET")
  })

  it("runs a full apply with a secret on the outer stdin without any step reading it", async () => {
    const { home, keysPath } = makeHomeWithForeignDirectory()
    const host = createLocalHost(home, undefined, { stdin: "SECRET\n" })

    await expect(ssh.authorizedKeys(USER, key).apply(host.connection, {})).resolves.toStrictEqual({
      status: "changed",
    })
    expect(readFileSync(keysPath, "utf8")).toBe(`${otherLine}\n${key}\n`)
  })
})
