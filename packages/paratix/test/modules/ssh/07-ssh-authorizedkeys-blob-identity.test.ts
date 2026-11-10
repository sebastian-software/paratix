/* eslint-disable @typescript-eslint/require-await -- async interface methods of the stateful fake host */
/* oxlint-disable jsdoc/require-param, jsdoc/require-returns -- doc comment describes the fake host helper, not a public API */
import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import type { Module, ModuleResult, SshConnection } from "../../../src/types.js"

import { ssh } from "../../../src/modules/ssh.js"
import {
  AUTHORIZED_KEYS_OWNER_REFUSAL,
  AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING,
  type AuthorizedKeysAccount,
  authorizedKeysAccountCommand,
  enterSshDirectoryLines,
  enterVerifiedSshDirectoryLines,
  ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL,
  ROOT_OWNED_SSH_DIRECTORY_ENTRIES_REFUSAL,
  ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL,
  rootInspectSshDirectoryLines,
} from "../../../src/modules/sshAuthorizedKeysAccount.js"
import {
  authorizedKeysReadCommand,
  authorizedKeysStagedFileGuard,
  authorizedKeysStagedFileModeGuard,
  authorizedKeysStagingPayloadPath,
} from "../../../src/modules/sshAuthorizedKeysFile.js"
import {
  authorizedKeysCleanupCommand,
  authorizedKeysMktempCommand,
  authorizedKeysPrepareCommand,
  type VerifiedSshDirectory,
} from "../../../src/modules/sshAuthorizedKeysReplace.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

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
const renamedKey = `ssh-ed25519 ${blob} renamed-key`
const otherLine = `ssh-ed25519 ${ed25519Blob(2)} other-key`
const optionedOther = `restrict,command="/bin/true" ssh-ed25519 ${ed25519Blob(3)} third`
const KEYS = "/home/alice/.ssh/authorized_keys"
const SSH_DIRECTORY = "/home/alice/.ssh"
// `/home` is a symlink to `/data/home` on this fake host, so the canonical
// `.ssh` path resolved by the account probe differs from the literal one.
const CANONICAL_SSH_DIRECTORY = "/data/home/alice/.ssh"
const STAGED_NAME = ".paratix-authorized-keys.AbCdEf"
// `device:inode owner` of the prepared `~/.ssh`, as the prepare step prints it.
const IDENTITY = "2049:4711 1000"
// The base64 payload goes into a private directory outside the user's `~/.ssh`.
const PAYLOAD_DIRECTORY = "/tmp/paratix-authorized-keys-payload.QrStUv"
const PAYLOAD_MKTEMP = "mktemp -d -p /tmp -- 'paratix-authorized-keys-payload.XXXXXX'"
const STAGED_FILE_REFUSAL =
  "authorized_keys staging file must be a regular single-link file owned by the staging user"
// A default ACL on `~/.ssh` overrides the umask, so the staged mode is confirmed before publishing.
const STAGED_MODE_REFUSAL =
  "authorized_keys staging file must have mode 600; a default ACL on ~/.ssh may override the umask"

type Drop = "missing" | "none" | "runuser" | "setpriv"
type RootOwnedKind = "extra-entry" | "linked-keys" | "protected" | "writable"

// What the inspection or the user-side read prints for each refused state.
const READ_REFUSALS: Record<"user-keys" | Exclude<RootOwnedKind, "protected">, string> = {
  "extra-entry": ROOT_OWNED_SSH_DIRECTORY_ENTRIES_REFUSAL,
  "linked-keys": ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL,
  "user-keys": AUTHORIZED_KEYS_OWNER_REFUSAL,
  writable: ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL,
}
type Step = "decode" | "mktemp" | "prepare" | "replace"

const DROP_PREFIXES: Record<Drop, string> = {
  missing: "",
  none: "",
  runuser: "'/usr/sbin/runuser' -u 'alice' -- ",
  setpriv: "'/usr/bin/setpriv' --reuid=1000 --regid=1000 --init-groups -- ",
}
// What every root-side command that launches a drop starts with.
const ROOT_PROLOGUE = "exec </dev/null\ncd /\n"
// Absolute tool paths the account probe prints for each drop.
const DROP_TOOLS: Record<Drop, string> = {
  missing: "",
  none: "",
  runuser: "/usr/sbin/runuser",
  setpriv: "/usr/bin/setpriv",
}
// Descriptor handling and output pipes every dropped step carries (see `asAuthorizedKeysUser`).
const DROP_OUTPUT_TAIL = ` 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; then echo 0 >&3; else echo "$?" >&3; fi | command -p cat >&4; } 2>&1 | command -p cat >&5; } 3>&1); } 4>&1 5>&2; (exit "\${paratix_status:-1}")`

type Host = {
  account: AuthorizedKeysAccount
  cleanups: () => number
  commands: () => string[]
  connection: SshConnection
  content: () => null | string
  foreignTouched: () => boolean
  prepares: () => number
  rawContent: () => Buffer | null
  repairs: () => number
  replaces: () => number
}

type HostOptions = {
  /** Called right before the final replace runs, e.g. to simulate a concurrent edit. */
  beforeReplace?: (content: null | string) => null | string
  /** Privilege-drop tool the account probe reports. */
  drop?: Drop
  /** Whether the decode script reports a failure. */
  failDecode?: boolean
  /** Raw stdout of the payload directory `mktemp -d`. */
  payloadMktempOutput?: string
  /** Raw stdout of the prepare step (the directory identity). */
  prepareOutput?: string
  /** Whether `authorized_keys` in the user's `~/.ssh` is owned by root, as after `sudo tee -a`. */
  rootOwnedAuthorizedKeys?: boolean
  /** A root-owned `~/.ssh`, as after an earlier root bootstrap, and what is wrong with it. */
  rootOwnedSshDirectory?: RootOwnedKind
  /** Raw stdout of the staging `mktemp`. */
  stagingMktempOutput?: string
  /** The owner replaces `~/.ssh` by a symlink to a foreign directory right before this step. */
  swapBefore?: Step
  /** Whether `~/.ssh` is a symlink from the start. */
  symlinkedSshDirectory?: boolean
}

// Latin-1 view of UTF-8 text, as the module reads and compares file content.
function bytes(text: string): string {
  return Buffer.from(text, "utf8").toString("latin1")
}

// The digest the module embeds for content followed by the read status suffix.
function checkedDigest(content: string): string {
  return createHash("sha256")
    .update(Buffer.from(`${content}\n0`, "latin1"))
    .digest("hex")
}

function initialLatin1(initial: Buffer | null | string): null | string {
  if (initial === null) return null
  return typeof initial === "string" ? bytes(initial) : initial.toString("latin1")
}

/**
 * Text of `fragment` as it appears inside a single-quoted `sh -c` script.
 *
 * @param fragment - Script text.
 * @returns The fragment with every `'` escaped like `shellQuote` does.
 */
function quotedFragment(fragment: string): string {
  return fragment.replaceAll("'", String.raw`'\''`)
}

function accountFor(drop: Drop): AuthorizedKeysAccount {
  return {
    dropPrefix: DROP_PREFIXES[drop],
    expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
    gid: "1000",
    uid: "1000",
    user: "alice",
  }
}

function verifiedFor(host: Host): VerifiedSshDirectory {
  return {
    account: host.account,
    expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
    identity: IDENTITY,
  }
}

type FakeResult = { code: number; stderr: string; stdout: string }

/**
 * The refusal the read prints for the host's ownership state, if any.
 *
 * @param options - The host options.
 * @returns The key into {@link READ_REFUSALS}, or `undefined` when the read succeeds.
 */
function readRefusalFor(options: HostOptions): keyof typeof READ_REFUSALS | undefined {
  if (options.rootOwnedAuthorizedKeys === true) return "user-keys"
  const kind = options.rootOwnedSshDirectory
  if (kind === undefined || kind === "protected") return undefined
  return kind
}

const OK: FakeResult = { code: 0, stderr: "", stdout: "" }
const SYMLINK_REFUSAL: FakeResult = { code: 1, stderr: ".ssh must not be a symlink", stdout: "" }
const PAYLOAD_PATH = authorizedKeysStagingPayloadPath(PAYLOAD_DIRECTORY)
const ACCOUNT_COMMAND = authorizedKeysAccountCommand({ home: "/home/alice", user: "alice" })
const STEP_ORDER: readonly Step[] = ["prepare", "mktemp", "decode", "replace"]

/** File state of the fake host and the handlers of its remote scripts. */
class FakeAuthorizedKeysFile {
  public readonly account: AuthorizedKeysAccount
  public cleanups = 0
  public commands: string[] = []
  public content: null | string
  // Set when a step would act on the foreign directory behind a swapped `~/.ssh`.
  public foreignTouched = false
  public payload = ""
  public prepares = 0
  public repairs = 0
  public replaces = 0
  public staged = ""
  private readonly drop: Drop
  private readonly refusal: keyof typeof READ_REFUSALS | undefined
  private rootOwned: boolean
  private swapped: boolean
  private readonly verified: VerifiedSshDirectory

  public constructor(
    initial: null | string,
    private readonly options: HostOptions
  ) {
    this.content = initial
    this.drop = options.drop ?? "setpriv"
    this.account = accountFor(this.drop)
    this.rootOwned = options.rootOwnedSshDirectory === "protected"
    this.refusal = readRefusalFor(options)
    this.swapped = options.symlinkedSshDirectory === true
    this.verified = {
      account: this.account,
      expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
      identity: IDENTITY,
    }
  }

  public exec(command: string): FakeResult {
    this.commands.push(command)
    const exact = this.exactHandlers().get(command)
    if (exact !== undefined) return exact(command)
    if (command.startsWith(`set -e\nexec </dev/null\ncd /\n[ ! -L '${PAYLOAD_PATH}' ]`)) {
      return this.decode(command)
    }
    if (command.startsWith(`${ROOT_PROLOGUE}{ paratix_status=`) && command.includes("mv -T -- ")) {
      return this.replace(command)
    }
    throw new Error(`unexpected exec: ${command}`)
  }

  private cleanup(command: string): FakeResult {
    if (this.refusedAfterSwap(command)) return SYMLINK_REFUSAL
    this.cleanups += 1
    return OK
  }

  // Decodes the payload; succeeds only when the command carries the digest of the decoded bytes.
  private decode(command: string): FakeResult {
    if (this.options.failDecode === true) {
      return { code: 1, stderr: "base64: invalid input", stdout: "" }
    }
    this.swapIfDue("decode")
    const pipe = `command -p base64 -d < '${PAYLOAD_PATH}' | { { paratix_status=$({ { if ${this.account.dropPrefix}/bin/sh -c `
    if (!command.includes(pipe)) {
      throw new Error(`decode does not pipe into the target user's shell: ${command}`)
    }
    if (this.refusedAfterSwap(command)) return SYMLINK_REFUSAL
    this.staged = Buffer.from(this.payload, "base64").toString("latin1")
    const args = `'${CANONICAL_SSH_DIRECTORY}' '${IDENTITY}' '${STAGED_NAME}' '${checkedDigest(this.staged)}'`
    return command.includes(`${args} 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;`)
      ? OK
      : { code: 1, stderr: "authorized_keys staging file does not match", stdout: "" }
  }

  // Handlers of the commands the module renders exactly, keyed by command.
  private exactHandlers(): Map<string, (command: string) => FakeResult> {
    const read = authorizedKeysReadCommand({
      ...this.account,
      expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
    })
    return new Map<string, (command: string) => FakeResult>([
      ["id -gn 'alice'", () => ({ ...OK, stdout: "alice\n" })],
      [`rm -rf -- '${PAYLOAD_DIRECTORY}'`, () => OK],
      [
        ACCOUNT_COMMAND,
        () => ({
          ...OK,
          stdout: `${this.drop} 1000 1000\n/data/home/alice\n${DROP_TOOLS[this.drop]}\n`,
        }),
      ],
      [authorizedKeysCleanupCommand(this.verified, STAGED_NAME), (c) => this.cleanup(c)],
      [authorizedKeysMktempCommand(this.verified), (c) => this.mktemp(c)],
      [authorizedKeysPrepareCommand(this.verified), (c) => this.prepare(c)],
      [
        PAYLOAD_MKTEMP,
        () => ({ ...OK, stdout: `${this.options.payloadMktempOutput ?? PAYLOAD_DIRECTORY}\n` }),
      ],
      [read, (c) => this.read(c)],
    ])
  }

  private mktemp(command: string): FakeResult {
    this.swapIfDue("mktemp")
    if (this.refusedAfterSwap(command)) return SYMLINK_REFUSAL
    return { ...OK, stdout: this.options.stagingMktempOutput ?? `${STAGED_NAME}\n` }
  }

  private prepare(command: string): FakeResult {
    this.swapIfDue("prepare")
    // Root enters and checks an existing `.ssh` before anything else; the
    // user-side part acts on `.` only after its own `cd -P` and `pwd -P` check.
    const rootChecks = rootInspectSshDirectoryLines(this.account, CANONICAL_SSH_DIRECTORY)
    if (this.swapped) {
      if (command.includes(rootChecks)) return SYMLINK_REFUSAL
      this.foreignTouched = true
    }
    if (this.rootOwned) {
      if (!command.includes(rootChecks)) throw new Error(`unchecked root repair: ${command}`)
      this.rootOwned = false
      this.repairs += 1
    }
    this.prepares += 1
    return { ...OK, stdout: this.options.prepareOutput ?? `${IDENTITY}\n` }
  }

  private read(command: string): FakeResult {
    if (this.swapped) return SYMLINK_REFUSAL
    if (this.refusal !== undefined) {
      // The real script refuses the state; the fake insists that the check exists.
      const message = READ_REFUSALS[this.refusal]
      if (!command.includes(message)) throw new Error(`read lacks the check for ${message}`)
      return { code: 1, stderr: message, stdout: "" }
    }
    if (this.content === null) return { ...OK, stdout: "missing\n" }
    const encoded = Buffer.from(`${this.content}\n0`, "latin1").toString("base64")
    return { ...OK, stdout: `present\n${encoded}` }
  }

  /**
   * Whether a step refuses the swapped directory; a step without the
   * verification lines would act on the foreign directory instead.
   */
  private refusedAfterSwap(command: string): boolean {
    if (!this.swapped) return false
    if (command.includes(quotedFragment(enterVerifiedSshDirectoryLines()))) return true
    this.foreignTouched = true
    return false
  }

  // Replaces only when the command's live-file comparison matches the current
  // content and its post-replace check expects the digest of the staged bytes.
  private replace(command: string): FakeResult {
    this.swapIfDue("replace")
    if (this.refusedAfterSwap(command)) return SYMLINK_REFUSAL
    // The replace addresses the canonical `.ssh`, the identity and the staged name as arguments.
    const prefix = ` sh '${CANONICAL_SSH_DIRECTORY}' '${IDENTITY}' '${STAGED_NAME}' `
    if (!command.includes(prefix)) {
      throw new Error(`replace does not use the verified directory: ${command}`)
    }
    this.content = this.options.beforeReplace?.(this.content) ?? this.content
    const original = this.content === null ? "missing" : checkedDigest(this.content)
    if (!command.includes(`${prefix}'${original}' `)) {
      return { code: 1, stderr: "authorized_keys changed during rewrite", stdout: "" }
    }
    if (!command.includes(` '${checkedDigest(this.staged)}' '700 alice alice directory' `)) {
      return { code: 1, stderr: "authorized_keys content changed during replace", stdout: "" }
    }
    this.content = this.staged
    this.replaces += 1
    return OK
  }

  private swapIfDue(step: Step): void {
    const swapBefore = this.options.swapBefore
    if (swapBefore === undefined) return
    if (STEP_ORDER.indexOf(step) >= STEP_ORDER.indexOf(swapBefore)) this.swapped = true
  }
}

/**
 * Stateful host: account probe, reads, base64 staging, decode verification,
 * the atomic replace with its live-file comparison, and the ownership probes
 * of one authorized_keys file. The decode and replace scripts only succeed
 * when the digests they carry match the fake file state, so a wrong
 * expectation fails like it would on a real host. A swapped `~/.ssh` is
 * refused only by a step that carries the `cd -P`/`pwd -P` verification.
 */
function createHost(initial: Buffer | null | string, options: HostOptions = {}): Host {
  const state = new FakeAuthorizedKeysFile(initialLatin1(initial), options)
  const base = createMockSsh({}, { strict: false })
  const connection: SshConnection = {
    ...base,
    async exec(command) {
      return state.exec(command)
    },
    async exists(path) {
      return path === SSH_DIRECTORY || (path === KEYS && state.content !== null)
    },
    async output(command) {
      if (command === "getent passwd 'alice' | cut -d: -f6") return "/home/alice"
      if (command === `stat -c '%a %U %G %F' '${SSH_DIRECTORY}'`) return "700 alice alice directory"
      if (command === `stat -c '%a %U %G %F' '${KEYS}'`) return "600 alice alice regular file"
      throw new Error(`unexpected output: ${command}`)
    },
    async test(command) {
      if (command === `[ -e '${KEYS}' ] || [ -L '${KEYS}' ]`) return state.content !== null
      if (command === `[ -L '${SSH_DIRECTORY}' ]`) return options.symlinkedSshDirectory === true
      return false
    },
    async writeFile(path, content) {
      // The payload is written into the private directory, never into `~/.ssh`.
      expect(path).toBe(PAYLOAD_PATH)
      state.payload = content
    },
  }
  return {
    account: state.account,
    cleanups: () => state.cleanups,
    commands: () => state.commands,
    connection,
    content: () =>
      state.content === null ? null : Buffer.from(state.content, "latin1").toString("utf8"),
    foreignTouched: () => state.foreignTouched,
    prepares: () => state.prepares,
    rawContent: () => (state.content === null ? null : Buffer.from(state.content, "latin1")),
    repairs: () => state.repairs,
    replaces: () => state.replaces,
  }
}

/**
 * The first recorded command that contains `marker`.
 *
 * @param commands - The recorded commands.
 * @param marker - Text the command must contain.
 * @returns The command; throws when none matches.
 */
function commandWith(commands: readonly string[], marker: string): string {
  const command = commands.find((candidate) => candidate.includes(marker))
  if (command === undefined) throw new Error(`no command contains ${marker}`)
  return command
}

/**
 * Commands whose privilege drops do not all read `/dev/null` (the stage step:
 * its payload pipe), close root's fds 3 to 5 and write into root-held pipes,
 * or whose root script does not replace its own stdin before the first drop.
 *
 * @param commands - The recorded commands.
 * @param prefix - The drop prefix the account uses.
 * @returns The violating commands; empty when all comply.
 */
function dropDescriptorViolations(commands: readonly string[], prefix: string): string[] {
  const violations: string[] = []
  for (const command of commands) {
    const drops = command.split(`${prefix}/bin/sh -c '`).length - 1
    const tails = command.split(DROP_OUTPUT_TAIL).length - 1
    const fromPipe = command.includes("command -p base64 -d < ") ? 1 : 0
    const nullInputs = command.split(` </dev/null${DROP_OUTPUT_TAIL}`).length - 1
    const standalone = command.startsWith(`${ROOT_PROLOGUE}{ paratix_status=`)
    const rootScript = command.startsWith(`set -e\n${ROOT_PROLOGUE}`)
    const unwrapped = tails !== drops || nullInputs !== drops - fromPipe
    if (unwrapped || (drops > 0 && !standalone && !rootScript)) violations.push(command)
  }
  return violations
}

async function statusOf(run: Promise<ModuleResult>): Promise<string> {
  const result = await run
  return result.status
}

async function dryRun(module: Module, connection: SshConnection): Promise<ModuleResult> {
  const result = await module._applyDryRun?.(connection, {})
  if (result === undefined) throw new Error("module has no dry-run")
  return result
}

describe("ssh.authorizedKeys idempotency", () => {
  it.each([
    ["without options", undefined],
    ["with options", { options: { command: "/bin/true", restrict: true } }],
  ])("reports ok on a second apply, check and dry-run %s", async (_label, options) => {
    const host = createHost(`${otherLine}\n`)
    const module = ssh.authorizedKeys("alice", key, options)

    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(await statusOf(dryRun(module, host.connection))).toBe("changed")
    expect(await statusOf(module.apply(host.connection, {}))).toBe("changed")
    expect(host.replaces()).toBe(1)

    await expect(module.check(host.connection, {})).resolves.toBe("ok")
    await expect(dryRun(module, host.connection)).resolves.toStrictEqual({ status: "ok" })
    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "ok" })
    expect(host.replaces()).toBe(1)
    expect(
      host
        .content()
        ?.split("\n")
        .filter((line) => line.includes(blob))
    ).toHaveLength(1)
  })
})

describe("ssh.authorizedKeys dry-run", () => {
  it("resolves the primary group only for converged content", async () => {
    const pending = createHost(`${otherLine}\n`)
    const converged = createHost(`${otherLine}\n${key}\n`)
    const module = ssh.authorizedKeys("alice", key)

    await expect(dryRun(module, pending.connection)).resolves.toStrictEqual({ status: "changed" })
    await expect(dryRun(module, converged.connection)).resolves.toStrictEqual({ status: "ok" })

    expect(pending.commands()).not.toContain("id -gn 'alice'")
    expect(converged.commands()).toContain("id -gn 'alice'")
  })
})

describe("ssh.authorizedKeys construction", () => {
  it.each([
    ["an unknown option field", { certAuthority: true }, "unsupported option"],
    ["a newline in a value", { command: "a\nb" }, "must not contain newlines"],
    ["a control character", { environment: { A: "x\u0001" } }, "control characters"],
    ["a value ending in a backslash", { command: "run\\" }, "must not end with a backslash"],
    ["a comma in a list element", { permitOpen: ["a:1,b:2"] }, "commas or whitespace"],
    ["whitespace in a list element", { from: ["a b"] }, "commas or whitespace"],
    ["an invalid environment key", { environment: { "1A": "x" } }, "must match"],
    ["an invalid expiry time", { expiryTime: "2026-12-31" }, "expiryTime must be a valid time"],
    ["contradictory options", { noPty: true, pty: true }, "contradict"],
    ["an empty command", { command: "" }, "command must be a non-empty string"],
  ])("rejects %s", (_label, options, message) => {
    expect(() => ssh.authorizedKeys("alice", key, { options } as never)).toThrow(message)
  })

  it.each([
    ["a key option at the top level", { restrict: true }, '"restrict"'],
    ["a misspelled setting", { option: { restrict: true } }, '"option"'],
  ])("rejects %s of the settings bag", (_label, settings, name) => {
    expect(() => ssh.authorizedKeys("alice", key, settings as never)).toThrow(
      `ssh.authorizedKeys: unsupported setting ${name}`
    )
  })

  it.each([
    ["a string", "absent"],
    ["null", null],
    ["an array", [{ state: "absent" }]],
    ["a boolean", true],
    ["a class instance", new Map([["state", "absent"]])],
  ])("rejects %s as the settings argument", (_label, settings) => {
    expect(() => ssh.authorizedKeys("alice", key, settings as never)).toThrow(
      "ssh.authorizedKeys: settings must be a plain object"
    )
  })

  it("accepts an omitted settings argument and a null-prototype settings object", () => {
    const settings = Object.assign(Object.create(null) as object, { state: "absent" })

    expect(() => ssh.authorizedKeys("alice", key)).not.toThrow()
    expect(() => ssh.authorizedKeys("alice", key, settings as never)).not.toThrow()
  })
})

describe("ssh.authorizedKeys blob identity", () => {
  it("replaces the same-blob line in place when the options change and removes later duplicates", async () => {
    const host = createHost(
      `${otherLine}\n${key}\n${optionedOther}\nrestrict ssh-ed25519 ${blob} dup\n`
    )
    const module = ssh.authorizedKeys("alice", key, { options: { restrict: true } })

    expect(await statusOf(module.apply(host.connection, {}))).toBe("changed")
    expect(host.content()).toBe(`${otherLine}\nrestrict ${key}\n${optionedOther}\n`)
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
  })

  it("replaces the line in place when only the trailing comment changes", async () => {
    const host = createHost(`${otherLine}\n${key}\n${optionedOther}\n`)
    const module = ssh.authorizedKeys("alice", renamedKey)

    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(await statusOf(module.apply(host.connection, {}))).toBe("changed")
    expect(host.content()).toBe(`${otherLine}\n${renamedKey}\n${optionedOther}\n`)
  })

  it("reads a file with option-bearing lines without error and without a duplicate", async () => {
    const line = `restrict,command="echo \\"a b\\"" ${key}`
    const host = createHost(`${optionedOther}\n${line}\n`)
    const module = ssh.authorizedKeys("alice", key, {
      options: { command: 'echo "a b"', restrict: true },
    })

    await expect(module.check(host.connection, {})).resolves.toBe("ok")
    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "ok" })
    expect(host.replaces()).toBe(0)
  })

  it("removes every line of the blob for absent and keeps other lines byte-identical", async () => {
    const unrelated = "# jürgen's note\n"
    const original = `${unrelated}${otherLine}\n${key}\nrestrict,command="x" ssh-ed25519 ${blob} c\n${optionedOther}`
    const host = createHost(original)
    const module = ssh.authorizedKeys("alice", key, { state: "absent" })

    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(await statusOf(module.apply(host.connection, {}))).toBe("changed")
    expect(host.content()).toBe(`${unrelated}${otherLine}\n${optionedOther}`)
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
  })
})

describe("ssh.authorizedKeys options guard", () => {
  const secret = "very-secret-token"
  const withOptions = `restrict,environment="TOKEN=${secret}" ${key}\n`

  it.each([
    ["alone", withOptions],
    ["beside an option-free line of the same blob", `${key}\n${withOptions}`],
  ])("fails apply and dry-run when options are omitted (%s)", async (_label, content) => {
    const host = createHost(content)
    const module = ssh.authorizedKeys("alice", key)

    for (const result of [
      await module.apply(host.connection, {}),
      await dryRun(module, host.connection),
    ]) {
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("(environment, restrict)")
      expect(result.error?.message).not.toContain(secret)
    }
    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(host.replaces()).toBe(0)
    expect(host.prepares()).toBe(0)
    expect(host.content()).toBe(content)
  })

  it("replaces the options with an option-free line for options: {}", async () => {
    const host = createHost(withOptions)
    const module = ssh.authorizedKeys("alice", key, { options: {} })

    expect(await statusOf(module.apply(host.connection, {}))).toBe("changed")
    expect(host.content()).toBe(`${key}\n`)
    await expect(module.check(host.connection, {})).resolves.toBe("ok")
  })
})

describe("ssh.authorizedKeys unparseable lines", () => {
  const unparseable = `garbage-prefix ${blob} trailing`
  const content = `${otherLine}\n${unparseable}\n# keep ÿ\n`

  it.each([
    ["present", {}],
    ["absent", { state: "absent" as const }],
  ])("fails in %s and leaves the file untouched", async (_label, settings) => {
    const host = createHost(content)
    const module = ssh.authorizedKeys("alice", key, settings)

    const result = await module.apply(host.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("line 2")
    expect(result.error?.message).not.toContain("garbage-prefix")
    expect(await statusOf(dryRun(module, host.connection))).toBe("failed")
    expect(host.replaces()).toBe(0)
    expect(host.prepares()).toBe(0)
  })

  it("keeps unrelated unparseable lines unchanged while appending", async () => {
    const foreign = "completely unparseable line"
    const host = createHost(`${foreign}\n${otherLine}\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.content()).toBe(`${foreign}\n${otherLine}\n${key}\n`)
  })
})

describe("ssh.authorizedKeys staging", () => {
  it("stages and replaces through the canonical .ssh path when a parent directory is a symlink", async () => {
    const host = createHost(`${otherLine}\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.prepares()).toBe(1)
    expect(host.content()).toBe(`${otherLine}\n${key}\n`)
  })

  it("rewrites a file with non-UTF-8 bytes in a foreign line and keeps those bytes", async () => {
    const foreign = Buffer.from([0x23, 0x20, 0xff, 0xfe, 0x80, 0x0a])
    const initial = Buffer.concat([foreign, Buffer.from(`${otherLine}\n`)])
    const host = createHost(initial)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.rawContent()).toStrictEqual(Buffer.concat([initial, Buffer.from(`${key}\n`)]))
  })

  it("fails without replacing when the file changes between read and replace", async () => {
    const concurrent = `${optionedOther}\n`
    const host = createHost(`${otherLine}\n`, {
      beforeReplace: () => bytes(`${otherLine}\n${concurrent}`),
    })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("authorized_keys changed during rewrite")
    expect(host.replaces()).toBe(0)
    expect(host.content()).toBe(`${otherLine}\n${concurrent}`)
  })

  it("writes the payload outside .ssh and removes its private directory after the decode", async () => {
    const host = createHost(`${otherLine}\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )

    const commands = host.commands()
    const decodeIndex = commands.findIndex((command) => command.includes("base64 -d"))
    const decode = commandWith(commands, "base64 -d")
    expect(decode).toContain(
      `command -p base64 -d < '${PAYLOAD_PATH}' | { { paratix_status=$({ { if ${host.account.dropPrefix}/bin/sh -c '`
    )
    expect(decode).toContain("staged=./$3\n")
    expect(decode).toContain('dd of="$staged" oflag=nofollow conv=excl status=none')
    expect(commands.indexOf(`rm -rf -- '${PAYLOAD_DIRECTORY}'`)).toBe(decodeIndex + 1)
    expect(commands.at(-1)).toBe(authorizedKeysCleanupCommand(verifiedFor(host), STAGED_NAME))
    expect(host.cleanups()).toBe(1)
  })

  it("re-checks the staged file in the replace and never runs chmod or chown on it", async () => {
    const host = createHost(`${otherLine}\n`)

    await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    const replaces = host.commands().filter((command) => command.includes("mv -T -- "))
    expect(replaces).toHaveLength(1)
    expect(replaces[0]).toContain(
      quotedFragment(
        `${enterVerifiedSshDirectoryLines()}\nstaged=./$3\n${authorizedKeysStagedFileGuard()}\n${authorizedKeysStagedFileModeGuard()}\n`
      )
    )
    expect(replaces[0].indexOf(quotedFragment(STAGED_MODE_REFUSAL))).toBeLessThan(
      replaces[0].indexOf("mv -T -- ")
    )
    expect(replaces[0]).toContain(quotedFragment(STAGED_FILE_REFUSAL))
    expect(replaces[0]).not.toContain("chmod")
    expect(replaces[0]).not.toContain("chown")
  })

  it("confirms the staged mode in the decode before the replace can publish it", async () => {
    const host = createHost(`${otherLine}\n`)

    await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    const decode = commandWith(host.commands(), "base64 -d")
    expect(decode).toContain(`${quotedFragment(authorizedKeysStagedFileModeGuard())}' sh `)
    expect(decode).not.toContain("chmod")
  })

  it("verifies the replaced file against the digest of the staged content without hashing the staging name", async () => {
    const host = createHost(`${otherLine}\n`)

    await expect(
      ssh.authorizedKeys("alice", key).apply(host.connection, {})
    ).resolves.toStrictEqual({ status: "changed" })

    const replace = commandWith(host.commands(), "mv -T -- ")
    const expectedContent = bytes(`${otherLine}\n${key}\n`)
    expect(replace).toContain(
      "authorized_keys_hash=$({ if command -p dd if=./authorized_keys iflag=nofollow status=none;"
    )
    expect(replace).toContain('[ "$authorized_keys_hash" = "$5" ]')
    expect(replace).toContain(` '${checkedDigest(expectedContent)}' '700 alice alice directory' `)
    expect(replace).not.toContain('sha256sum "$staged"')
    expect(replace).not.toContain(blob)
  })

  it("removes the payload directory and does not replace when the decode fails", async () => {
    const host = createHost(`${otherLine}\n`, { failDecode: true })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to stage authorized_keys rewrite")
    expect(host.commands()).toContain(`rm -rf -- '${PAYLOAD_DIRECTORY}'`)
    expect(host.cleanups()).toBe(1)
    expect(host.replaces()).toBe(0)
  })

  it.each([
    ["inside .ssh", `${CANONICAL_SSH_DIRECTORY}/paratix-authorized-keys-payload.QrStUv`],
    ["with a foreign prefix", "/tmp/other.QrStUv"],
    ["empty", ""],
  ])("refuses an unexpected payload directory %s", async (_label, stdout) => {
    const host = createHost(`${otherLine}\n`, { payloadMktempOutput: stdout })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Unexpected mktemp output")
    expect(host.commands().some((command) => command.startsWith("rm -rf -- "))).toBe(false)
    expect(host.cleanups()).toBe(1)
    expect(host.replaces()).toBe(0)
  })

  it.each([
    ["an absolute path", `${CANONICAL_SSH_DIRECTORY}/${STAGED_NAME}\n`],
    ["a parent reference", `../${STAGED_NAME}\n`],
    ["a foreign prefix", ".other.AbCdEf\n"],
    ["two lines", `${STAGED_NAME}\n${STAGED_NAME}\n`],
    ["empty output", ""],
  ])("refuses a staging mktemp output with %s before staging anything", async (_label, stdout) => {
    const host = createHost(`${otherLine}\n`, { stagingMktempOutput: stdout })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Unexpected mktemp output")
    expect(host.commands()).not.toContain(PAYLOAD_MKTEMP)
    expect(host.cleanups()).toBe(0)
    expect(host.replaces()).toBe(0)
  })

  it("fails without replacing when the file appears between read and replace", async () => {
    const host = createHost(null, { beforeReplace: () => bytes(`${otherLine}\n`) })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("authorized_keys changed during rewrite")
    expect(host.content()).toBe(`${otherLine}\n`)
  })
})

describe("ssh.authorizedKeys symlinked .ssh", () => {
  it("fails dry-run and reports needs-apply in check without preparing anything", async () => {
    const host = createHost(`${key}\n`, { symlinkedSshDirectory: true })
    const module = ssh.authorizedKeys("alice", key)

    const result = await dryRun(module, host.connection)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(".ssh must not be a symlink")
    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(await statusOf(module.apply(host.connection, {}))).toBe("failed")
    expect(host.prepares()).toBe(0)
    expect(host.replaces()).toBe(0)
  })
})

describe("ssh.authorizedKeys foreign lines", () => {
  const authority = `cert-authority,principals="ops" ssh-ed25519 ${blob} user-ca`

  it("keeps a cert-authority line of the same blob in present and absent", async () => {
    const host = createHost(`${authority}\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.content()).toBe(`${authority}\n${key}\n`)
    expect(
      await statusOf(
        ssh.authorizedKeys("alice", key, { state: "absent" }).apply(host.connection, {})
      )
    ).toBe("changed")
    expect(host.content()).toBe(`${authority}\n`)
  })

  it("does not apply the options guard to a cert-authority line", async () => {
    const host = createHost(`${authority}\n${key}\n`)
    const module = ssh.authorizedKeys("alice", key)

    await expect(module.check(host.connection, {})).resolves.toBe("ok")
    await expect(module.apply(host.connection, {})).resolves.toStrictEqual({ status: "ok" })
  })

  it("does not treat another key whose comment names the blob as a conflict", async () => {
    const mentions = `ssh-ed25519 ${ed25519Blob(4)} rotated-from ${blob}`
    const host = createHost(`${mentions}\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.content()).toBe(`${mentions}\n${key}\n`)
  })

  it("replaces a CRLF key line without comment and keeps CRLF on other lines", async () => {
    const host = createHost(`${otherLine}\r\nssh-ed25519 ${blob}\r\n# note\r\n`)

    expect(await statusOf(ssh.authorizedKeys("alice", key).apply(host.connection, {}))).toBe(
      "changed"
    )
    expect(host.content()).toBe(`${otherLine}\r\n${key}\n# note\r\n`)
  })
})

describe("ssh.authorizedKeys privilege drop", () => {
  it.each([
    ["setpriv", "'/usr/bin/setpriv' --reuid=1000 --regid=1000 --init-groups -- "],
    ["runuser", "'/usr/sbin/runuser' -u 'alice' -- "],
  ] as const)("runs every step inside .ssh as the target user via %s", async (drop, prefix) => {
    const host = createHost(`${otherLine}\n`, { drop })

    await expect(
      ssh.authorizedKeys("alice", key).apply(host.connection, {})
    ).resolves.toStrictEqual({ status: "changed" })

    expect(host.account.dropPrefix).toBe(prefix)
    expect(host.content()).toBe(`${otherLine}\n${key}\n`)
    const insideSshDirectory = host
      .commands()
      .filter((command) => command.includes(`'${CANONICAL_SSH_DIRECTORY}'`))
    // Read, prepare, mktemp, decode, replace and cleanup.
    expect(insideSshDirectory).toHaveLength(6)
    for (const command of insideSshDirectory) expect(command).toContain(`${prefix}/bin/sh -c '`)
    // Root only repairs a `.ssh` the user does not own, and then only `.` after
    // the checks; the user-side prepare creates a missing `.ssh` itself.
    const prepare = commandWith(insideSshDirectory, "chmod 700")
    expect(prepare).toContain(
      `{ { if ${prefix}/bin/sh -c 'set -e\n[ -e "$1" ] || [ -L "$1" ] || mkdir -m 700 -- "$1"\n`
    )
    expect(prepare.indexOf(`[ "$(pwd -P)" = '${CANONICAL_SSH_DIRECTORY}' ]`)).toBeLessThan(
      prepare.indexOf("command -p chmod 700 . && command -p chown -h -- '1000:1000' .")
    )
    expect(prepare).toContain(`if [ "$ssh_directory_owner" != '1000' ]; then\n`)
    expect(prepare).toContain(
      quotedFragment(`${enterSshDirectoryLines()}\n[ "$(stat -c '%u' .)" = "$2" ]`)
    )
    expect(prepare).toContain('chmod 700 .\nchown -h -- "$2:$3" .\n')
    expect(prepare).toContain(
      ` sh '${CANONICAL_SSH_DIRECTORY}' '1000' '1000' </dev/null${DROP_OUTPUT_TAIL}`
    )
    // Every drop reads /dev/null (the stage step: only its payload pipe) and
    // writes into root-held pipes, never into root's own descriptors.
    expect(dropDescriptorViolations(host.commands(), prefix)).toStrictEqual([])
    expect(prepare).not.toContain("mkdir -p")
  })

  it("runs without a prefix when the remote shell already has the target uid", async () => {
    const host = createHost(`${otherLine}\n`, { drop: "none" })

    await expect(
      ssh.authorizedKeys("alice", key).apply(host.connection, {})
    ).resolves.toStrictEqual({ status: "changed" })

    const replace = host.commands().find((command) => command.includes("mv -T -- "))
    expect(replace?.startsWith(`${ROOT_PROLOGUE}{ paratix_status=$({ { if /bin/sh -c '`)).toBe(true)
    // The directory checks still apply.
    expect(replace).toContain(quotedFragment(enterVerifiedSshDirectoryLines()))
  })

  it("fails clearly when neither setpriv nor runuser exists and never reads or prepares", async () => {
    const host = createHost(`${otherLine}\n`, { drop: "missing" })
    const module = ssh.authorizedKeys("alice", key)

    const results = [await module.apply(host.connection, {}), await dryRun(module, host.connection)]

    for (const result of results) {
      expect(result.status).toBe("failed")
      expect(result.error?.message).toBe(
        `[ssh.authorizedKeys: alice (present)] ${AUTHORIZED_KEYS_PRIVILEGE_DROP_MISSING}`
      )
    }
    await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
    expect(host.commands().some((command) => command.includes("sh -c "))).toBe(false)
    expect(host.prepares()).toBe(0)
    expect(host.replaces()).toBe(0)
  })

  it("enters .ssh by its physical path in the read before using relative names", () => {
    const read = authorizedKeysReadCommand({
      ...accountFor("setpriv"),
      expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
    })

    expect(read).toContain(quotedFragment(enterSshDirectoryLines()))
    expect(read).toContain("dd if=./authorized_keys iflag=nofollow status=none")
    expect(read).toContain(
      ` sh '${CANONICAL_SSH_DIRECTORY}' '1000' </dev/null${DROP_OUTPUT_TAIL}\nfi`
    )
    // Root reads only a root-owned `.ssh` that nobody else may write.
    expect(read).toContain(
      `if [ "$ssh_directory_owner" != '1000' ]; then\n[ ! -L ./authorized_keys ] || `
    )
  })
})

describe("ssh.authorizedKeys swapped .ssh", () => {
  it.each(["prepare", "mktemp", "decode", "replace"] as const)(
    "fails when .ssh becomes a symlink before the %s step and never acts on its target",
    async (step) => {
      const host = createHost(`${otherLine}\n`, { swapBefore: step })

      const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(".ssh must not be a symlink")
      expect(host.foreignTouched()).toBe(false)
      expect(host.replaces()).toBe(0)
      expect(host.content()).toBe(`${otherLine}\n`)
      // The cleanup refuses the swapped directory as well, so nothing is removed through it.
      expect(host.cleanups()).toBe(0)
    }
  )

  it.each([
    ["a foreign owner", "2049:4711 0\n"],
    ["a malformed identity", "2049 1000\n"],
    ["extra output", `${IDENTITY}\n${IDENTITY}\n`],
  ])("refuses a prepare step that reports %s", async (_label, prepareOutput) => {
    const host = createHost(`${otherLine}\n`, { prepareOutput })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to verify the prepared .ssh directory")
    expect(host.commands()).not.toContain(authorizedKeysMktempCommand(verifiedFor(host)))
    expect(host.replaces()).toBe(0)
  })
})

describe("ssh.authorizedKeys root-owned .ssh", () => {
  it("repairs a protected root-owned .ssh as root on the verified directory before the user-side prepare", async () => {
    const host = createHost(`${otherLine}\n`, { rootOwnedSshDirectory: "protected" })

    await expect(
      ssh.authorizedKeys("alice", key).apply(host.connection, {})
    ).resolves.toStrictEqual({ status: "changed" })

    expect(host.repairs()).toBe(1)
    expect(host.content()).toBe(`${otherLine}\n${key}\n`)
    const prepare = commandWith(
      host.commands(),
      "command -p chmod 700 . && command -p chown -h -- '1000:1000' ."
    )
    const order = [
      `${host.account.dropPrefix}/bin/sh -c 'cd -P -- "$1" || { echo '\\''cannot enter the home directory as the target user'\\''`,
      `cd -P -- '${CANONICAL_SSH_DIRECTORY}' || `,
      `[ "$(pwd -P)" = '${CANONICAL_SSH_DIRECTORY}' ] || `,
      `[ "$ssh_directory_owner" = '1000' ] || [ "$ssh_directory_owner" = 0 ] || `,
      `    ?????w*|????????w*) echo '${ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL}' >&2; exit 1 ;;`,
      "find . -mindepth 1 -maxdepth 1 ! -name authorized_keys ! -name known_hosts ! -name known_hosts.old -print -quit",
      `[ "$authorized_keys_shape" = '0 1' ] || { echo '${ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL}'`,
      `if [ "$ssh_directory_owner" != '1000' ]; then\nif [ ! -L ./authorized_keys ] && [ -f ./authorized_keys ]; then`,
      "  command -p chown -h -- '1000:1000' ./authorized_keys",
      "command -p chmod 700 . && command -p chown -h -- '1000:1000' .",
      `[ "$(pwd -P)" = '${CANONICAL_SSH_DIRECTORY}' ] || { echo '.ssh directory changed during metadata update'`,
      `[ "$(command -p stat -c '%u' .)" = '1000' ] || `,
      `${host.account.dropPrefix}/bin/sh -c 'set -e\n[ -e "$1" ]`,
    ]
    const positions = order.map((fragment) => prepare.indexOf(fragment))
    expect(positions.every((position) => position >= 0)).toBe(true)
    expect([...positions].sort((left, right) => left - right)).toStrictEqual(positions)
    // Root names no entry but `authorized_keys`, which the inspection checked.
    const rootPart = prepare.slice(0, prepare.lastIndexOf(`${host.account.dropPrefix}/bin/sh -c '`))
    expect(new Set(rootPart.match(/\.\/[\w.\-]+/gv))).toStrictEqual(new Set(["./authorized_keys"]))
  })

  it("reads a protected root-owned .ssh as root in the verified directory after the inspection", () => {
    const read = authorizedKeysReadCommand({
      ...accountFor("setpriv"),
      expectedSshDirectory: CANONICAL_SSH_DIRECTORY,
    })

    const rootBranch = read.slice(
      read.indexOf(`if [ "$ssh_directory_owner" != '1000' ]; then\n[ ! -L ./authorized_keys ]`),
      read.indexOf("\nelse\n")
    )
    expect(rootBranch.length).toBeGreaterThan(0)
    expect(
      read.indexOf(rootInspectSshDirectoryLines(accountFor("setpriv"), CANONICAL_SSH_DIRECTORY))
    ).toBeLessThan(read.indexOf(rootBranch))
    // The classification is a character test, independent of shell octal arithmetic.
    expect(read).toContain(`ssh_directory_mode=$(command -p stat -c '%A' .) || exit 1`)
    expect(read).not.toContain("$((")
    expect(rootBranch).toContain("dd if=./authorized_keys iflag=nofollow status=none")
    expect(rootBranch).not.toContain("sh -c")
  })

  it.each([
    ["writable by group or others", "writable", ROOT_OWNED_SSH_DIRECTORY_WRITABLE_REFUSAL],
    ["holding a foreign entry", "extra-entry", ROOT_OWNED_SSH_DIRECTORY_ENTRIES_REFUSAL],
    ["whose authorized_keys has a second link", "linked-keys", ROOT_OWNED_AUTHORIZED_KEYS_REFUSAL],
  ] as const)(
    "refuses a root-owned .ssh %s in dry-run, check and apply without any chmod or chown",
    async (_label, rootOwnedSshDirectory, message) => {
      const host = createHost(`${otherLine}\n`, { rootOwnedSshDirectory })
      const module = ssh.authorizedKeys("alice", key)

      const results = [
        await dryRun(module, host.connection),
        await module.apply(host.connection, {}),
      ]

      for (const result of results) {
        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain(message)
      }
      await expect(module.check(host.connection, {})).resolves.toBe("needs-apply")
      expect(host.prepares()).toBe(0)
      expect(host.repairs()).toBe(0)
      expect(host.commands().some((command) => command.includes("chmod"))).toBe(false)
    }
  )

  it("refuses a root-owned authorized_keys in a user-owned .ssh with an explicit message", async () => {
    const host = createHost(`${otherLine}\n`, { rootOwnedAuthorizedKeys: true })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(AUTHORIZED_KEYS_OWNER_REFUSAL)
    expect(host.prepares()).toBe(0)
  })

  it("fails without touching the foreign directory when a root-owned .ssh becomes a symlink before the repair", async () => {
    const host = createHost(`${otherLine}\n`, {
      rootOwnedSshDirectory: "protected",
      swapBefore: "prepare",
    })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(".ssh must not be a symlink")
    expect(host.foreignTouched()).toBe(false)
    expect(host.repairs()).toBe(0)
    expect(host.replaces()).toBe(0)
  })
})
