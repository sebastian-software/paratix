/* eslint-disable @typescript-eslint/require-await -- async interface methods of the stateful fake host */
/* oxlint-disable jsdoc/require-param, jsdoc/require-returns -- doc comment describes the fake host helper, not a public API */
import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import type { Module, ModuleResult, SshConnection } from "../../../src/types.js"

import { ssh } from "../../../src/modules/ssh.js"
import {
  authorizedKeysReadCommand,
  authorizedKeysStagingPayloadPath,
} from "../../../src/modules/sshAuthorizedKeysFile.js"
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
// `.ssh` path printed by the guard script differs from the literal one.
const CANONICAL_SSH_DIRECTORY = "/data/home/alice/.ssh"
const CANONICAL_KEYS = `${CANONICAL_SSH_DIRECTORY}/authorized_keys`
const STAGED = `${CANONICAL_SSH_DIRECTORY}/.paratix-authorized-keys.AbCdEf`
// The base64 payload goes into a private directory outside the user's `~/.ssh`.
const PAYLOAD_DIRECTORY = "/tmp/paratix-authorized-keys-payload.QrStUv"
const PAYLOAD_MKTEMP = "mktemp -d -p /tmp -- 'paratix-authorized-keys-payload.XXXXXX'"
const STAGED_GUARD = `[ ! -L '${STAGED}' ] && [ -f '${STAGED}' ] && [ "$(stat -c '%u %h' -- '${STAGED}')" = "$(id -u) 1" ] || { echo 'authorized_keys staging file must be a regular single-link file owned by the staging user' >&2; exit 1; }`
// A default ACL on `~/.ssh` overrides the umask, so the staged mode is confirmed before publishing.
const STAGED_MODE_GUARD = `[ "$(stat -c '%a' -- '${STAGED}')" = 600 ] || { echo 'authorized_keys staging file must have mode 600; a default ACL on ~/.ssh may override the umask' >&2; exit 1; }`

type Host = {
  commands: () => string[]
  connection: SshConnection
  content: () => null | string
  prepares: () => number
  rawContent: () => Buffer | null
  replaces: () => number
}

type HostOptions = {
  /** Called right before the final replace runs, e.g. to simulate a concurrent edit. */
  beforeReplace?: (content: null | string) => null | string
  /** Whether the decode script reports a failure. */
  failDecode?: boolean
  /** Raw stdout of the payload directory `mktemp -d`. */
  payloadMktempOutput?: string
  /** Whether `~/.ssh` is a symlink. */
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

type FakeResult = { code: number; stderr: string; stdout: string }

const OK: FakeResult = { code: 0, stderr: "", stdout: "" }
const PAYLOAD_PATH = authorizedKeysStagingPayloadPath(PAYLOAD_DIRECTORY)
const READ_COMMAND = authorizedKeysReadCommand({
  authorizedKeysPath: KEYS,
  sshDirectoryPath: SSH_DIRECTORY,
})

/** File state of the fake host and the handlers of its remote scripts. */
class FakeAuthorizedKeysFile {
  public commands: string[] = []
  public content: null | string
  public payload = ""
  public prepares = 0
  public replaces = 0
  public staged = ""

  public constructor(
    initial: null | string,
    private readonly options: HostOptions
  ) {
    this.content = initial
  }

  public exec(command: string): FakeResult {
    this.commands.push(command)
    if (command === READ_COMMAND) return this.read()
    if (command === "id -gn 'alice'") return { ...OK, stdout: "alice\n" }
    if (command.startsWith(`set -e\n[ ! -L '${SSH_DIRECTORY}' ] || `)) return this.guard(command)
    if (command === PAYLOAD_MKTEMP) {
      return { ...OK, stdout: `${this.options.payloadMktempOutput ?? PAYLOAD_DIRECTORY}\n` }
    }
    if (command.startsWith(`set -e\numask 077\n[ ! -L '${PAYLOAD_PATH}' ]`)) {
      return this.decode(command)
    }
    if (command.startsWith(`${STAGED_GUARD}\n${STAGED_MODE_GUARD}\nchown -h -- `)) {
      return this.replace(command)
    }
    if (command.startsWith("rm -f -- ") || command.startsWith("rm -rf -- ")) return OK
    throw new Error(`unexpected exec: ${command}`)
  }

  // Decodes the payload; succeeds only when the command carries the digest of the decoded bytes.
  private decode(command: string): FakeResult {
    if (this.options.failDecode === true) {
      return { code: 1, stderr: "base64: invalid input", stdout: "" }
    }
    this.staged = Buffer.from(this.payload, "base64").toString("latin1")
    return command.includes(checkedDigest(this.staged))
      ? OK
      : { code: 1, stderr: "authorized_keys staging file does not match", stdout: "" }
  }

  private guard(command: string): FakeResult {
    if (!command.includes("mkdir -p")) throw new Error(`unexpected guard: ${command}`)
    this.prepares += 1
    return { ...OK, stdout: `${CANONICAL_SSH_DIRECTORY}\n` }
  }

  private read(): FakeResult {
    if (this.options.symlinkedSshDirectory === true) {
      return { code: 1, stderr: ".ssh must not be a symlink", stdout: "" }
    }
    if (this.content === null) return { ...OK, stdout: "missing\n" }
    const encoded = Buffer.from(`${this.content}\n0`, "latin1").toString("base64")
    return { ...OK, stdout: `present\n${encoded}` }
  }

  // Replaces only when the command's live-file comparison matches the current
  // content and its post-replace check expects the digest of the staged bytes.
  private replace(command: string): FakeResult {
    // The replace must address the canonical path, not the literal one through `/home`.
    if (!command.includes(`'${CANONICAL_KEYS}'`)) {
      throw new Error(`replace does not use the canonical path: ${command}`)
    }
    this.content = this.options.beforeReplace?.(this.content) ?? this.content
    const unchanged =
      this.content === null
        ? command.includes(`[ ! -e '${CANONICAL_KEYS}' ] && [ ! -L '${CANONICAL_KEYS}' ]`)
        : command.includes(checkedDigest(this.content))
    if (!unchanged) return { code: 1, stderr: "authorized_keys changed during rewrite", stdout: "" }
    if (!command.includes(`[ "$authorized_keys_hash" = '${checkedDigest(this.staged)}' ]`)) {
      return { code: 1, stderr: "authorized_keys content changed during replace", stdout: "" }
    }
    this.content = this.staged
    this.replaces += 1
    return OK
  }
}

/**
 * Stateful host: reads, base64 staging, decode verification, the atomic
 * replace with its live-file comparison, and the ownership probes of one
 * authorized_keys file. The decode and replace scripts only succeed when the
 * digests they carry match the fake file state, so a wrong expectation fails
 * like it would on a real host.
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
      if (
        command === `mktemp -p '${CANONICAL_SSH_DIRECTORY}' -- '.paratix-authorized-keys.XXXXXX'`
      ) {
        return STAGED
      }
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
    commands: () => state.commands,
    connection,
    content: () =>
      state.content === null ? null : Buffer.from(state.content, "latin1").toString("utf8"),
    prepares: () => state.prepares,
    rawContent: () => (state.content === null ? null : Buffer.from(state.content, "latin1")),
    replaces: () => state.replaces,
  }
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
    const decode = commands.at(decodeIndex)
    expect(decode).toContain(`${STAGED_GUARD}\nrm -f -- '${STAGED}'\n`)
    expect(decode).toContain(`dd of='${STAGED}' oflag=nofollow conv=excl status=none`)
    expect(commands.indexOf(`rm -rf -- '${PAYLOAD_DIRECTORY}'`)).toBe(decodeIndex + 1)
    expect(commands).toContain(`rm -f -- '${STAGED}'`)
    expect(commands.some((command) => command.includes(`${STAGED}.base64`))).toBe(false)
  })

  it("re-checks the staged file before a no-follow chown and never chmods it in the replace", async () => {
    const host = createHost(`${otherLine}\n`)

    await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    const replaces = host.commands().filter((command) => command.includes("mv -T -- "))
    expect(replaces).toHaveLength(1)
    expect(replaces[0].split("\n").slice(0, 3)).toStrictEqual([
      STAGED_GUARD,
      STAGED_MODE_GUARD,
      `chown -h -- 'alice':'alice' '${STAGED}' && {`,
    ])
    expect(replaces[0]).not.toContain("chmod")
  })

  it("confirms the staged mode in the decode before the replace can publish it", async () => {
    const host = createHost(`${otherLine}\n`)

    await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    const decode = host.commands().find((command) => command.includes("base64 -d"))
    expect(decode?.split("\n").at(-1)).toBe(STAGED_MODE_GUARD)
    expect(decode).not.toContain("chmod")
  })

  it("verifies the replaced file against the digest of the staged content without hashing the staging name", async () => {
    const host = createHost(`${otherLine}\n`)

    await expect(
      ssh.authorizedKeys("alice", key).apply(host.connection, {})
    ).resolves.toStrictEqual({ status: "changed" })

    const replace = host.commands().find((command) => command.includes("mv -T -- "))
    const expectedContent = bytes(`${otherLine}\n${key}\n`)
    expect(replace).toContain(
      `authorized_keys_hash=$({ if dd if='${CANONICAL_KEYS}' iflag=nofollow status=none;`
    )
    expect(replace).toContain(`[ "$authorized_keys_hash" = '${checkedDigest(expectedContent)}' ]`)
    expect(replace).not.toContain(`sha256sum '${STAGED}'`)
    expect(replace).not.toContain("expected_authorized_keys_hash")
    expect(replace).not.toContain(blob)
  })

  it("removes the payload directory and does not replace when the decode fails", async () => {
    const host = createHost(`${otherLine}\n`, { failDecode: true })

    const result = await ssh.authorizedKeys("alice", key).apply(host.connection, {})

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to stage authorized_keys rewrite")
    expect(host.commands()).toContain(`rm -rf -- '${PAYLOAD_DIRECTORY}'`)
    expect(host.commands()).toContain(`rm -f -- '${STAGED}'`)
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
    expect(host.commands()).toContain(`rm -f -- '${STAGED}'`)
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
