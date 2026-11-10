/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import {
  type AuthorizedKeysAccount,
  authorizedKeysAccountCommand,
} from "../../../src/modules/sshAuthorizedKeysAccount.js"
import {
  authorizedKeysReadCommand,
  authorizedKeysStageDecodeCommand,
  authorizedKeysStagedFileGuard,
  authorizedKeysStagedFileModeGuard,
} from "../../../src/modules/sshAuthorizedKeysFile.js"
import {
  authorizedKeysCleanupCommand,
  authorizedKeysMktempCommand,
  authorizedKeysPrepareCommand,
  authorizedKeysReplaceCommand,
  type VerifiedSshDirectory,
} from "../../../src/modules/sshAuthorizedKeysReplace.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

// `setpriv` prefix of the default fake target user (uid and gid 1000).
const SETPRIV_PREFIX = "'/usr/bin/setpriv' --reuid=1000 --regid=1000 --init-groups -- "
// What every dropped step carries: stdin from /dev/null, root's fds closed.
const DROP_TAIL = " </dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-"
// `device:inode owner` identity the prepare step prints for a uid-1000 `.ssh`.
const IDENTITY = "2049:4711 1000"
// Relative staging name the user-side `mktemp` prints.
const STAGED_NAME = ".paratix-authorized-keys.ABCDEF"

const successfulSshApplyOptions: MockSshOptions = {
  allowWrites: [
    {
      options: { mode: "0600" },
      remotePath: /^\/tmp\/paratix-authorized-keys-payload\.[^\/]+\/payload\.base64$/v,
    },
  ],
  responseStubs: [
    { command: "mkdir -p ~/.ssh && chmod 700 ~/.ssh", result: { code: 0 } },
    { command: /^ssh-keygen -F '[^']+'$/v, result: { code: 1 } },
    { command: /^ssh-keygen -R '[^']+'$/v, result: { code: 0 } },
    {
      command: /^printf '%s\\n' '[^']+' >> ~\/\.ssh\/known_hosts$/v,
      result: { code: 0 },
    },
    {
      // R-0000765: preparing `.ssh` is a single `set -e` exec: create it as
      // the target user, verify it by its physical path and print its identity.
      // Tests for other users stub their exact prepare command.
      command:
        /^set -e\nexec <\/dev\/null\ncd \/\n\{ paratix_status=[^\n]*cannot enter the home directory as the target user/v,
      result: { code: 0, stdout: `${IDENTITY}\n` },
    },
    {
      // Blob-based identity: the existing file is read once as the target user
      // via a no-follow `dd` piped through base64. Unless a test stubs the
      // exact command, the file is reported as missing.
      command:
        /^set -e\nexec <\/dev\/null\ncd \/\nif \[ ! -e '[^']+' \] && \[ ! -L '[^']+' \]; then\n/v,
      result: { stdout: "missing\n" },
    },
    {
      // The user-side `mktemp` inside the verified `.ssh`.
      command:
        /^exec <\/dev\/null\ncd \/\n\{ paratix_status=\$\(\{ \{ if '\/usr\/bin\/setpriv' [^\n]+ -- \/bin\/sh -c 'set -e\ncd -P -- "\$1"[\s\S]*\nmktemp -- /v,
      result: { stdout: `${STAGED_NAME}\n` },
    },
    {
      // Decoding of the base64 payload and verification of the staged bytes.
      command:
        /^set -e\nexec <\/dev\/null\ncd \/\n\[ ! -L '\/tmp\/paratix-authorized-keys-payload\.[^']+\/payload\.base64' \] && \[ -f /v,
      result: { code: 0 },
    },
    {
      // The final replace runs as the target user inside the verified `.ssh`.
      command:
        /^exec <\/dev\/null\ncd \/\n\{ paratix_status=[^\n]+ -- \/bin\/sh -c 'cd -P -- "\$1"[\s\S]*mv -T -- /v,
      result: { code: 0 },
    },
    {
      // The user-side cleanup of the staging name.
      command:
        /^exec <\/dev\/null\ncd \/\n\{ paratix_status=[^\n]+ -- \/bin\/sh -c 'cd -P -- "\$1"[\s\S]*\nrm -f -- "\.\/\$3"' sh /v,
      result: { code: 0 },
    },
    {
      // The base64 payload lives in a private directory outside `~/.ssh`.
      command: /^mktemp -d -p \/tmp -- 'paratix-authorized-keys-payload\.X{6}'$/v,
      result: { stdout: "/tmp/paratix-authorized-keys-payload.STUB\n" },
    },
    {
      command: /^rm -rf -- '\/tmp\/paratix-authorized-keys-payload\.[^']+'$/v,
      result: { code: 0 },
    },
    {
      command: /^\[ -e '[^']+\/\.ssh\/authorized_keys' \]$/v,
      result: { code: 1 },
    },
  ],
}

function createSshApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulSshApplyOptions)
}

const emptyEnv = {}

function isKnownHostsAppend(command: string): boolean {
  return command.startsWith("printf '%s\\n' ") && command.endsWith(" >> ~/.ssh/known_hosts")
}

function sshString(value: Buffer | string): Buffer {
  const valueBytes = typeof value === "string" ? Buffer.from(value) : value
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(valueBytes.length)
  return Buffer.concat([lengthBuffer, valueBytes])
}

function makeHostKeyBuffer(algo: string): Buffer {
  if (algo === "ssh-ed25519") {
    return Buffer.concat([sshString(algo), sshString(Buffer.alloc(32, 1))])
  }
  if (algo === "ssh-rsa") {
    return Buffer.concat([
      sshString(algo),
      sshString(Buffer.from([1, 0, 1])),
      sshString(Buffer.alloc(32, 2)),
    ])
  }
  return Buffer.concat([sshString(algo), sshString(Buffer.alloc(16, 3))])
}

function makeOtherEd25519Key(fill: number, comment: string): string {
  const blob = Buffer.concat([sshString("ssh-ed25519"), sshString(Buffer.alloc(32, fill))])
  return `ssh-ed25519 ${blob.toString("base64")} ${comment}`
}

/**
 * Target account as the account probe reports it.
 *
 * @param parameters - User, canonical `.ssh` and optional ids and prefix.
 * @param parameters.dropPrefix - The privilege-drop prefix; defaults to `setpriv` for uid 1000.
 * @param parameters.expectedSshDirectory - The canonical `.ssh` path.
 * @param parameters.id - Numeric uid and gid; defaults to `1000`.
 * @param parameters.user - The target user.
 * @returns The account the module derives from the probe.
 */
function accountFor(parameters: {
  dropPrefix?: string
  expectedSshDirectory: string
  id?: string
  user: string
}): { expectedSshDirectory: string } & AuthorizedKeysAccount {
  const { dropPrefix = SETPRIV_PREFIX, expectedSshDirectory, id = "1000", user } = parameters
  return { dropPrefix, expectedSshDirectory, gid: id, uid: id, user }
}

/**
 * The account probe of a user and its stubbed response.
 *
 * @param parameters - Getent home, canonical home, user, tool and ids.
 * @param parameters.canonicalHome - What `realpath -e` prints for the home.
 * @param parameters.drop - The privilege-drop tool the probe reports.
 * @param parameters.home - The getent home.
 * @param parameters.id - Numeric uid and gid.
 * @param parameters.user - The target user.
 * @returns A response entry for `createMockSsh`.
 */
function accountProbe(parameters: {
  canonicalHome?: string
  drop?: string
  home: string
  id?: string
  user: string
}): Record<string, { stdout: string }> {
  const { canonicalHome = parameters.home, drop = "setpriv", home, id = "1000", user } = parameters
  return {
    [authorizedKeysAccountCommand({ home, user })]: {
      stdout: `${drop} ${id} ${id}\n${canonicalHome}\n${drop === "setpriv" ? "/usr/bin/setpriv" : ""}\n`,
    },
  }
}

function verifiedFor(account: { expectedSshDirectory: string } & AuthorizedKeysAccount) {
  const verified: VerifiedSshDirectory = {
    account,
    expectedSshDirectory: account.expectedSshDirectory,
    identity: `2049:4711 ${account.uid}`,
  }
  return verified
}

function authorizedKeysReadResponse(content: null | string): { stdout: string } {
  if (content === null) return { stdout: "missing\n" }
  const encoded = Buffer.from(`${content}\n0`, "latin1").toString("base64")
  return { stdout: `present\n${encoded}` }
}

function checkedDigest(content: string): string {
  return createHash("sha256")
    .update(Buffer.from(`${content}\n0`, "latin1"))
    .digest("hex")
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

// Payload directory the shared `mktemp -d` stub reports.
const PAYLOAD_DIRECTORY = "/tmp/paratix-authorized-keys-payload.STUB"
const PAYLOAD_PATH = `${PAYLOAD_DIRECTORY}/payload.base64`
const PAYLOAD_CLEANUP = `rm -rf -- '${PAYLOAD_DIRECTORY}'`

const STAGED_FILE_MODE_REFUSAL =
  "authorized_keys staging file must have mode 600; a default ACL on ~/.ssh may override the umask"

/**
 * The staged bytes travel as base64 text through SFTP into a private payload
 * directory under `/tmp`; root decodes them and pipes them into the stage
 * script that runs as the target user, so non-UTF-8 bytes survive unchanged.
 *
 * @param parameters - Account, staged content and staging name.
 * @param parameters.account - The target account.
 * @param parameters.content - The staged content.
 * @param parameters.stagedName - The relative staging name.
 * @returns The decode and verification command rendered by the module.
 */
function decodeFor(parameters: {
  account: { expectedSshDirectory: string } & AuthorizedKeysAccount
  content: string
  stagedName?: string
}): string {
  const { account, content, stagedName = STAGED_NAME } = parameters
  return authorizedKeysStageDecodeCommand({
    account,
    content,
    expectedSshDirectory: account.expectedSshDirectory,
    identity: verifiedFor(account).identity,
    payloadDirectory: PAYLOAD_DIRECTORY,
    stagedName,
  })
}

/**
 * Decode the staged payloads the module wrote through SFTP.
 *
 * @param mockSsh - The mock connection.
 * @param mockSsh.writeFileCalls - The recorded writeFile calls.
 * @returns The staged contents in write order.
 */
function stagedContents(mockSsh: { writeFileCalls: Array<{ content: string }> }): string[] {
  return mockSsh.writeFileCalls.map((call) =>
    Buffer.from(call.content, "base64").toString("latin1")
  )
}

function isFinalReplace(command: string): boolean {
  return command.includes("mv -T -- ")
}

function finalReplaceFor(parameters: {
  account: { expectedSshDirectory: string } & AuthorizedKeysAccount
  content: string
  group: string
  original?: null | string
  stagedName?: string
}): string {
  const { account, content, group, original = null, stagedName = STAGED_NAME } = parameters
  return authorizedKeysReplaceCommand({
    content,
    original,
    primaryGroup: group,
    stagedName,
    verified: verifiedFor(account),
  })
}

/**
 * Wrap a fresh mock SSH connection that reflects a virtual
 * `~/.ssh/known_hosts` file across two apply runs so the R-0000038
 * regression test can assert idempotent behaviour without using
 * conditionals inside the test body. The grep test reflects whether the
 * tracked line is present; the printf-append exec records the line as added.
 *
 * @param line - The verified host-key line that the test simulates.
 * @param baseResponses - Base responses for unrelated commands (e.g.
 *   `ssh-keyscan`).
 * @returns A mock SSH connection whose `test` and `exec` track the virtual
 *   known_hosts state.
 */
function createKnownHostsTrackingMock(
  line: string,
  baseResponses: Record<string, { code?: number; stderr?: string; stdout?: string }>
): ReturnType<typeof createMockSsh> {
  const grepCommand = `grep -qxF '${line}' ~/.ssh/known_hosts`
  const printfCommand = `printf '%s\\n' '${line}' >> ~/.ssh/known_hosts`
  let present = false
  const base = createSshApplyMockSsh(baseResponses)
  return {
    ...base,
    async exec(command: string, options?: Parameters<typeof base.exec>[1]) {
      const result = await base.exec(command, options)
      if (command === printfCommand) present = true
      return result
    },
    test: async (command: string): Promise<boolean> =>
      command === grepCommand ? present : base.test(command),
  }
}

describe("ssh.authorizedKeys", () => {
  const testKey = `ssh-ed25519 ${makeHostKeyBuffer("ssh-ed25519").toString("base64")} test-key`

  // resolveHome calls conn.output() which returns the home path
  const getentAlice = "getent passwd 'alice' | cut -d: -f6"
  // R-0000065: resolvePrimaryGroup runs `id -gn` for both apply and check
  // to derive the user's actual primary group.
  const idGroupAlice = "id -gn 'alice'"
  const aliceHome = "/home/alice"
  const aliceDir = `'/home/alice/.ssh'`
  const aliceKeys = `'/home/alice/.ssh/authorized_keys'`
  const aliceKeysExistsOrSymlinkProbe =
    "[ -e '/home/alice/.ssh/authorized_keys' ] || [ -L '/home/alice/.ssh/authorized_keys' ]"
  const aliceAccount = accountFor({ expectedSshDirectory: "/home/alice/.ssh", user: "alice" })
  const aliceVerified = verifiedFor(aliceAccount)
  const aliceAccountProbe = authorizedKeysAccountCommand({ home: aliceHome, user: "alice" })
  // R-0000181: the temp file lives in <home>/.ssh on the destination
  // filesystem so `mv -T` is atomic (single rename(2)); the user-side
  // `mktemp` prints its relative name.
  const aliceMktempPattern = authorizedKeysMktempCommand(aliceVerified)
  const tempPath = STAGED_NAME
  // R-0000765: the apply pipeline prepares `.ssh` in a single `set -e` exec.
  const aliceSshDirectoryGuard = authorizedKeysPrepareCommand(aliceVerified)
  const aliceRead = authorizedKeysReadCommand(aliceAccount)
  const otherKey = makeOtherEd25519Key(7, "other-key")
  const aliceDecode = (content: string): string => decodeFor({ account: aliceAccount, content })
  const aliceFinalReplace = (original: null | string, content: string): string =>
    finalReplaceFor({ account: aliceAccount, content, group: "alice", original })
  // The final replace for a file that was missing when it was read.
  const aliceFinalReplaceCommand = aliceFinalReplace(null, `${testKey}\n`)
  const aliceCleanup = authorizedKeysCleanupCommand(aliceVerified, STAGED_NAME)
  const deployAccount = accountFor({ expectedSshDirectory: "/home/deploy/.ssh", user: "deploy" })
  const spaceyAccount = accountFor({ expectedSshDirectory: "/home/my user/.ssh", user: "alice" })

  function aliceResponses(
    extra?: Record<string, Partial<{ code: number; stderr: string; stdout: string }>>
  ) {
    return {
      "[ -L '/home/alice/.ssh' ]": { code: 1 },
      [aliceKeysExistsOrSymlinkProbe]: { code: 0 },
      ...accountProbe({ home: aliceHome, user: "alice" }),
      [getentAlice]: { stdout: aliceHome },
      [idGroupAlice]: { stdout: "alice" },
      ...extra,
    }
  }

  it("rejects authorized_keys entries with invalid base64 key material", () => {
    expect(() => {
      ssh.authorizedKeys("alice", "ssh-ed25519 not-base64! test-key")
    }).toThrow("strict base64")
  })

  it("rejects authorized_keys entries whose encoded algorithm does not match", () => {
    const mismatchedKey = `ssh-rsa ${makeHostKeyBuffer("ssh-ed25519").toString("base64")} test-key`

    expect(() => {
      ssh.authorizedKeys("alice", mismatchedKey)
    }).toThrow("valid OpenSSH public key")
  })

  it("rejects authorized_keys entries with unsupported key algorithms", () => {
    const unsupportedKey = `ssh-dss ${makeHostKeyBuffer("ssh-dss").toString("base64")} test-key`

    expect(() => {
      ssh.authorizedKeys("alice", unsupportedKey)
    }).toThrow("unsupported public key algorithm")
  })

  it.each(["present", "absent"] as const)("accepts state at construction time: %s", (state) => {
    expect(() => ssh.authorizedKeys("alice", testKey, { state })).not.toThrow()
  })

  it("rejects unknown string states at construction time", () => {
    expect(() => {
      ssh.authorizedKeys("alice", testKey, {
        state: "remove",
      } as unknown as { state: "absent" | "present" })
    }).toThrow('ssh.authorizedKeys state must be "present" or "absent"')
  })

  it("rejects non-string states at construction time", () => {
    expect(() => {
      ssh.authorizedKeys("alice", testKey, {
        state: false,
      } as unknown as { state: "absent" | "present" })
    }).toThrow('ssh.authorizedKeys state must be "present" or "absent"')
  })

  it("check returns ok when key exists in authorized_keys (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key is missing (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${otherKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression — check returns needs-apply when authorized_keys does not exist for a fresh user", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(aliceRead)
    expect(mockSsh.calls).not.toContain("stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'")
  })

  it("returns needs-apply in check when the target user does not exist yet", async () => {
    const mockSsh = createMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey)

    await expect(mod.check(mockSsh, emptyEnv)).resolves.toBe("needs-apply")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("returns ok in check for absent state when the target user does not exist", async () => {
    const mockSsh = createMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey, { state: "absent" })

    await expect(mod.check(mockSsh, emptyEnv)).resolves.toBe("ok")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("returns ok in apply for absent state when the target user does not exist", async () => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain(
      "mkdir -p '/.ssh' && chmod 700 '/.ssh' && chown 'ghost':'ghost' '/.ssh'"
    )
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh' ]")
    expect(mockSsh.calls).not.toContain("[ -e '/.ssh/authorized_keys' ]")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when key is missing (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${otherKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when key exists (state: absent)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when authorized_keys is a symlink", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply before reading keys when .ssh is a symlink", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(aliceRead)
  })

  it("check returns needs-apply when .ssh ownership or mode has drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "755 root root directory" },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when authorized_keys ownership or mode has drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "644 root root regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("apply creates directory, adds key with correct permissions (state: present)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // R-0000765: the .ssh-directory preparation is a single `set -e` exec;
    // the authorized_keys symlink probe runs in the user-side read and again
    // in the final replace, both on the relative name in the verified `.ssh`.
    expect(mockSsh.calls).toContain(aliceAccountProbe)
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    for (const command of [aliceRead, aliceFinalReplaceCommand]) {
      expect(command).toContain(
        quotedFragment(
          "[ ! -L ./authorized_keys ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }"
        )
      )
    }
    expect(mockSsh.calls).toContain(aliceRead)
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.writeFileCalls).toStrictEqual([
      {
        content: Buffer.from(`${testKey}\n`).toString("base64"),
        options: { mode: "0600" },
        remotePath: PAYLOAD_PATH,
      },
    ])
    expect(mockSsh.calls).toContain(aliceDecode(`${testKey}\n`))
    expect(mockSsh.calls.indexOf(PAYLOAD_CLEANUP)).toBe(
      mockSsh.calls.indexOf(aliceDecode(`${testKey}\n`)) + 1
    )
    expect(mockSsh.calls).not.toContain(`printf '%s\\n' '${testKey}' >> ${aliceKeys}`)
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(aliceCleanup)
    // F8: the read and plan run before the directory is prepared.
    expect(mockSsh.calls.indexOf(aliceRead)).toBeLessThan(
      mockSsh.calls.indexOf(aliceSshDirectoryGuard)
    )
  })

  it("apply returns ok without rewriting when present state is already converged", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${otherKey}\n${testKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls).not.toContain(aliceSshDirectoryGuard)
    expect(mockSsh.writeFileCalls).toStrictEqual([])
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: apply does not append a duplicate key when only permissions have drifted", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "644 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const checkResult = await mod.check(mockSsh, emptyEnv)
    expect(checkResult).toBe("needs-apply")

    const applyResult = await mod.apply(mockSsh, emptyEnv)
    expect(applyResult.status).toBe("changed")
    // The unchanged content is restaged so the atomic replace resets mode
    // and ownership without appending a second copy of the key.
    expect(stagedContents(mockSsh)).toStrictEqual([`${testKey}\n`])
    expect(mockSsh.calls).toContain(aliceDecode(`${testKey}\n`))
    expect(mockSsh.calls).toContain(aliceFinalReplace(`${testKey}\n`, `${testKey}\n`))
  })

  it("regression: present rewrite terminates existing authorized_keys before appending", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(otherKey),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    await mod.apply(mockSsh, emptyEnv)

    expect(stagedContents(mockSsh)).toStrictEqual([`${otherKey}\n${testKey}\n`])
  })

  it("regression: present rewrite fails closed when reading authorized_keys fails", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: { code: 2, stderr: "dd: read error", stdout: "present\nc2VjcmV0" },
      }),
      { ...successfulSshApplyOptions, rejectNonZeroExit: true }
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("dd: read error")
    // Partial file content must never be echoed in the failure.
    expect(String(result.error)).not.toContain("c2VjcmV0")
    expect(mockSsh.calls).toContain(aliceRead)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: present rewrite fails closed when the staging file is swapped during staging", async () => {
    const decodeCommand = aliceDecode(`${testKey}\n`)
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [decodeCommand]: {
          code: 1,
          stderr:
            "authorized_keys staging file must be a regular single-link file owned by the staging user",
        },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "authorized_keys staging file must be a regular single-link file owned by the staging user"
    )
    expect(decodeCommand).toContain('dd of="$staged" oflag=nofollow conv=excl status=none')
    const keyDigest = checkedDigest(`${testKey}\n`)
    // The stage step reads the decoded payload from its pipe, not /dev/null.
    expect(decodeCommand).toContain(
      ` '${tempPath}' '${keyDigest}' 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-;`
    )
    expect(mockSsh.calls).toContain(PAYLOAD_CLEANUP)
    expect(aliceRead).toContain("dd if=./authorized_keys iflag=nofollow status=none")
    expect(mockSsh.calls).toContain(decodeCommand)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
    expect(mockSsh.calls).toContain(aliceCleanup)
  })

  it("regression: present rewrite fails closed when authorized_keys is recreated as a symlink before the replace", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: {
          code: 1,
          stderr: "authorized_keys changed during rewrite",
        },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys changed during rewrite")
    expect(aliceFinalReplaceCommand).toContain(
      quotedFragment(
        "[ ! -e ./authorized_keys ] && [ ! -L ./authorized_keys ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }"
      )
    )
    expect(aliceFinalReplaceCommand).toContain(` '${tempPath}' 'missing' `)
    // The live-file comparison runs directly before the backup link and the rename.
    expect(aliceFinalReplaceCommand.indexOf("authorized_keys changed during rewrite")).toBeLessThan(
      aliceFinalReplaceCommand.indexOf("ln -P --")
    )
  })

  it("apply removes every line of the key blob (state: absent)", async () => {
    const original = `${otherKey}\n${testKey}\n`
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(original),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(stagedContents(mockSsh)).toStrictEqual([`${otherKey}\n`])
    expect(mockSsh.calls).toContain(aliceDecode(`${otherKey}\n`))
    expect(mockSsh.calls).toContain(aliceFinalReplace(original, `${otherKey}\n`))
  })

  it("apply returns ok without rewriting when absent state is already converged", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [aliceRead]: authorizedKeysReadResponse(`${otherKey}\n`),
        "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
        "stat -c '%a %U %G %F' '/home/alice/.ssh/authorized_keys'": {
          stdout: "600 alice alice regular file",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.writeFileCalls).toStrictEqual([])
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: absent apply returns ok before preparing .ssh when authorized_keys is missing", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceKeysExistsOrSymlinkProbe]: { code: 1 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.calls).toContain(aliceKeysExistsOrSymlinkProbe)
    expect(mockSsh.calls).not.toContain(idGroupAlice)
    expect(mockSsh.calls).not.toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls).not.toContain(aliceRead)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: absent rewrite fails closed on read errors and does not replace the target", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: { code: 2, stderr: "dd: read error" },
      }),
      { ...successfulSshApplyOptions, rejectNonZeroExit: true }
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("dd: read error")
    expect(mockSsh.calls).toContain(aliceRead)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: absent rewrite fails closed when authorized_keys changes before the replace", async () => {
    const replaceCommand = aliceFinalReplace(`${testKey}\n`, "")
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
        [replaceCommand]: {
          code: 1,
          stderr: "authorized_keys changed during rewrite",
        },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys changed during rewrite")
    expect(replaceCommand).toContain(
      "current_authorized_keys_hash=$({ if command -p dd if=./authorized_keys iflag=nofollow status=none;"
    )
    const originalDigest = checkedDigest(`${testKey}\n`)
    expect(replaceCommand).toContain(` '${tempPath}' '${originalDigest}' `)
    expect(mockSsh.calls).toContain(aliceDecode(""))
    expect(mockSsh.calls).toContain(replaceCommand)
  })

  // R-0000044 (superseded by blob identity): `state: "absent"` removes every
  // line whose key blob matches, regardless of options and trailing comment,
  // because sshd would still accept the key through any of them. Lines that
  // only mention the key body (a comment line, or another key whose comment
  // contains the body) are not entries of this key and stay byte-identical.
  it("regression: absent apply removes every line of the blob but keeps lines that only mention the key body", async () => {
    const blob = testKey.split(" ")[1]
    const restrictedEntry = `command="/usr/bin/restricted" ${testKey}`
    const otherCommentEntry = `ssh-ed25519 ${blob} another-comment`
    const commentLine = `# rotated: ${testKey}`
    const unrelatedEntry = makeOtherEd25519Key(9, `mentions-${blob}`)
    const original = `${commentLine}\n${testKey}\n${restrictedEntry}\n${unrelatedEntry}\n${otherCommentEntry}\n`

    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(original),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(stagedContents(mockSsh)).toStrictEqual([`${commentLine}\n${unrelatedEntry}\n`])
  })

  it("regression: apply resets ownership and mode after removing a key (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceFinalReplace(`${testKey}\n`, ""))
  })

  it("returns failed when authorized_keys is a symlink", async () => {
    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception. The user-side read
    // refuses a symlinked authorized_keys before `.ssh` is prepared.
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceRead]: {
          code: 1,
          stderr: "authorized_keys must not be a symlink",
        },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys must not be a symlink")
    expect(mockSsh.calls).not.toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
  })

  // R-0000285 / R-0000610: harden the final rename against a symlink race.
  // The shell now hardlinks the existing authorized_keys to a sibling
  // backup before the rename and re-checks `[ ! -L ]` immediately after,
  // so a destination that turns into a symlink during the race window is
  // caught by the post-`ln` symlink guard. Apply must surface that as a
  // structured failure instead of letting the mutation throw.
  it("R-0000285: returns failed when authorized_keys was recreated as a symlink during replace", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: {
          code: 1,
          stderr: "authorized_keys must not be a symlink",
        },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys must not be a symlink")
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
  })

  it("regression: returns failed when mv -n reports success without replacing authorized_keys", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: {
          code: 1,
          stderr: "authorized_keys replace did not consume temporary file",
        },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys replace did not consume temporary file")
    const keyLineDigest = checkedDigest(`${testKey}\n`)
    expect(aliceFinalReplaceCommand).not.toContain("expected_authorized_keys_hash")
    expect(aliceFinalReplaceCommand).not.toContain('sha256sum "$staged"')
    expect(aliceFinalReplaceCommand).toContain('[ ! -e "$staged" ]')
    expect(aliceFinalReplaceCommand).toContain(
      "authorized_keys_hash=$({ if command -p dd if=./authorized_keys iflag=nofollow status=none;"
    )
    expect(aliceFinalReplaceCommand).toContain('[ "$authorized_keys_hash" = "$5" ]')
    expect(aliceFinalReplaceCommand).toContain(` 'missing' '${keyLineDigest}' `)
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
  })

  it("regression: returns failed before publishing when the staged file does not have mode 600", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: { code: 1, stderr: STAGED_FILE_MODE_REFUSAL },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(STAGED_FILE_MODE_REFUSAL)
    // A default ACL on ~/.ssh overrides the umask: the decode and the replace
    // confirm mode 600 after the staged-file guard and before anything is
    // published, and neither runs a chmod or chown on the staged file.
    const decodeCommand = aliceDecode(`${testKey}\n`)
    expect(decodeCommand).toContain(`${quotedFragment(authorizedKeysStagedFileModeGuard())}' sh `)
    expect(aliceFinalReplaceCommand).toContain(
      quotedFragment(
        `staged=./$3\n${authorizedKeysStagedFileGuard()}\n${authorizedKeysStagedFileModeGuard()}\n`
      )
    )
    expect(aliceFinalReplaceCommand.indexOf(quotedFragment(STAGED_FILE_MODE_REFUSAL))).toBeLessThan(
      aliceFinalReplaceCommand.indexOf("mv -T --")
    )
    expect(`${decodeCommand}\n${aliceFinalReplaceCommand}`).not.toContain("chmod")
    expect(`${decodeCommand}\n${aliceFinalReplaceCommand}`).not.toContain("chown")
    expect(mockSsh.calls).toContain(decodeCommand)
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(aliceCleanup)
  })

  it("verifies the replaced file against the digest of the computed content, not the staging name", () => {
    const content = `${otherKey}\n${testKey}\n`
    const replaceCommand = aliceFinalReplace(`${otherKey}\n`, content)

    expect(replaceCommand).toContain(
      quotedFragment(
        `[ "$authorized_keys_hash" = "$5" ] || { rm -f -- ./authorized_keys.paratix-backup; echo 'authorized_keys content changed during replace' >&2; exit 1; }`
      )
    )
    expect(replaceCommand).toContain(` '${checkedDigest(content)}' '700 alice alice directory' `)
    expect(replaceCommand).not.toContain('sha256sum "$staged"')
    // Only the digest reaches the command line, never the content itself.
    expect(replaceCommand).not.toContain(testKey)
    expect(replaceCommand).not.toContain(otherKey)
  })

  it("returns failed when .ssh is a symlink before chmod, chown, mktemp, or rewrite", async () => {
    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceRead]: authorizedKeysReadResponse(null),
        [aliceSshDirectoryGuard]: {
          code: 1,
          stderr: ".ssh must not be a symlink",
        },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(".ssh must not be a symlink")
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    // A missing `.ssh` is created by the target user, and mode and owner
    // change only for the working directory after `cd -P` and the `pwd -P`
    // check, by root only for a root-owned `.ssh`.
    expect(aliceSshDirectoryGuard).toContain(`${SETPRIV_PREFIX}/bin/sh -c 'set -e\n`)
    expect(aliceSshDirectoryGuard.indexOf(`[ "$(pwd -P)" = ${aliceDir} ]`)).toBeLessThan(
      aliceSshDirectoryGuard.indexOf(
        "command -p chmod 700 . && command -p chown -h -- '1000:1000' ."
      )
    )
    expect(aliceSshDirectoryGuard.indexOf('[ "$(pwd -P)" = "$1" ]')).toBeLessThan(
      aliceSshDirectoryGuard.indexOf("chmod 700 .\n")
    )
    expect(aliceSshDirectoryGuard).toContain('[ -e "$1" ] || [ -L "$1" ] || mkdir -m 700 -- "$1"')
    expect(aliceSshDirectoryGuard).toContain(` sh ${aliceDir} '1000' '1000'${DROP_TAIL};`)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("returns failed from the read without preparing .ssh when .ssh is already a symlink", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceRead]: { code: 1, stderr: ".ssh must not be a symlink" },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(".ssh must not be a symlink")
    expect(aliceRead).toContain(`[ ! -L ${aliceDir} ]`)
    expect(aliceRead).toContain(` sh ${aliceDir} '1000'${DROP_TAIL};`)
    expect(mockSsh.calls).not.toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
  })

  it.each([
    ["a relative canonical home", "setpriv 1000 1000\nhome/alice\n/usr/bin/setpriv\n"],
    ["a canonical home with a colon", "setpriv 1000 1000\n/home/al:ice\n/usr/bin/setpriv\n"],
    ["a non-numeric uid", "setpriv alice 1000\n/home/alice\n/usr/bin/setpriv\n"],
    ["an unknown tool", "sudo 1000 1000\n/home/alice\n/usr/bin/sudo\n"],
    ["a relative tool path", "setpriv 1000 1000\n/home/alice\nsetpriv\n"],
    ["a tool path of another program", "setpriv 1000 1000\n/home/alice\n/tmp/evil\n"],
    ["a missing tool path", "runuser 1000 1000\n/home/alice\n\n"],
    ["extra output", "setpriv 1000 1000\n/home/alice\n/usr/bin/setpriv\n/etc\n"],
  ])("fails before reading when the account probe reports %s", async (_label, stdout) => {
    const mockSsh = createMockSsh(
      aliceResponses({ [aliceAccountProbe]: { stdout } }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to resolve the target account")
    expect(mockSsh.calls.some((command) => command.includes("sh -c "))).toBe(false)
  })

  it("fails without preparing .ssh when the home directory does not exist", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceAccountProbe]: { stdout: "setpriv 1000 1000\n\n/usr/bin/setpriv\n" },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("home directory /home/alice does not exist")
    // The missing home reads as a missing file without running the read script.
    expect(mockSsh.calls.some((command) => command.includes("sh -c "))).toBe(false)
    await expect(mod._applyDryRun?.(mockSsh, emptyEnv)).resolves.toStrictEqual({
      status: "changed",
    })
  })

  it("stages and replaces through the canonical .ssh path when a parent directory is a symlink", async () => {
    const canonicalAccount = accountFor({
      expectedSshDirectory: "/data/home/alice/.ssh",
      user: "alice",
    })
    const canonicalVerified = verifiedFor(canonicalAccount)
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        ...accountProbe({ canonicalHome: "/data/home/alice", home: aliceHome, user: "alice" }),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toStrictEqual([PAYLOAD_PATH])
    expect(mockSsh.calls).toContain(authorizedKeysReadCommand(canonicalAccount))
    expect(mockSsh.calls).toContain(authorizedKeysPrepareCommand(canonicalVerified))
    expect(mockSsh.calls).toContain(authorizedKeysMktempCommand(canonicalVerified))
    expect(mockSsh.calls).toContain(
      finalReplaceFor({ account: canonicalAccount, content: `${testKey}\n`, group: "alice" })
    )
    expect(mockSsh.calls).toContain(authorizedKeysCleanupCommand(canonicalVerified, STAGED_NAME))
  })

  it("regression: returns failed when .ssh is exchanged during metadata update", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceSshDirectoryGuard]: {
          code: 1,
          stderr: ".ssh directory changed during metadata update",
        },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(".ssh directory changed during metadata update")
    // `pwd -P` is checked again after the metadata update, then the identity is printed.
    const finalLines = quotedFragment(
      `[ "$(pwd -P)" = "$1" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }\nstat -c '%d:%i %u' .`
    )
    expect(aliceSshDirectoryGuard).toContain(`${finalLines}' sh `)
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
  })

  it("regression: returns failed when .ssh is exchanged before the final authorized_keys replace", async () => {
    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: {
          code: 1,
          stderr: ".ssh ownership changed before authorized_keys replace",
        },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(".ssh ownership changed before authorized_keys replace")
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).toContain(aliceDecode(`${testKey}\n`))
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(aliceCleanup)
  })

  // R-0000181: temp file must live in <home>/.ssh, on the same filesystem
  // as authorized_keys, so `mv -T` is atomic instead of a cross-FS copy
  // that loses owner/mode and breaks under NFS root_squash.
  it("stages the authorized_keys rewrite inside <home>/.ssh on the destination filesystem", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(`${otherKey}\n`),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toStrictEqual([PAYLOAD_PATH])
    expect(aliceMktempPattern).toContain(
      quotedFragment("mktemp -- '.paratix-authorized-keys.XXXXXX'")
    )
    expect(aliceMktempPattern).toContain(` sh ${aliceDir} '${IDENTITY}'${DROP_TAIL};`)
    // The legacy /run/paratix path must not be used any more.
    expect(mockSsh.calls.every((c) => !c.includes("/run/paratix"))).toBe(true)
  })

  it.each([
    ["empty output", ""],
    ["multiline output", `${tempPath}\n.paratix-authorized-keys.EVIL`],
    ["an absolute path", "/tmp/.paratix-authorized-keys.ABCDEF"],
    ["a path component", "../.paratix-authorized-keys.ABCDEF"],
    ["wrong prefix", "not-paratix-authorized-keys.ABCDEF"],
  ])("rejects unsafe authorized_keys mktemp output: %s", async (_caseName, stdout) => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Unexpected mktemp output")
    expect(mockSsh.writeFileCalls).toStrictEqual([])
    expect(mockSsh.calls.some(isFinalReplace)).toBe(false)
    // Nothing is removed for a name the module did not validate.
    expect(mockSsh.calls.some((command) => command.includes('rm -f -- "./$3"'))).toBe(false)
    expect(mockSsh.calls.some((command) => command.startsWith("mktemp -d "))).toBe(false)
  })

  it("stages absent-state rewrites inside <home>/.ssh as well", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [aliceRead]: authorizedKeysReadResponse(`${testKey}\n`),
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.calls.every((c) => !c.includes("/run/paratix"))).toBe(true)
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ssh.authorizedKeys("alice", testKey)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("fails closed in apply when the user does not exist and resolveHome returns an empty string", async () => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'ghost' | cut -d: -f6": { stdout: "" },
    })
    const mod = ssh.authorizedKeys("ghost", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[ssh.authorizedKeys: ghost] failed to resolve a safe home directory"
    )
    expect(mockSsh.calls).not.toContain(
      "mkdir -p '/.ssh' && chmod 700 '/.ssh' && chown 'ghost':'ghost' '/.ssh'"
    )
    expect(mockSsh.calls).not.toContain(
      "[ ! -L '/.ssh/authorized_keys' ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }"
    )
  })

  it.each([
    ["relative", "home/alice"],
    ["colon-containing", "/home/al:ice"],
    ["LF-containing", "/home/al\nice"],
    ["CR-containing", "/home/al\rice"],
  ])("rejects %s home paths in check", async (_caseName, home) => {
    const mockSsh = createMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: home },
    })
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toStrictEqual(["getent passwd 'alice' | cut -d: -f6"])
  })

  it.each([
    ["relative", "home/alice"],
    ["colon-containing", "/home/al:ice"],
    ["LF-containing", "/home/al\nice"],
    ["CR-containing", "/home/al\rice"],
  ])("fails closed in apply for %s home paths", async (_caseName, home) => {
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: home },
    })
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[ssh.authorizedKeys: alice] failed to resolve a safe home directory"
    )
    expect(mockSsh.calls).toStrictEqual(["getent passwd 'alice' | cut -d: -f6"])
  })

  it("resolves home directory dynamically for root user", async () => {
    const rootAccount = accountFor({
      dropPrefix: "",
      expectedSshDirectory: "/root/.ssh",
      id: "0",
      user: "root",
    })
    const mockSsh = createMockSsh({
      "[ -e '/root/.ssh' ]": { code: 0 },
      "[ -e '/root/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/root/.ssh' ]": { code: 1 },
      "[ -L '/root/.ssh/authorized_keys' ]": { code: 1 },
      ...accountProbe({ drop: "none", home: "/root", id: "0", user: "root" }),
      [authorizedKeysReadCommand(rootAccount)]: authorizedKeysReadResponse(`${testKey}\n`),
      "getent passwd 'root' | cut -d: -f6": { stdout: "/root" },
      "id -gn 'root'": { stdout: "root" },
      "stat -c '%a %U %G %F' '/root/.ssh'": { stdout: "700 root root directory" },
      "stat -c '%a %U %G %F' '/root/.ssh/authorized_keys'": {
        stdout: "600 root root regular file",
      },
    })
    const mod = ssh.authorizedKeys("root", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("applies for the root user without a privilege drop but with the directory checks", async () => {
    const rootAccount = accountFor({
      dropPrefix: "",
      expectedSshDirectory: "/root/.ssh",
      id: "0",
      user: "root",
    })
    const rootVerified = verifiedFor(rootAccount)
    const content = `${otherKey}\n${testKey}\n`
    const commands = {
      cleanup: authorizedKeysCleanupCommand(rootVerified, STAGED_NAME),
      mktemp: authorizedKeysMktempCommand(rootVerified),
      prepare: authorizedKeysPrepareCommand(rootVerified),
      read: authorizedKeysReadCommand(rootAccount),
      replace: finalReplaceFor({
        account: rootAccount,
        content,
        group: "root",
        original: `${otherKey}\n`,
      }),
    }
    const mockSsh = createSshApplyMockSsh({
      ...accountProbe({ drop: "none", home: "/root", id: "0", user: "root" }),
      [commands.cleanup]: { code: 0 },
      [commands.mktemp]: { stdout: `${STAGED_NAME}\n` },
      [commands.prepare]: { stdout: `${rootVerified.identity}\n` },
      [commands.read]: authorizedKeysReadResponse(`${otherKey}\n`),
      [commands.replace]: { code: 0 },
      "getent passwd 'root' | cut -d: -f6": { stdout: "/root" },
      "id -gn 'root'": { stdout: "root" },
    })

    const result = await ssh.authorizedKeys("root", testKey).apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(stagedContents(mockSsh)).toStrictEqual([content])
    for (const command of Object.values(commands)) expect(mockSsh.calls).toContain(command)
    expect(
      commands.replace.startsWith(
        `exec </dev/null\ncd /\n{ paratix_status=$({ { if /bin/sh -c 'cd -P -- "$1" || `
      )
    ).toBe(true)
    expect(commands.prepare).toContain(`{ { if /bin/sh -c 'set -e\n[ -e "$1" ] || [ -L "$1" ]`)
    expect(commands.prepare).toContain(` sh '/root/.ssh' '0' '0'${DROP_TAIL};`)
    expect(mockSsh.calls).toContain(decodeFor({ account: rootAccount, content }))
    expect(mockSsh.calls.join("\n")).not.toContain("setpriv' --reuid")
  })

  it("resolves home directory dynamically for non-root user", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh' ]": { code: 1 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      ...accountProbe({ home: "/home/deploy", user: "deploy" }),
      [authorizedKeysReadCommand(deployAccount)]: authorizedKeysReadResponse(`${testKey}\n`),
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "deploy" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh'": { stdout: "700 deploy deploy directory" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh/authorized_keys'": {
        stdout: "600 deploy deploy regular file",
      },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("regression: home path with spaces is correctly shell-quoted in check", async () => {
    const spaceyHome = "/home/my user"
    const mockSsh = createMockSsh({
      "[ -e '/home/my user/.ssh' ]": { code: 0 },
      "[ -e '/home/my user/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/my user/.ssh' ]": { code: 1 },
      "[ -L '/home/my user/.ssh/authorized_keys' ]": { code: 1 },
      ...accountProbe({ home: spaceyHome, user: "alice" }),
      [authorizedKeysReadCommand(spaceyAccount)]: authorizedKeysReadResponse(`${testKey}\n`),
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
      "stat -c '%a %U %G %F' '/home/my user/.ssh'": { stdout: "700 alice alice directory" },
      "stat -c '%a %U %G %F' '/home/my user/.ssh/authorized_keys'": {
        stdout: "600 alice alice regular file",
      },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    // Verify that the path containing a space was passed as a quoted argument
    expect(mockSsh.calls).toContain(authorizedKeysReadCommand(spaceyAccount))
    expect(authorizedKeysReadCommand(spaceyAccount)).toContain(" sh '/home/my user/.ssh' '1000'")
  })

  it("regression: home path with spaces is correctly shell-quoted in apply", async () => {
    const spaceyHome = "/home/my user"
    const spaceyVerified = verifiedFor(spaceyAccount)
    const mockSsh = createSshApplyMockSsh({
      ...accountProbe({ home: spaceyHome, user: "alice" }),
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // Every step must quote the space-containing path.
    expect(mockSsh.calls).toContain(authorizedKeysPrepareCommand(spaceyVerified))
    expect(authorizedKeysPrepareCommand(spaceyVerified)).toContain(
      " sh '/home/my user/.ssh' '1000' '1000'"
    )
    // R-0000181: mktemp must operate inside <home>/.ssh on the destination filesystem.
    expect(mockSsh.calls).toContain(authorizedKeysMktempCommand(spaceyVerified))
    expect(mockSsh.calls).toContain(authorizedKeysReadCommand(spaceyAccount))
    expect(mockSsh.calls).toContain(decodeFor({ account: spaceyAccount, content: `${testKey}\n` }))
    expect(mockSsh.calls).toContain(
      finalReplaceFor({ account: spaceyAccount, content: `${testKey}\n`, group: "alice" })
    )
  })

  // R-0000065 regression: when the user's primary group is not equal to the
  // username (e.g. `deploy:users`, a service user like `www-data:www-data`,
  // or an operator in `paratix:wheel`), apply must chown to the user's
  // actual primary group and check must compare against that same group so
  // a stable check-ok state is reachable without overwriting the
  // semantically correct group ownership.
  it("R-0000065: apply uses the user's resolved primary group for chown when it differs from the username", async () => {
    const mockSsh = createSshApplyMockSsh({
      ...accountProbe({ home: "/home/deploy", user: "deploy" }),
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // The directory chown uses the numeric primary gid of the account probe.
    expect(mockSsh.calls).toContain(authorizedKeysPrepareCommand(verifiedFor(deployAccount)))
    const deployPrepare = authorizedKeysPrepareCommand(verifiedFor(deployAccount))
    expect(deployPrepare).toContain('chown -h -- "$2:$3" .')
    expect(deployPrepare).toContain(` sh '/home/deploy/.ssh' '1000' '1000'${DROP_TAIL};`)
    // The replace compares ownership against the resolved primary group.
    const replace = finalReplaceFor({
      account: deployAccount,
      content: `${testKey}\n`,
      group: "users",
    })
    expect(mockSsh.calls).toContain(replace)
    expect(replace).toContain(" '700 deploy users directory' '600 deploy users regular file'")
    // The legacy `${user}:${user}` chown must not be issued.
    expect(mockSsh.calls.some((command) => command.includes("'deploy':'deploy'"))).toBe(false)
  })

  it("R-0000065: check returns ok when the primary group differs from the username and matches stat output", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh' ]": { code: 1 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      ...accountProbe({ home: "/home/deploy", user: "deploy" }),
      [authorizedKeysReadCommand(deployAccount)]: authorizedKeysReadResponse(`${testKey}\n`),
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh'": {
        stdout: "700 deploy users directory",
      },
      "stat -c '%a %U %G %F' '/home/deploy/.ssh/authorized_keys'": {
        stdout: "600 deploy users regular file",
      },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("rejects keys containing newlines at construction time", () => {
    const malicious = `${testKey}\nssh-ed25519 INJECTED extra-key`
    expect(() => ssh.authorizedKeys("alice", malicious)).toThrow(/must not contain newlines/v)
  })

  it("rejects keys containing carriage returns at construction time", () => {
    const malicious = `${testKey}\rssh-ed25519 INJECTED extra-key`
    expect(() => ssh.authorizedKeys("alice", malicious)).toThrow(/must not contain newlines/v)
  })

  it("rejects an empty key at construction time", () => {
    expect(() => ssh.authorizedKeys("alice", "")).toThrow(/must not be empty/v)
  })

  it.each(["", "--name", "-r", "bad user", "1alice", "älice"])(
    "rejects invalid usernames at construction time: %s",
    (user) => {
      expect(() => ssh.authorizedKeys(user, testKey)).toThrow(
        `user name ${JSON.stringify(user)} is invalid`
      )
    }
  )
})
