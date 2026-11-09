/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

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
      // R-0000765: .ssh directory preparation and authorized_keys symlink
      // probe now run in a single `set -e` pipeline. The previous two
      // separate stub entries are replaced by the fused pattern below.
      command:
        /^set -e\n\[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must not be a symlink' >&2; exit 1; \}\nif \[ -e '[^']+\/\.ssh' \]; then\n {2}\[ -d '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a directory' >&2; exit 1; \}\nelse\n {2}mkdir -p '[^']+\/\.ssh'\nfi\n\[ -d '[^']+\/\.ssh' \] && \[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a real directory' >&2; exit 1; \}\nssh_directory_identity=\$\(stat -c '%d:%i' '[^']+\/\.ssh'\) \|\| exit \$\?\nchmod 700 '[^']+\/\.ssh' && chown '[^']+':'[^']+' '[^']+\/\.ssh'\n\[ ! -L '[^']+\/\.ssh' \] && \[ -d '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a real directory' >&2; exit 1; \}\npost_ssh_directory_identity=\$\(stat -c '%d:%i' '[^']+\/\.ssh'\) \|\| exit \$\?\n\[ "\$post_ssh_directory_identity" = "\$ssh_directory_identity" \] \|\| \{ echo '\.ssh directory changed during metadata update' >&2; exit 1; \}\n\[ ! -L '[^']+\/\.ssh\/authorized_keys' \] \|\| \{ echo 'authorized_keys must not be a symlink' >&2; exit 1; \}\ncanonical_ssh_directory=\$\(command -p realpath -e -- '[^']+\/\.ssh'\) \|\| exit \$\?\n/v,
      // The guard prints the canonical `.ssh` path; tests for other homes
      // stub their exact guard command.
      result: { code: 0, stdout: "/home/alice/.ssh\n" },
    },
    {
      // Blob-based identity: the existing file is read once via a no-follow
      // `dd` piped through base64. Unless a test stubs the exact command, the
      // file is reported as missing.
      command:
        /^set -e\n\[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must not be a symlink' >&2; exit 1; \}\n\[ ! -L '[^']+\/\.ssh\/authorized_keys' \] \|\| \{ echo 'authorized_keys must not be a symlink' >&2; exit 1; \}\nif \[ -e /v,
      result: { stdout: "missing\n" },
    },
    {
      // Decoding of the base64 payload and verification of the staged bytes.
      command:
        /^set -e\numask 077\n\[ ! -L '\/tmp\/paratix-authorized-keys-payload\.[^']+\/payload\.base64' \] && \[ -f /v,
      result: { code: 0 },
    },
    {
      // The final replace re-checks the staged file before its no-follow chown.
      command: /^\[ ! -L '[^']+\/\.ssh\/\.paratix-authorized-keys\.[^']+' \] && \[ -f /v,
      result: { code: 0 },
    },
    {
      command: /^rm -f -- '[^']+\/\.ssh\/\.paratix-authorized-keys\.[^']+'$/v,
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
      command: /^mktemp -p '[^']+\/\.ssh' -- '\.paratix-authorized-keys\.X{6}'$/v,
      result: { stdout: "/home/alice/.ssh/.paratix-authorized-keys.STUB" },
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
 * R-0000617: the existing authorized_keys is read via `dd ... iflag=nofollow`
 * so the open(2) call uses O_NOFOLLOW, collapsing the TOCTOU window where a
 * symlink could otherwise be swapped in after the `[ ! -L ]` guard. The bytes
 * travel base64-encoded with a trailing read status. The read also refuses a
 * symlinked `.ssh` directory.
 *
 * @param authorizedKeysPath - The shell-quoted authorized_keys path.
 * @returns The read command rendered by the module.
 */
function authorizedKeysReadCommand(authorizedKeysPath: string): string {
  const sshDirectoryPath = authorizedKeysPath.replace(/\/authorized_keys'$/v, "'")
  return `set -e
[ ! -L ${sshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
[ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
if [ -e ${authorizedKeysPath} ]; then
  [ -f ${authorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  printf 'present\\n'
  { if dd if=${authorizedKeysPath} iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; } | base64 -w 0
else
  printf 'missing\\n'
fi`
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

// Payload directory the shared `mktemp -d` stub reports.
const PAYLOAD_DIRECTORY = "/tmp/paratix-authorized-keys-payload.STUB"
const PAYLOAD_PATH = `${PAYLOAD_DIRECTORY}/payload.base64`
const PAYLOAD_CLEANUP = `rm -rf -- '${PAYLOAD_DIRECTORY}'`

/**
 * The guard the decode and the final replace run on the staged file: still a
 * regular, single-link file owned by the staging uid, and not a symlink.
 *
 * @param temporaryPath - The unquoted staging path.
 * @returns The guard statement rendered by the module.
 */
function stagedFileGuard(temporaryPath: string): string {
  return `[ ! -L '${temporaryPath}' ] && [ -f '${temporaryPath}' ] && [ "$(stat -c '%u %h' -- '${temporaryPath}')" = "$(id -u) 1" ] || { echo 'authorized_keys staging file must be a regular single-link file owned by the staging user' >&2; exit 1; }`
}

const STAGED_FILE_MODE_REFUSAL =
  "authorized_keys staging file must have mode 600; a default ACL on ~/.ssh may override the umask"

/**
 * The mode check the decode and the final replace run on the staged file after
 * {@link stagedFileGuard}: a default ACL on `~/.ssh` overrides the umask, so
 * the file must be confirmed as 0600 before anything is published.
 *
 * @param temporaryPath - The unquoted staging path.
 * @returns The mode check statement rendered by the module.
 */
function stagedFileModeGuard(temporaryPath: string): string {
  return `[ "$(stat -c '%a' -- '${temporaryPath}')" = 600 ] || { echo '${STAGED_FILE_MODE_REFUSAL}' >&2; exit 1; }`
}

/**
 * The staged bytes travel as base64 text through SFTP into a private payload
 * directory under `/tmp` and are decoded on the host, so non-UTF-8 bytes
 * survive unchanged.
 *
 * @param parameters - Staged content and staging path.
 * @param parameters.content - The staged content.
 * @param parameters.temporaryPath - The unquoted staging path.
 * @returns The decode and verification command rendered by the module.
 */
function authorizedKeysStageDecodeCommand(parameters: {
  content: string
  temporaryPath: string
}): string {
  const { content, temporaryPath } = parameters
  const payload = `'${PAYLOAD_PATH}'`
  return `set -e
umask 077
[ ! -L ${payload} ] && [ -f ${payload} ] || { echo 'authorized_keys staging payload must be a regular file' >&2; exit 1; }
${stagedFileGuard(temporaryPath)}
rm -f -- '${temporaryPath}'
dd if=${payload} iflag=nofollow status=none | base64 -d | dd of='${temporaryPath}' oflag=nofollow conv=excl status=none
rm -f -- ${payload}
staged_hash=$({ if dd if='${temporaryPath}' iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; } | sha256sum | cut -d' ' -f1)
[ "$staged_hash" = '${checkedDigest(content)}' ] || { echo 'authorized_keys staging file does not match the computed content' >&2; exit 1; }
${stagedFileModeGuard(temporaryPath)}`
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
  return command.includes("\nchown -h -- ")
}

function sshDirectoryGuardCommand(parameters: {
  authorizedKeysPath: string
  group: string
  sshDirectoryPath: string
  user: string
}): string {
  const { authorizedKeysPath, group, sshDirectoryPath, user } = parameters
  return `set -e
[ ! -L ${sshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
if [ -e ${sshDirectoryPath} ]; then
  [ -d ${sshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }
else
  mkdir -p ${sshDirectoryPath}
fi
[ -d ${sshDirectoryPath} ] && [ ! -L ${sshDirectoryPath} ] || { echo '.ssh must be a real directory' >&2; exit 1; }
ssh_directory_identity=$(stat -c '%d:%i' ${sshDirectoryPath}) || exit $?
chmod 700 ${sshDirectoryPath} && chown '${user}':'${group}' ${sshDirectoryPath}
[ ! -L ${sshDirectoryPath} ] && [ -d ${sshDirectoryPath} ] || { echo '.ssh must be a real directory' >&2; exit 1; }
post_ssh_directory_identity=$(stat -c '%d:%i' ${sshDirectoryPath}) || exit $?
[ "$post_ssh_directory_identity" = "$ssh_directory_identity" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
[ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
canonical_ssh_directory=$(command -p realpath -e -- ${sshDirectoryPath}) || exit $?
canonical_ssh_directory_identity=$(stat -c '%d:%i' -- "$canonical_ssh_directory") || exit $?
[ "$canonical_ssh_directory_identity" = "$post_ssh_directory_identity" ] || { echo '.ssh directory changed during metadata update' >&2; exit 1; }
printf '%s\\n' "$canonical_ssh_directory"`
}

function authorizedKeysFinalReplaceCommand(parameters: {
  authorizedKeysPath: string
  content: string
  expectedSshDirectoryState: string
  group: string
  original?: null | string
  sshDirectoryPath: string
  temporaryPath: string
  user: string
}): string {
  const {
    authorizedKeysPath,
    content,
    expectedSshDirectoryState,
    group,
    original = null,
    sshDirectoryPath,
    temporaryPath,
    user,
  } = parameters
  // The live-file comparison runs in the same script directly before the
  // backup link and the rename.
  const unchangedGuard =
    original === null
      ? `  [ ! -e ${authorizedKeysPath} ] && [ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }`
      : `  [ -f ${authorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
  current_authorized_keys_hash=$({ if dd if=${authorizedKeysPath} iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; } | sha256sum | cut -d' ' -f1) || exit $?
  [ "$current_authorized_keys_hash" = '${checkedDigest(original)}' ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }`
  // R-0000610: hardlink-backup variant. The pre-existing destination is
  // hardlinked to `<authorized_keys>.paratix-backup` before the atomic
  // rename, so a failing `mv` can restore the original via a second
  // atomic rename. The backup is removed once verification succeeds.
  // R-0000622: the backup hardlink uses `ln -P --` so a last-instant
  // symlink swap between the `[ ! -L ]` probe and the link cannot
  // redirect the hardlink to an attacker-controlled target; the
  // `[ ! -L ]` guard is also repeated immediately before the `ln` as
  // defence in depth.
  const backupPath = `${authorizedKeysPath.slice(0, -1)}.paratix-backup'`
  // The post-replace check compares the live file, read without following
  // symlinks, with the literal digest of the computed content.
  return `${stagedFileGuard(temporaryPath)}
${stagedFileModeGuard(temporaryPath)}
chown -h -- '${user}':'${group}' '${temporaryPath}' && {
  [ ! -L ${sshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }
  [ -d ${sshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }
  ssh_directory_state=$(stat -c '%a %U %G %F' ${sshDirectoryPath}) || exit $?
  [ "$ssh_directory_state" = '${expectedSshDirectoryState}' ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }
  [ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  rm -f -- ${backupPath}
  backup_created=0
${unchangedGuard}
  if [ -e ${authorizedKeysPath} ]; then
    [ -f ${authorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }
    [ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }
    ln -P -- ${authorizedKeysPath} ${backupPath} || { echo 'failed to create authorized_keys backup hardlink' >&2; exit 1; }
    backup_created=1
  fi
  [ ! -L ${authorizedKeysPath} ] || { rm -f -- ${backupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  if ! mv -T -- '${temporaryPath}' ${authorizedKeysPath}; then
    if [ "$backup_created" = 1 ]; then
      mv -T -- ${backupPath} ${authorizedKeysPath} || echo 'authorized_keys backup restore failed; backup is at '${backupPath} >&2
    fi
    echo 'authorized_keys replace failed' >&2
    exit 1
  fi
  [ ! -e '${temporaryPath}' ] || { rm -f -- ${backupPath}; echo 'authorized_keys replace did not consume temporary file' >&2; exit 1; }
  [ ! -L ${authorizedKeysPath} ] || { rm -f -- ${backupPath}; echo 'authorized_keys must not be a symlink' >&2; exit 1; }
  [ -f ${authorizedKeysPath} ] || { rm -f -- ${backupPath}; echo 'authorized_keys must be a regular file' >&2; exit 1; }
  authorized_keys_state=$(stat -c '%a %U %G %F' ${authorizedKeysPath}) || { rm -f -- ${backupPath}; exit 1; }
  [ "$authorized_keys_state" = '600 ${user} ${group} regular file' ] || { rm -f -- ${backupPath}; echo 'authorized_keys metadata changed during replace' >&2; exit 1; }
  authorized_keys_hash=$({ if dd if=${authorizedKeysPath} iflag=nofollow status=none; then printf '\\n0'; else printf '\\n1'; fi; } | sha256sum | cut -d' ' -f1) || { rm -f -- ${backupPath}; exit 1; }
  [ "$authorized_keys_hash" = '${checkedDigest(content)}' ] || { rm -f -- ${backupPath}; echo 'authorized_keys content changed during replace' >&2; exit 1; }
  rm -f -- ${backupPath}
}`
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
  // R-0000181: temp file lives in <home>/.ssh on the destination filesystem
  // so `mv -T` is atomic (single rename(2)) and avoids cross-FS copies.
  const aliceMktempPattern = "mktemp -p '/home/alice/.ssh' -- '.paratix-authorized-keys.XXXXXX'"
  const tempPath = "/home/alice/.ssh/.paratix-authorized-keys.ABCDEF"
  // R-0000765: the apply pipeline runs the .ssh-directory preparation and
  // the authorized_keys symlink probe in a single `set -e` shell exec.
  const aliceSshDirectoryGuard = sshDirectoryGuardCommand({
    authorizedKeysPath: aliceKeys,
    group: "alice",
    sshDirectoryPath: aliceDir,
    user: "alice",
  })
  const aliceRead = authorizedKeysReadCommand(aliceKeys)
  const otherKey = makeOtherEd25519Key(7, "other-key")
  const aliceDecode = (content: string): string =>
    authorizedKeysStageDecodeCommand({ content, temporaryPath: tempPath })
  const aliceFinalReplace = (original: null | string, content: string): string =>
    authorizedKeysFinalReplaceCommand({
      authorizedKeysPath: aliceKeys,
      content,
      expectedSshDirectoryState: "700 alice alice directory",
      group: "alice",
      original,
      sshDirectoryPath: aliceDir,
      temporaryPath: tempPath,
      user: "alice",
    })
  // The final replace for a file that was missing when it was read.
  const aliceFinalReplaceCommand = aliceFinalReplace(null, `${testKey}\n`)
  const aliceCleanup = `rm -f -- '${tempPath}'`

  function aliceResponses(
    extra?: Record<string, Partial<{ code: number; stderr: string; stdout: string }>>
  ) {
    return {
      "[ -L '/home/alice/.ssh' ]": { code: 1 },
      [aliceKeysExistsOrSymlinkProbe]: { code: 0 },
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
    // R-0000765: the .ssh-directory preparation and the authorized_keys
    // symlink probe are now part of the same fused `set -e` exec; assert
    // the fused command directly and on the embedded symlink clause as a
    // substring instead of expecting a separate exec call.
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(aliceSshDirectoryGuard).toContain(
      `[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`
    )
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
    expect(decodeCommand).toContain(`dd of='${tempPath}' oflag=nofollow conv=excl status=none`)
    expect(mockSsh.calls).toContain(PAYLOAD_CLEANUP)
    expect(aliceRead).toContain(`dd if=${aliceKeys} iflag=nofollow status=none`)
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
      `[ ! -e ${aliceKeys} ] && [ ! -L ${aliceKeys} ] || { echo 'authorized_keys changed during rewrite' >&2; exit 1; }`
    )
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
      `current_authorized_keys_hash=$({ if dd if=${aliceKeys} iflag=nofollow status=none;`
    )
    expect(replaceCommand).toContain(checkedDigest(`${testKey}\n`))
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
    // ModuleResult instead of an unstructured exception.
    // R-0000765: the symlink probe is now embedded into the fused .ssh
    // directory preparation exec, so the stub keys off the combined
    // command instead of the previously-separate symlink check.
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceSshDirectoryGuard]: {
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
    expect(aliceFinalReplaceCommand).not.toContain(`sha256sum '${tempPath}'`)
    expect(aliceFinalReplaceCommand).toContain(`[ ! -e '${tempPath}' ]`)
    expect(aliceFinalReplaceCommand).toContain(
      `authorized_keys_hash=$({ if dd if=${aliceKeys} iflag=nofollow status=none;`
    )
    expect(aliceFinalReplaceCommand).toContain(`[ "$authorized_keys_hash" = '${keyLineDigest}' ]`)
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
    // published, and neither runs a symlink-following chmod on the staged file.
    const decodeCommand = aliceDecode(`${testKey}\n`)
    expect(decodeCommand.split("\n").at(-1)).toBe(stagedFileModeGuard(tempPath))
    expect(aliceFinalReplaceCommand.split("\n").slice(0, 3)).toStrictEqual([
      stagedFileGuard(tempPath),
      stagedFileModeGuard(tempPath),
      `chown -h -- 'alice':'alice' '${tempPath}' && {`,
    ])
    expect(aliceFinalReplaceCommand.indexOf(STAGED_FILE_MODE_REFUSAL)).toBeLessThan(
      aliceFinalReplaceCommand.indexOf("mv -T --")
    )
    expect(`${decodeCommand}\n${aliceFinalReplaceCommand}`).not.toContain("chmod")
    expect(mockSsh.calls).toContain(decodeCommand)
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(aliceCleanup)
  })

  it("verifies the replaced file against the digest of the computed content, not the staging name", () => {
    const content = `${otherKey}\n${testKey}\n`
    const replaceCommand = aliceFinalReplace(`${otherKey}\n`, content)

    expect(replaceCommand).toContain(
      `[ "$authorized_keys_hash" = '${checkedDigest(content)}' ] || { rm -f -- '/home/alice/.ssh/authorized_keys.paratix-backup'; echo 'authorized_keys content changed during replace' >&2; exit 1; }`
    )
    expect(replaceCommand).not.toContain(`sha256sum '${tempPath}'`)
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
    expect(mockSsh.calls).not.toContain(
      `mkdir -p ${aliceDir} && chmod 700 ${aliceDir} && chown 'alice':'alice' ${aliceDir}`
    )
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
    expect(mockSsh.calls).not.toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
  })

  it("returns failed when the guard does not print a canonical .ssh path", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceSshDirectoryGuard]: { code: 0, stdout: "/home/alice\n" },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to resolve the canonical .ssh directory")
    expect(mockSsh.calls).not.toContain(aliceMktempPattern)
  })

  it("stages and replaces through the canonical .ssh path when a parent directory is a symlink", async () => {
    const canonicalDirectory = "/data/home/alice/.ssh"
    const canonicalMktemp = `mktemp -p '${canonicalDirectory}' -- '.paratix-authorized-keys.XXXXXX'`
    const canonicalTemp = `${canonicalDirectory}/.paratix-authorized-keys.CANON1`
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceSshDirectoryGuard]: { code: 0, stdout: `${canonicalDirectory}\n` },
        [canonicalMktemp]: { stdout: canonicalTemp },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toStrictEqual([PAYLOAD_PATH])
    expect(mockSsh.calls).toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: `'${canonicalDirectory}/authorized_keys'`,
        content: `${testKey}\n`,
        expectedSshDirectoryState: "700 alice alice directory",
        group: "alice",
        sshDirectoryPath: `'${canonicalDirectory}'`,
        temporaryPath: canonicalTemp,
        user: "alice",
      })
    )
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
    expect(aliceSshDirectoryGuard).toContain(
      "ssh_directory_identity=$(stat -c '%d:%i' '/home/alice/.ssh')"
    )
    expect(aliceSshDirectoryGuard).toContain(
      "post_ssh_directory_identity=$(stat -c '%d:%i' '/home/alice/.ssh')"
    )
    expect(aliceSshDirectoryGuard).toContain(
      '[ "$post_ssh_directory_identity" = "$ssh_directory_identity" ]'
    )
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
    expect(tempPath.startsWith(`${aliceHome}/.ssh/.paratix-authorized-keys.`)).toBe(true)
    // The legacy /run/paratix path must not be used any more.
    expect(mockSsh.calls.every((c) => !c.includes("/run/paratix"))).toBe(true)
  })

  it.each([
    ["empty output", ""],
    ["multiline output", `${tempPath}\n${aliceHome}/.ssh/.paratix-authorized-keys.EVIL`],
    ["outside <home>/.ssh", "/tmp/.paratix-authorized-keys.ABCDEF"],
    ["wrong prefix", `${aliceHome}/.ssh/not-paratix-authorized-keys.ABCDEF`],
  ])("rejects unsafe authorized_keys mktemp output: %s", async (_caseName, stdout) => {
    const foreignPath = "/tmp/.paratix-authorized-keys.ABCDEF"
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
    expect(mockSsh.calls).not.toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: aliceKeys,
        content: `${testKey}\n`,
        expectedSshDirectoryState: "700 alice alice directory",
        group: "alice",
        sshDirectoryPath: aliceDir,
        temporaryPath: foreignPath,
        user: "alice",
      })
    )
    expect(mockSsh.calls).not.toContain(`rm -f -- '${foreignPath}'`)
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
    const mockSsh = createMockSsh({
      "[ -e '/root/.ssh' ]": { code: 0 },
      "[ -e '/root/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/root/.ssh' ]": { code: 1 },
      "[ -L '/root/.ssh/authorized_keys' ]": { code: 1 },
      [authorizedKeysReadCommand("'/root/.ssh/authorized_keys'")]: authorizedKeysReadResponse(
        `${testKey}\n`
      ),
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

  it("resolves home directory dynamically for non-root user", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh' ]": { code: 1 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [authorizedKeysReadCommand("'/home/deploy/.ssh/authorized_keys'")]:
        authorizedKeysReadResponse(`${testKey}\n`),
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
      [authorizedKeysReadCommand("'/home/my user/.ssh/authorized_keys'")]:
        authorizedKeysReadResponse(`${testKey}\n`),
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
    expect(mockSsh.calls).toContain(
      authorizedKeysReadCommand("'/home/my user/.ssh/authorized_keys'")
    )
  })

  it("regression: home path with spaces is correctly shell-quoted in apply", async () => {
    const spaceyHome = "/home/my user"
    const spaceyMktemp = "mktemp -p '/home/my user/.ssh' -- '.paratix-authorized-keys.XXXXXX'"
    const spaceyTemp = "/home/my user/.ssh/.paratix-authorized-keys.SPACEY"
    const spaceyGuard = sshDirectoryGuardCommand({
      authorizedKeysPath: "'/home/my user/.ssh/authorized_keys'",
      group: "alice",
      sshDirectoryPath: "'/home/my user/.ssh'",
      user: "alice",
    })
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
      [spaceyGuard]: { stdout: "/home/my user/.ssh\n" },
      [spaceyMktemp]: { stdout: spaceyTemp },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // Directory creation must quote the space-containing path.
    // R-0000765: includes the fused authorized_keys symlink probe.
    expect(mockSsh.calls).toContain(spaceyGuard)
    // R-0000181: mktemp must operate inside <home>/.ssh on the destination filesystem.
    expect(mockSsh.calls).toContain(spaceyMktemp)
    // The no-follow read and the staging verification must quote the
    // space-containing path
    expect(mockSsh.calls).toContain(
      authorizedKeysReadCommand("'/home/my user/.ssh/authorized_keys'")
    )
    expect(mockSsh.calls).toContain(
      authorizedKeysStageDecodeCommand({ content: `${testKey}\n`, temporaryPath: spaceyTemp })
    )
    // Chmod must quote the space-containing path
    expect(mockSsh.calls).toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: "'/home/my user/.ssh/authorized_keys'",
        content: `${testKey}\n`,
        expectedSshDirectoryState: "700 alice alice directory",
        group: "alice",
        sshDirectoryPath: "'/home/my user/.ssh'",
        temporaryPath: spaceyTemp,
        user: "alice",
      })
    )
  })

  // R-0000065 regression: when the user's primary group is not equal to the
  // username (e.g. `deploy:users`, a service user like `www-data:www-data`,
  // or an operator in `paratix:wheel`), apply must chown to the user's
  // actual primary group and check must compare against that same group so
  // a stable check-ok state is reachable without overwriting the
  // semantically correct group ownership.
  it("R-0000065: apply uses the user's resolved primary group for chown when it differs from the username", async () => {
    const deployMktemp = "mktemp -p '/home/deploy/.ssh' -- '.paratix-authorized-keys.XXXXXX'"
    const deployTemp = "/home/deploy/.ssh/.paratix-authorized-keys.DEPLOY"
    const deployGuard = sshDirectoryGuardCommand({
      authorizedKeysPath: "'/home/deploy/.ssh/authorized_keys'",
      group: "users",
      sshDirectoryPath: "'/home/deploy/.ssh'",
      user: "deploy",
    })
    const mockSsh = createSshApplyMockSsh({
      [deployGuard]: { stdout: "/home/deploy/.ssh\n" },
      [deployMktemp]: { stdout: deployTemp },
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Directory chown uses the resolved primary group, not the username.
    // R-0000765: includes the fused authorized_keys symlink probe.
    expect(mockSsh.calls).toContain(deployGuard)
    // The authorized_keys chown must also use the resolved primary group.
    expect(mockSsh.calls).toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: "'/home/deploy/.ssh/authorized_keys'",
        content: `${testKey}\n`,
        expectedSshDirectoryState: "700 deploy users directory",
        group: "users",
        sshDirectoryPath: "'/home/deploy/.ssh'",
        temporaryPath: deployTemp,
        user: "deploy",
      })
    )
    // The legacy `${user}:${user}` chown must not be issued.
    expect(mockSsh.calls).not.toContain(
      `mkdir -p '/home/deploy/.ssh' && chmod 700 '/home/deploy/.ssh' && chown 'deploy':'deploy' '/home/deploy/.ssh'`
    )
  })

  it("R-0000065: check returns ok when the primary group differs from the username and matches stat output", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/home/deploy/.ssh' ]": { code: 0 },
      "[ -e '/home/deploy/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/home/deploy/.ssh' ]": { code: 1 },
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [authorizedKeysReadCommand("'/home/deploy/.ssh/authorized_keys'")]:
        authorizedKeysReadResponse(`${testKey}\n`),
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
