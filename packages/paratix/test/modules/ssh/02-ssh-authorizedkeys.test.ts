/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const successfulSshApplyOptions: MockSshOptions = {
  responseStubs: [
    { command: "mkdir -p ~/.ssh && chmod 700 ~/.ssh", result: { code: 0 } },
    { command: /^ssh-keygen -F '[^']+'$/v, result: { code: 1 } },
    { command: /^ssh-keygen -R '[^']+'$/v, result: { code: 0 } },
    {
      command: /^printf '%s\\n' '[^']+' >> ~\/\.ssh\/known_hosts$/v,
      result: { code: 0 },
    },
    {
      command:
        /^\[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must not be a symlink' >&2; exit 1; \}; if \[ -e '[^']+\/\.ssh' \]; then \[ -d '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a directory' >&2; exit 1; \}; else mkdir -p '[^']+\/\.ssh'; fi; \[ -d '[^']+\/\.ssh' \] && \[ ! -L '[^']+\/\.ssh' \] \|\| \{ echo '\.ssh must be a real directory' >&2; exit 1; \}; chmod 700 '[^']+\/\.ssh' && chown '[^']+':'[^']+' '[^']+\/\.ssh'$/v,
      result: { code: 0 },
    },
    {
      command:
        /^\[ ! -L '[^']+\/\.ssh\/authorized_keys' \] \|\| \{ echo 'authorized_keys must not be a symlink' >&2; exit 1; \}$/v,
      result: { code: 0 },
    },
    {
      command: /^\{ if \[ -f '[^']+\/\.ssh\/authorized_keys' \]; then .+; fi; \}$/v,
      result: { code: 0 },
    },
    {
      command: /^chmod 600 '[^']+\/\.ssh\/\.paratix-authorized-keys\.[^']+' && chown /v,
      result: { code: 0 },
    },
    {
      command: /^rm -f '[^']+\/\.ssh\/\.paratix-authorized-keys\.[^']+'$/v,
      result: { code: 0 },
    },
    {
      command: /^mktemp '[^']+\/\.ssh\/\.paratix-authorized-keys\.X{6}'$/v,
      result: { stdout: "/home/alice/.ssh/.paratix-authorized-keys.STUB" },
    },
  ],
}

function createSshApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulSshApplyOptions)
}

const emptyEnv = {}

// Helper used by R-0000044 regression: locate the authorized_keys rewrite
// command (the one that pipes grep into the staging path). Lifted out of
// the test body so eslint-plugin-jest's `no-conditional-in-test` rule
// does not flag the predicate.
function includesGrepRewrite(command: string): boolean {
  return command.includes(" > '") && command.includes("grep")
}

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

function presentAuthorizedKeysRewriteCommand(
  authorizedKeysPath: string,
  temporaryPath: string,
  key: string
): string {
  return `{ if [ -f ${authorizedKeysPath} ]; then awk '1' ${authorizedKeysPath} > '${temporaryPath}' || exit $?; grep -qxF -- '${key}' ${authorizedKeysPath}; grep_status=$?; if [ "$grep_status" -eq 0 ]; then :; elif [ "$grep_status" -eq 1 ]; then printf '%s\\n' '${key}' >> '${temporaryPath}'; else exit "$grep_status"; fi; else printf '%s\\n' '${key}' > '${temporaryPath}'; fi; }`
}

function absentAuthorizedKeysRewriteCommand(
  authorizedKeysPath: string,
  temporaryPath: string,
  key: string
): string {
  return `{ if [ -f ${authorizedKeysPath} ]; then grep -vxF -- '${key}' ${authorizedKeysPath} > '${temporaryPath}'; grep_status=$?; if [ "$grep_status" -eq 0 ] || [ "$grep_status" -eq 1 ]; then :; else exit "$grep_status"; fi; else : > '${temporaryPath}'; fi; }`
}

function authorizedKeysFinalReplaceCommand(parameters: {
  authorizedKeysPath: string
  expectedSshDirectoryState: string
  group: string
  sshDirectoryPath: string
  temporaryPath: string
  user: string
}): string {
  const {
    authorizedKeysPath,
    expectedSshDirectoryState,
    group,
    sshDirectoryPath,
    temporaryPath,
    user,
  } = parameters
  return `chmod 600 '${temporaryPath}' && chown '${user}':'${group}' '${temporaryPath}' && { [ ! -L ${sshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; [ -d ${sshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }; ssh_directory_state=$(stat -c '%a %U %G %F' ${sshDirectoryPath}) || exit $?; [ "$ssh_directory_state" = '${expectedSshDirectoryState}' ] || { echo '.ssh ownership changed before authorized_keys replace' >&2; exit 1; }; [ ! -L ${authorizedKeysPath} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }; if [ -e ${authorizedKeysPath} ]; then [ -f ${authorizedKeysPath} ] || { echo 'authorized_keys must be a regular file' >&2; exit 1; }; rm -f -- ${authorizedKeysPath}; fi; mv -T -n -- '${temporaryPath}' ${authorizedKeysPath} || { echo 'authorized_keys was recreated during replace; refusing to clobber' >&2; exit 1; }; }`
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
  // R-0000181: temp file lives in <home>/.ssh on the destination filesystem
  // so `mv -T` is atomic (single rename(2)) and avoids cross-FS copies.
  const aliceMktempPattern = "mktemp '/home/alice/.ssh/.paratix-authorized-keys.XXXXXX'"
  const tempPath = "/home/alice/.ssh/.paratix-authorized-keys.ABCDEF"
  const aliceSshDirectoryGuard =
    "[ ! -L '/home/alice/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/alice/.ssh' ]; then [ -d '/home/alice/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/alice/.ssh'; fi; [ -d '/home/alice/.ssh' ] && [ ! -L '/home/alice/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/alice/.ssh' && chown 'alice':'alice' '/home/alice/.ssh'"
  const aliceFinalReplaceCommand = authorizedKeysFinalReplaceCommand({
    authorizedKeysPath: aliceKeys,
    expectedSshDirectoryState: "700 alice alice directory",
    group: "alice",
    sshDirectoryPath: aliceDir,
    temporaryPath: tempPath,
    user: "alice",
  })

  function aliceResponses(
    extra?: Record<string, Partial<{ code: number; stderr: string; stdout: string }>>
  ) {
    return {
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

  it("check returns ok when key exists in authorized_keys (state: present)", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
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
    expect(mockSsh.calls).not.toContain(`grep -qxF -- '${testKey}' ${aliceKeys}`)
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
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 1 },
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
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when .ssh ownership or mode has drifted", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
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
    expect(mockSsh.calls).toContain(aliceSshDirectoryGuard)
    expect(mockSsh.calls).toContain(
      `[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`
    )
    expect(mockSsh.calls).toContain(aliceMktempPattern)
    expect(mockSsh.calls).toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
    expect(mockSsh.calls).not.toContain(`printf '%s\\n' '${testKey}' >> ${aliceKeys}`)
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(`rm -f '${tempPath}'`)
  })

  it("regression: apply does not append a duplicate key when only permissions have drifted", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        "[ -e '/home/alice/.ssh' ]": { code: 0 },
        "[ -e '/home/alice/.ssh/authorized_keys' ]": { code: 0 },
        "[ -L '/home/alice/.ssh/authorized_keys' ]": { code: 1 },
        [`grep -qxF -- '${testKey}' ${aliceKeys}`]: { code: 0 },
        [aliceMktempPattern]: { stdout: tempPath },
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
    expect(mockSsh.calls).toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
    expect(mockSsh.calls).not.toContain(
      `{ if [ -f ${aliceKeys} ]; then cat ${aliceKeys}; fi; printf '%s\\n' '${testKey}'; } > '${tempPath}'`
    )
  })

  it("regression: present rewrite terminates existing authorized_keys before appending", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.calls).toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
  })

  it("regression: present rewrite fails closed when reading authorized_keys fails", async () => {
    const rewriteCommand = presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [rewriteCommand]: { code: 2, stderr: "awk: read error" },
      }),
      { ...successfulSshApplyOptions, rejectNonZeroExit: true }
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("awk: read error")
    expect(mockSsh.calls).toContain(rewriteCommand)
    expect(mockSsh.calls).not.toContain(aliceFinalReplaceCommand)
  })

  it("apply removes key with grep -vxF and preserves filter errors (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // R-0000044: whole-line match so an entry whose body is a substring of
    // an unrelated authorized_keys line is not collateral-damage-deleted.
    expect(mockSsh.calls).toContain(
      absentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
  })

  it("regression: absent rewrite fails closed on grep errors and does not replace the target", async () => {
    const rewriteCommand = absentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
        [rewriteCommand]: { code: 2, stderr: "grep: read error" },
      }),
      { ...successfulSshApplyOptions, rejectNonZeroExit: true }
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })

    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("grep: read error")
    expect(mockSsh.calls).toContain(rewriteCommand)
    expect(mockSsh.calls).not.toContain(aliceFinalReplaceCommand)
  })

  // R-0000044: in real life, a `grep -vF -- '<key body>'` filter matches any
  // line containing the key body as a substring — this is wrong when the same
  // key body also appears in another entry that has an `options=...` prefix or
  // a different comment. The fix is `grep -vxF` (whole-line). This regression
  // test asserts the absent path renders the whole-line filter, never the
  // substring filter.
  it("regression: absent apply uses whole-line filter so it cannot delete keys that share a substring", async () => {
    const exactKeyToRemove = testKey
    const collateralEntry = `command="/usr/bin/restricted" ${testKey}`

    // Sanity: in the unfixed implementation, `grep -vF -- '<body>' ...` would
    // also match the collateral entry because it contains `<body>` as a
    // substring. The fixed implementation uses `grep -vxF` (whole-line),
    // which only matches the exact `exactKeyToRemove` line.
    expect(collateralEntry.includes(testKey)).toBe(true)
    expect(collateralEntry).not.toBe(exactKeyToRemove)

    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", exactKeyToRemove, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // The rendered command must use `grep -vxF`, never the broader `grep -vF`.
    const rewriteCall = mockSsh.calls.find(includesGrepRewrite)
    expect(rewriteCall).toBeDefined()
    expect(rewriteCall).toContain("grep -vxF")
    expect(rewriteCall).not.toMatch(/grep -vF\s/v)
  })

  it("regression: apply resets ownership and mode after removing a key (state: absent)", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
  })

  it("returns failed when authorized_keys is a symlink", async () => {
    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const mockSsh = createMockSsh(
      aliceResponses({
        [`[ ! -L ${aliceKeys} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`]:
          {
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

  // R-0000285: harden the final rename against a symlink race. When the
  // shell pipeline as a whole reports failure (e.g. because `mv -T -n`
  // refused to clobber a recreated symlink), apply must surface a
  // structured failure rather than letting the mutation throw.
  it("R-0000285: returns failed when authorized_keys was recreated as a symlink during replace", async () => {
    const mockSsh = createMockSsh(
      aliceResponses({
        [aliceFinalReplaceCommand]: {
          code: 1,
          stderr: "authorized_keys was recreated during replace; refusing to clobber",
        },
        [aliceMktempPattern]: { stdout: tempPath },
      }),
      successfulSshApplyOptions
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("authorized_keys was recreated during replace")
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
  })

  it("returns failed when .ssh is a symlink before chmod, chown, mktemp, or rewrite", async () => {
    // R-0000244: mutation failures surface as a structured `failed`
    // ModuleResult instead of an unstructured exception.
    const mockSsh = createMockSsh(
      aliceResponses({
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
    expect(mockSsh.calls).not.toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
    expect(mockSsh.calls).not.toContain(aliceFinalReplaceCommand)
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
    expect(mockSsh.calls).toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, tempPath, testKey)
    )
    expect(mockSsh.calls).toContain(aliceFinalReplaceCommand)
    expect(mockSsh.calls).toContain(`rm -f '${tempPath}'`)
  })

  // R-0000181: temp file must live in <home>/.ssh, on the same filesystem
  // as authorized_keys, so `mv -T` is atomic instead of a cross-FS copy
  // that loses owner/mode and breaks under NFS root_squash.
  it("stages the authorized_keys rewrite inside <home>/.ssh on the destination filesystem", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
      })
    )
    const mod = ssh.authorizedKeys("alice", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(aliceMktempPattern)
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

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Unexpected mktemp output")
    expect(mockSsh.calls).not.toContain(
      presentAuthorizedKeysRewriteCommand(aliceKeys, foreignPath, testKey)
    )
    expect(mockSsh.calls).not.toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: aliceKeys,
        expectedSshDirectoryState: "700 alice alice directory",
        group: "alice",
        sshDirectoryPath: aliceDir,
        temporaryPath: foreignPath,
        user: "alice",
      })
    )
    expect(mockSsh.calls).not.toContain(`rm -f '${foreignPath}'`)
  })

  it("stages absent-state rewrites inside <home>/.ssh as well", async () => {
    const mockSsh = createSshApplyMockSsh(
      aliceResponses({
        [aliceMktempPattern]: { stdout: tempPath },
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

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "[ssh.authorizedKeys: ghost] failed to resolve a safe home directory"
    )
    expect(mockSsh.calls).not.toContain(
      "mkdir -p '/.ssh' && chmod 700 '/.ssh' && chown 'ghost':'ghost' '/.ssh'"
    )
    expect(mockSsh.calls).not.toContain(
      "[ ! -L '/.ssh/authorized_keys' ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }"
    )
  })

  it("resolves home directory dynamically for root user", async () => {
    const mockSsh = createMockSsh({
      "[ -e '/root/.ssh' ]": { code: 0 },
      "[ -e '/root/.ssh/authorized_keys' ]": { code: 0 },
      "[ -L '/root/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/root/.ssh/authorized_keys'`]: { code: 0 },
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
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/deploy/.ssh/authorized_keys'`]: { code: 0 },
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
      "[ -L '/home/my user/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`]: { code: 0 },
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
      `grep -qxF -- '${testKey}' '/home/my user/.ssh/authorized_keys'`
    )
  })

  it("regression: home path with spaces is correctly shell-quoted in apply", async () => {
    const spaceyHome = "/home/my user"
    const spaceyMktemp = "mktemp '/home/my user/.ssh/.paratix-authorized-keys.XXXXXX'"
    const spaceyTemp = "/home/my user/.ssh/.paratix-authorized-keys.SPACEY"
    const mockSsh = createSshApplyMockSsh({
      "getent passwd 'alice' | cut -d: -f6": { stdout: spaceyHome },
      "id -gn 'alice'": { stdout: "alice" },
      [spaceyMktemp]: { stdout: spaceyTemp },
    })
    const mod = ssh.authorizedKeys("alice", testKey)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    // Directory creation must quote the space-containing path
    expect(mockSsh.calls).toContain(
      `[ ! -L '/home/my user/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/my user/.ssh' ]; then [ -d '/home/my user/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/my user/.ssh'; fi; [ -d '/home/my user/.ssh' ] && [ ! -L '/home/my user/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/my user/.ssh' && chown 'alice':'alice' '/home/my user/.ssh'`
    )
    // R-0000181: mktemp must operate inside <home>/.ssh on the destination filesystem.
    expect(mockSsh.calls).toContain(spaceyMktemp)
    // Temp rewrite command must quote the space-containing path
    expect(mockSsh.calls).toContain(
      presentAuthorizedKeysRewriteCommand(
        "'/home/my user/.ssh/authorized_keys'",
        spaceyTemp,
        testKey
      )
    )
    // Chmod must quote the space-containing path
    expect(mockSsh.calls).toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: "'/home/my user/.ssh/authorized_keys'",
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
    const deployMktemp = "mktemp '/home/deploy/.ssh/.paratix-authorized-keys.XXXXXX'"
    const deployTemp = "/home/deploy/.ssh/.paratix-authorized-keys.DEPLOY"
    const mockSsh = createSshApplyMockSsh({
      [deployMktemp]: { stdout: deployTemp },
      "getent passwd 'deploy' | cut -d: -f6": { stdout: "/home/deploy" },
      "id -gn 'deploy'": { stdout: "users" },
    })
    const mod = ssh.authorizedKeys("deploy", testKey)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Directory chown uses the resolved primary group, not the username.
    expect(mockSsh.calls).toContain(
      `[ ! -L '/home/deploy/.ssh' ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e '/home/deploy/.ssh' ]; then [ -d '/home/deploy/.ssh' ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p '/home/deploy/.ssh'; fi; [ -d '/home/deploy/.ssh' ] && [ ! -L '/home/deploy/.ssh' ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 '/home/deploy/.ssh' && chown 'deploy':'users' '/home/deploy/.ssh'`
    )
    // The authorized_keys chown must also use the resolved primary group.
    expect(mockSsh.calls).toContain(
      authorizedKeysFinalReplaceCommand({
        authorizedKeysPath: "'/home/deploy/.ssh/authorized_keys'",
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
      "[ -L '/home/deploy/.ssh/authorized_keys' ]": { code: 1 },
      [`grep -qxF -- '${testKey}' '/home/deploy/.ssh/authorized_keys'`]: { code: 0 },
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
