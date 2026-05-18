import { describe, expect, it } from "vitest"

import { user } from "../../src/modules/user.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("user.present check", () => {
  it("returns needs-apply when the user does not exist", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 1 },
    })
    const mod = user.present("alice")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the user exists and no options are given", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = user.present("alice")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // Bug #7 regression: check must compare uid via getent passwd
  it("returns needs-apply when uid does not match", async () => {
    const ssh = createMockSsh({
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { uid: 9999 })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when uid matches", async () => {
    const ssh = createMockSsh({
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { uid: 1001 })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  // Bug #7 regression: check must compare shell via getent passwd
  it("returns needs-apply when shell does not match", async () => {
    const ssh = createMockSsh({
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { shell: "/bin/bash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when shell matches", async () => {
    const ssh = createMockSsh({
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/bash" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { shell: "/bin/bash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  // Bug #7 regression: check must compare home via getent passwd
  it("returns needs-apply when home directory does not match", async () => {
    const ssh = createMockSsh({
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/srv/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when home directory matches", async () => {
    const ssh = createMockSsh({
      // R-0000656: check now also enforces the home directory mode.
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "700",
      },
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  // Bug #7 regression: check must compare supplementary groups via id -Gn/id -gn
  it("returns needs-apply when groups do not match", async () => {
    const ssh = createMockSsh({
      "id -Gn 'alice'": { code: 0, stdout: "alice sudo" },
      "id -gn 'alice'": { code: 0, stdout: "alice" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["alice", "docker"] })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when supplementary groups match even though the primary group is present in id -Gn", async () => {
    const ssh = createMockSsh({
      "id -Gn 'alice'": { code: 0, stdout: "alice sudo" },
      "id -gn 'alice'": { code: 0, stdout: "alice" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["sudo"] })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000043: groups are additive — extra unrelated memberships beyond
  // the desired set are tolerated, mirroring the `usermod --append --groups`
  // apply path.
  it("returns ok when extra supplementary groups exist beyond the desired set", async () => {
    const ssh = createMockSsh({
      "id -Gn 'alice'": { code: 0, stdout: "alice sudo docker" },
      "id -gn 'alice'": { code: 0, stdout: "alice" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["sudo"] })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when a desired supplementary group is missing", async () => {
    const ssh = createMockSsh({
      "id -Gn 'alice'": { code: 0, stdout: "alice sudo" },
      "id -gn 'alice'": { code: 0, stdout: "alice" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["sudo", "docker"] })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000544: shadow hash comparison is now done server-side via bash -c with
  // cmp -s to avoid sending the raw hash back over stdout. The exec call uses
  // ignoreExitCode:true and returns code 0 for match, non-zero for mismatch.
  it("returns needs-apply when shadow hash does not match password", async () => {
    const compareCommand =
      "bash -c 'set -o pipefail\ncmp -s <(getent shadow '\\''alice'\\'' | cut -d: -f2) -'"
    const ssh = createMockSsh({
      [compareCommand]: { code: 1 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$newhash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when shadow hash matches password", async () => {
    const compareCommand =
      "bash -c 'set -o pipefail\ncmp -s <(getent shadow '\\''alice'\\'' | cut -d: -f2) -'"
    const ssh = createMockSsh({
      [compareCommand]: { code: 0 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000657: cmp exits 1 to signal a clean mismatch. That must remain
  // `needs-apply` so apply runs and updates the hash.
  it("returns needs-apply when cmp reports exit code 1 (clean mismatch)", async () => {
    const compareCommand =
      "bash -c 'set -o pipefail\ncmp -s <(getent shadow '\\''alice'\\'' | cut -d: -f2) -'"
    const ssh = createMockSsh({
      [compareCommand]: { code: 1 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000657: cmp/bash exit codes ≥ 2 signal a toolchain or environmental
  // problem (missing cmp, getent failure, broken process substitution,
  // permission denial reading /etc/shadow). The check must surface a
  // structured failure instead of silently re-running setPassword on every
  // run by reporting `needs-apply`.
  it("throws a toolchain failure when cmp exits with code 2 (hard error)", async () => {
    const compareCommand =
      "bash -c 'set -o pipefail\ncmp -s <(getent shadow '\\''alice'\\'' | cut -d: -f2) -'"
    const ssh = createMockSsh({
      [compareCommand]: { code: 2, stderr: "cmp: invalid option" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    await expect(mod.check(ssh, emptyEnv)).rejects.toThrow(
      /shadow hash comparison toolchain error/v
    )
  })

  // R-0000657: a 127 exit (bash: command not found) must also be classified
  // as a toolchain error, not a hash mismatch.
  it("throws a toolchain failure when bash returns 127 (cmp missing)", async () => {
    const compareCommand =
      "bash -c 'set -o pipefail\ncmp -s <(getent shadow '\\''alice'\\'' | cut -d: -f2) -'"
    const ssh = createMockSsh({
      [compareCommand]: { code: 127, stderr: "bash: cmp: command not found" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    await expect(mod.check(ssh, emptyEnv)).rejects.toThrow(
      /shadow hash comparison toolchain error/v
    )
  })
})

describe("user.present apply", () => {
  // Bug #8 regression: setPassword must use chpasswd -e for pre-hashed passwords.
  // R-0000036 regression: the password hash must be passed via stdin, not as
  // a command-line argument, so it never appears in /var/log/auth.log,
  // ps -ef, or /proc/<pid>/cmdline.
  it("uses chpasswd -e via stdin when setting a pre-hashed password", async () => {
    const ssh = createMockSsh({
      "chpasswd -e": { code: 0 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    await mod.apply(ssh, emptyEnv)

    // The command itself no longer materialises the hash on argv.
    expect(ssh.calls).toContain("chpasswd -e")
    expect(ssh.calls.every((c) => !c.includes("$6$hash"))).toBe(true)

    // The hash is delivered via the input field instead, with the username
    // prefix matching the chpasswd `<user>:<hash>` format.
    const chpasswdCall = ssh.execCalls.find((entry) => entry.command === "chpasswd -e")
    expect(chpasswdCall?.options?.input).toBe("alice:$6$hash\n")
    // The hash is registered as a secret so any failure message is masked.
    expect(chpasswdCall?.options?.secrets).toStrictEqual(["$6$hash"])
  })

  it("apply returns failed and masks the hash when chpasswd -e fails", async () => {
    const ssh = createMockSsh({
      "chpasswd -e": { code: 1, stderr: "stderr referencing $6$hash" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain("chpasswd -e failed")
    // The hash must not appear unredacted in the failure message because
    // user.setPassword passed it as a secret to ssh.exec.
    expect(result.error?.message).not.toContain("$6$hash")
    const commandError = result.error as CommandError
    expect(commandError.fullStderr).not.toContain("$6$hash")
    expect(commandError.fullStdout).not.toContain("$6$hash")
  })

  it("does not call chpasswd when no password is set", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    await mod.apply(ssh, emptyEnv)
    const chpasswdCalled = ssh.calls.some((c) => c.includes("chpasswd"))
    expect(chpasswdCalled).toBe(false)
  })

  // R-0000043 regression: a password-only update must not invoke `usermod`
  // with no flags, because `usermod ${name}` fails with
  // `usermod: no flags given`.
  it("skips the usermod call when only the password changes", async () => {
    const ssh = createMockSsh({
      "chpasswd -e": { code: 0 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    // No usermod invocation must be attempted in the password-only case.
    expect(ssh.calls.some((c) => c.startsWith("usermod"))).toBe(false)
    expect(ssh.calls).toContain("chpasswd -e")
  })

  // R-0000043 regression: when re-applying a user with `groups`, the rendered
  // command must contain `--append` so unrelated supplementary group
  // memberships (sudo, docker, manually added groups) are preserved.
  it("emits usermod --append --groups so existing supplementary groups are preserved", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "usermod --append --groups 'docker,wheel' 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["docker", "wheel"] })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("usermod --append --groups 'docker,wheel' 'alice'")
    // No `usermod --groups ...` without `--append` is rendered.
    const usermodCall = ssh.calls.find((c) => c.startsWith("usermod"))
    expect(usermodCall).toContain("--append")
    expect(usermodCall).toContain("--groups")
  })

  // R-0000043: useradd path must NOT include `--append` (the flag is only
  // valid for usermod, and a freshly created account has no preexisting
  // supplementary memberships to preserve anyway).
  it("does not emit --append when creating a new account with groups via useradd", async () => {
    const ssh = createMockSsh({
      "id 'bob'": { code: 1 },
      "useradd --groups 'docker' --create-home 'bob'": { code: 0 },
    })
    const mod = user.present("bob", { groups: ["docker"] })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    const useraddCall = ssh.calls.find((c) => c.startsWith("useradd"))
    expect(useraddCall).toBeDefined()
    expect(useraddCall).not.toContain("--append")
  })

  it("apply returns changed when user is created successfully", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 1 },
      "useradd  --create-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns needs-apply when ssh is null", async () => {
    const mod = user.present("alice")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[user.present: alice] SSH connection is required")
  })

  // R-0000088 regression: when the user already exists and no options are
  // given, `apply` must return status "ok" (no mutation occurred) instead of
  // falsely reporting "changed". usermod must not be invoked because there
  // are no flags to apply, and useradd must not be invoked because the user
  // exists.
  it("returns ok and skips usermod when user exists and no options are given", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls.some((c) => c.startsWith("usermod"))).toBe(false)
    expect(ssh.calls.some((c) => c.startsWith("useradd"))).toBe(false)
  })

  // R-0000088 regression: when the user does not exist, useradd must run
  // and `apply` must return "changed".
  it("returns changed and invokes useradd when user does not exist", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 1 },
      "useradd  --create-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("useradd  --create-home 'alice'")
  })

  // R-0000088 regression: when the user exists and flags differ, usermod
  // must run and `apply` must return "changed".
  it("returns changed and invokes usermod when user exists and flags differ", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "usermod --shell '/bin/bash' 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { shell: "/bin/bash" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("usermod --shell '/bin/bash' 'alice'")
  })

  // R-0000088 regression: setPassword has no pre-check, so any password
  // invocation counts as a mutation. `apply` must return "changed" even when
  // no usermod/useradd ran.
  it("returns changed when only the password is set on an existing user", async () => {
    const ssh = createMockSsh({
      "chpasswd -e": { code: 0 },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chpasswd -e")
    expect(ssh.calls.some((c) => c.startsWith("usermod"))).toBe(false)
  })
})

describe("user.absent check", () => {
  it("returns needs-apply when the user exists", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
    })
    const mod = user.absent("alice")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the user does not exist", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 1 },
    })
    const mod = user.absent("alice")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })
})

describe("user.absent apply", () => {
  // R-0000077: when the user is already gone, the id probe must
  // short-circuit so userdel is never invoked. This mirrors the early
  // return in cron.absent and prevents apply from reporting
  // failedCommand for an already-satisfied state.
  it("returns ok and skips userdel when the user does not exist", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 1 },
    })
    const mod = user.absent("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("userdel  'alice'")
    expect(ssh.calls).not.toContain("userdel --remove 'alice'")
  })

  it("returns changed when userdel succeeds", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "userdel  'alice'": { code: 0 },
    })
    const mod = user.absent("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("userdel  'alice'")
  })

  // R-0000077 defensive fallback: even when the id probe says the user
  // exists, a concurrent removal can cause userdel to exit with code 6
  // ("specified user doesn't exist"). Treat that as idempotent success.
  it("returns ok when userdel exits with code 6 (user already gone)", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "userdel  'alice'": { code: 6 },
    })
    const mod = user.absent("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns failed when userdel exits with a non-6 non-zero code", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "userdel  'alice'": { code: 1 },
    })
    const mod = user.absent("alice")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when ssh is null", async () => {
    const mod = user.absent("alice")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

// R-0000119: user.present and user.absent must reject names that violate the
// POSIX user-name whitelist before they can reach `useradd`, `usermod`, or
// `userdel`. The validation runs at module-construction time so misuse fails
// fast — long before an SSH connection is opened.
describe("validation", () => {
  it("user.present throws when the name starts with a flag", () => {
    expect(() => user.present("--name")).toThrow("is invalid")
  })

  it("user.present throws when the name is empty", () => {
    expect(() => user.present("")).toThrow("is invalid")
  })

  it("user.present throws when the name contains a space", () => {
    expect(() => user.present("name with space")).toThrow("is invalid")
  })

  it("user.present throws when the name has a leading digit", () => {
    expect(() => user.present("1nval1d")).toThrow("is invalid")
  })

  it("user.present throws when the name contains non-ASCII letters", () => {
    expect(() => user.present("Üser")).toThrow("is invalid")
  })

  it("user.absent throws when the name starts with a flag", () => {
    expect(() => user.absent("--name")).toThrow("is invalid")
  })

  it("user.absent throws when the name is empty", () => {
    expect(() => user.absent("")).toThrow("is invalid")
  })

  it("user.absent throws when the name contains a space", () => {
    expect(() => user.absent("name with space")).toThrow("is invalid")
  })

  it("user.absent throws when the name has a leading digit", () => {
    expect(() => user.absent("1nval1d")).toThrow("is invalid")
  })

  it("user.absent throws when the name contains non-ASCII letters", () => {
    expect(() => user.absent("Üser")).toThrow("is invalid")
  })

  // R-0000120: uid must be a non-negative finite integer below 2^32 — `useradd
  // --uid` would silently truncate larger values and reject NaN with an
  // implementation-defined error message that exposes the raw input.
  it("user.present throws when uid is negative", () => {
    expect(() => user.present("alice", { uid: -1 })).toThrow("uid")
  })

  it("user.present throws when uid is NaN", () => {
    expect(() => user.present("alice", { uid: Number.NaN })).toThrow("uid")
  })

  it("user.present throws when uid is fractional", () => {
    expect(() => user.present("alice", { uid: 1000.5 })).toThrow("uid")
  })

  it("user.present throws when uid is above the uid_t range", () => {
    expect(() => user.present("alice", { uid: 2 ** 32 })).toThrow("uid")
  })

  // R-0000120: a comma in a group name would inject an additional `--groups`
  // entry, and a newline could split the rendered command. Both must be
  // rejected at construction time.
  it("user.present throws when a group name contains a comma", () => {
    expect(() => user.present("alice", { groups: ["sudo,docker"] })).toThrow("group name")
  })

  it("user.present throws when a group name contains a newline", () => {
    expect(() => user.present("alice", { groups: ["sudo\ndocker"] })).toThrow("group name")
  })

  it("user.present throws when a group name is empty", () => {
    expect(() => user.present("alice", { groups: [""] })).toThrow("group name")
  })

  it("user.present throws when a group name starts with a flag", () => {
    expect(() => user.present("alice", { groups: ["--badgroup"] })).toThrow("group name")
  })

  // R-0000226: password hashes are written to `chpasswd -e` via stdin as
  // `<user>:<hash>\n`. Structural separators must be rejected before they can
  // add extra chpasswd entries or alter the field boundary.
  it("user.present throws when a password hash is empty", () => {
    expect(() => user.present("alice", { password: "" })).toThrow("password hash is invalid")
  })

  it("user.present throws when a password hash contains a newline", () => {
    expect(() => user.present("alice", { password: "$6$hash\nbob:$6$other" })).toThrow(
      "password hash"
    )
  })

  it("user.present throws when a password hash contains a carriage return", () => {
    expect(() => user.present("alice", { password: "$6$hash\rbob:$6$other" })).toThrow(
      "password hash"
    )
  })

  it("user.present throws when a password hash contains a colon", () => {
    expect(() => user.present("alice", { password: "$6$hash:extra" })).toThrow("password hash")
  })

  // R-0000652: /etc/passwd is a colon-separated record terminated by a
  // newline. A newline or colon embedded in --shell would split the passwd
  // entry and corrupt the file format. useradd performs no such check itself,
  // so reject control characters and non-absolute paths at construction time.
  it("user.present throws when shell contains a newline", () => {
    expect(() => user.present("alice", { shell: "/bin/bash\nfoo" })).toThrow("shell path")
  })

  it("user.present throws when shell contains a carriage return", () => {
    expect(() => user.present("alice", { shell: "/bin/bash\rfoo" })).toThrow("shell path")
  })

  it("user.present throws when shell contains a colon", () => {
    expect(() => user.present("alice", { shell: "/bin/bash:extra" })).toThrow("shell path")
  })

  it("user.present throws when shell is not an absolute path", () => {
    expect(() => user.present("alice", { shell: "bin/bash" })).toThrow("shell path")
  })

  // R-0000652: home directories share the same passwd-record constraint as
  // shell paths; control characters or relative paths must be rejected before
  // they reach useradd/usermod.
  it("user.present throws when home contains a newline", () => {
    expect(() => user.present("alice", { home: "/home/alice\nfoo" })).toThrow("home path")
  })

  it("user.present throws when home contains a carriage return", () => {
    expect(() => user.present("alice", { home: "/home/alice\rfoo" })).toThrow("home path")
  })

  it("user.present throws when home contains a colon", () => {
    expect(() => user.present("alice", { home: "/home/alice:extra" })).toThrow("home path")
  })

  it("user.present throws when home is not an absolute path", () => {
    expect(() => user.present("alice", { home: "home/alice" })).toThrow("home path")
  })

  // R-0000656: homeMode without home cannot be applied (we would not know
  // which path to chmod), so reject the orphan combination up front.
  it("user.present throws when homeMode is set without home", () => {
    expect(() => user.present("alice", { homeMode: "0700" })).toThrow(
      "homeMode requires home to be set"
    )
  })

  it("user.present throws when homeMode contains non-octal digits", () => {
    expect(() => user.present("alice", { home: "/home/alice", homeMode: "0800" })).toThrow(
      "home mode"
    )
  })

  it("user.present throws when homeMode has the wrong length", () => {
    expect(() => user.present("alice", { home: "/home/alice", homeMode: "00700" })).toThrow(
      "home mode"
    )
  })

  it("user.present throws when homeMode contains letters", () => {
    expect(() => user.present("alice", { home: "/home/alice", homeMode: "rwx" })).toThrow(
      "home mode"
    )
  })
})

// R-0000656: when `home` is updated on an existing account, `usermod` must
// receive `--move-home` so the old contents follow the user to the new
// location. Without the flag the passwd entry is rewritten but the previous
// home (with all its dot-files) is left behind. The home mode is also
// enforced post-mutation so the result does not depend on the runner host's
// HOME_MODE setting in /etc/login.defs.
describe("user.present home migration and mode (R-0000656)", () => {
  it("emits usermod --home with --move-home so existing home contents follow the user", async () => {
    const ssh = createMockSsh({
      // chmod runs after usermod regardless of pre-check (stat fails -> mismatch),
      // so include the chmod stub for the default 0700 mode.
      "[ ! -L '/srv/alice' ] && [ -d '/srv/alice' ] && chmod '0700' '/srv/alice'": { code: 0 },
      // R-0000822: chmod is wrapped in pre/post stat probes that verify
      // the home directory's inode identity did not change. Stub both
      // probes with the same identity so the verification succeeds.
      "[ ! -L '/srv/alice' ] && [ -d '/srv/alice' ] && stat -c '%a' '/srv/alice'": { code: 1 },
      "[ ! -L '/srv/alice' ] && [ -d '/srv/alice' ] && stat -c '%d:%i' '/srv/alice'": {
        code: 0,
        stdout: "64769:1234\n",
      },
      "id 'alice'": { code: 0 },
      "usermod --home '/srv/alice' --move-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/srv/alice" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("usermod --home '/srv/alice' --move-home 'alice'")
  })

  it("does not emit --move-home when creating a new account with home via useradd", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/srv/bob' ] && [ -d '/srv/bob' ] && chmod '0700' '/srv/bob'": { code: 0 },
      "[ ! -L '/srv/bob' ] && [ -d '/srv/bob' ] && stat -c '%a' '/srv/bob'": {
        code: 0,
        stdout: "755",
      },
      // R-0000822: pre/post-chmod inode-identity probes
      "[ ! -L '/srv/bob' ] && [ -d '/srv/bob' ] && stat -c '%d:%i' '/srv/bob'": {
        code: 0,
        stdout: "64769:2345\n",
      },
      "id 'bob'": { code: 1 },
      "useradd --home '/srv/bob' --create-home 'bob'": { code: 0 },
    })
    const mod = user.present("bob", { home: "/srv/bob" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    const useraddCall = ssh.calls.find((c) => c.startsWith("useradd"))
    expect(useraddCall).toBeDefined()
    expect(useraddCall).not.toContain("--move-home")
  })

  it("runs chmod with default mode 0700 after useradd when home is set", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0700' '/home/alice'": { code: 0 },
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "755",
      },
      // R-0000822: pre/post-chmod inode-identity probes
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%d:%i' '/home/alice'": {
        code: 0,
        stdout: "64769:3456\n",
      },
      "id 'alice'": { code: 1 },
      "useradd --home '/home/alice' --create-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0700' '/home/alice'"
    )
  })

  it("runs chmod with the explicit homeMode when provided", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0750' '/home/alice'": { code: 0 },
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "755",
      },
      // R-0000822: pre/post-chmod inode-identity probes
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%d:%i' '/home/alice'": {
        code: 0,
        stdout: "64769:4567\n",
      },
      "id 'alice'": { code: 1 },
      "useradd --home '/home/alice' --create-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice", homeMode: "0750" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0750' '/home/alice'"
    )
  })

  it("returns failed when chmod on the home directory fails", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0700' '/home/alice'": {
        code: 1,
        stderr: "chmod: cannot access",
      },
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": { code: 1 },
      // R-0000822: pre-stat must succeed to reach the chmod step.
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%d:%i' '/home/alice'": {
        code: 0,
        stdout: "64769:5678\n",
      },
      "id 'alice'": { code: 1 },
      "useradd --home '/home/alice' --create-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("chmod home failed")
  })

  it("skips the chmod call when the current home mode already matches the default", async () => {
    // Apply path: user exists. Because `home` is set, usermod runs with
    // --home/--move-home, then the home mode is checked. With stat
    // reporting 700, chmod must NOT run and the post-mutation result is
    // "changed" because usermod itself was invoked.
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "700",
      },
      "id 'alice'": { code: 0 },
      "usermod --home '/home/alice' --move-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls.some((c) => c.includes("chmod"))).toBe(false)
  })

  it("check returns needs-apply when the home mode does not match the default", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "755",
      },
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when the home mode matches the default 0700", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 0,
        stdout: "700",
      },
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when stat reports a missing home directory", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 1,
        stderr: "No such file",
      },
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000778: `homeModeMatches` must refuse to follow a symlink at the home
  // path. The guard `[ ! -L <home> ]` returns false when the path is a
  // symlink, which yields `needs-apply` instead of comparing a target's mode
  // and silently treating the user as "ok".
  it("R-0000778: check returns needs-apply when the home path is a symlink", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 1,
      },
      "getent passwd 'alice'": { code: 0, stdout: "alice:x:1001:1001::/home/alice:/bin/sh" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000778: `applyHomeMode` must refuse to chmod a symlinked home so a
  // race that swaps the home for a symlink to `/etc` between the
  // pre-check and the chmod cannot clobber the target's permissions.
  it("R-0000778: apply returns failed when chmod refuses a symlinked home", async () => {
    const ssh = createMockSsh({
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && chmod '0700' '/home/alice'": {
        code: 1,
        stderr: "[: not a directory",
      },
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%a' '/home/alice'": {
        code: 1,
      },
      // R-0000822: the pre-stat probe uses the same `[ ! -L ] && [ -d ]`
      // guard as chmod, so it also fails for a symlinked home. The
      // failure surfaces as `chmod home failed: pre-stat failed`, which
      // keeps the assertion below intact.
      "[ ! -L '/home/alice' ] && [ -d '/home/alice' ] && stat -c '%d:%i' '/home/alice'": {
        code: 1,
        stderr: "[: not a directory",
      },
      "id 'alice'": { code: 0 },
      "usermod --home '/home/alice' --move-home 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { home: "/home/alice" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("chmod home failed")
  })
})
