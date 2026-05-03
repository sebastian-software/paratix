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

  it("returns needs-apply when shadow hash does not match password", async () => {
    const ssh = createMockSsh({
      "getent shadow 'alice'": { code: 0, stdout: "alice:$6$oldhash:19000:0:99999:7:::" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$newhash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when shadow hash matches password", async () => {
    const ssh = createMockSsh({
      "getent shadow 'alice'": { code: 0, stdout: "alice:$6$hash:19000:0:99999:7:::" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
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
})
