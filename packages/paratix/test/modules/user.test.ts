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

  it("returns needs-apply when there are extra supplementary groups beyond the desired set", async () => {
    const ssh = createMockSsh({
      "id -Gn 'alice'": { code: 0, stdout: "alice sudo docker" },
      "id -gn 'alice'": { code: 0, stdout: "alice" },
      "id 'alice'": { code: 0 },
    })
    const mod = user.present("alice", { groups: ["sudo"] })
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
  // Bug #8 regression: setPassword must use chpasswd -e for pre-hashed passwords
  it("uses chpasswd -e when setting a pre-hashed password", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "printf '%s\\n' 'alice:$6$hash' | chpasswd -e": { code: 0 },
      "usermod  'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    await mod.apply(ssh, emptyEnv)
    expect(ssh.calls).toContain("printf '%s\\n' 'alice:$6$hash' | chpasswd -e")
  })

  it("apply returns failed when chpasswd -e fails", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "printf '%s\\n' 'alice:$6$hash' | chpasswd -e": { code: 1 },
      "usermod  'alice'": { code: 0 },
    })
    const mod = user.present("alice", { password: "$6$hash" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain("chpasswd -e failed")
  })

  it("does not call chpasswd when no password is set", async () => {
    const ssh = createMockSsh({
      "id 'alice'": { code: 0 },
      "usermod  'alice'": { code: 0 },
    })
    const mod = user.present("alice")
    await mod.apply(ssh, emptyEnv)
    const chpasswdCalled = ssh.calls.some((c) => c.includes("chpasswd"))
    expect(chpasswdCalled).toBe(false)
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
