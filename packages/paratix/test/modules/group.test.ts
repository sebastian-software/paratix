import { describe, expect, it } from "vitest"

import type { ExecResult } from "../../src/types.js"

import { group } from "../../src/modules/group.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

function createGroupLookupSequenceSsh(
  lookups: Array<Partial<ExecResult>>,
  responses: Parameters<typeof createMockSsh>[0]
): ReturnType<typeof createMockSsh> {
  const ssh = createMockSsh(responses)
  const exec = ssh.exec.bind(ssh)
  ssh.exec = async (command, options) => {
    if (command !== "getent group 'deploy'") return exec(command, options)

    ssh.calls.push(command)
    ssh.execCalls.push({ command, options })
    const lookup = lookups.shift()
    return {
      code: lookup?.code ?? 0,
      stderr: lookup?.stderr ?? "",
      stdout: lookup?.stdout ?? "",
    }
  }
  return ssh
}

describe("group.present", () => {
  it("check returns ok when the group exists (no GID requested)", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
    })
    const mod = group.present("deploy")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the group does not exist", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
    })
    const mod = group.present("deploy")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = group.present("deploy")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000048 regression: when a desired GID is set, check must compare it
  // against the existing GID parsed from `getent group <name>` and report
  // drift on mismatch.
  it("check returns ok when the group exists with the desired GID", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1200:" },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the group exists but the GID differs", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when groupadd succeeds without gid", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
      "groupadd -- 'deploy'": { code: 0 },
    })
    const mod = group.present("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("groupadd -- 'deploy'")
  })

  it("apply returns changed when groupadd succeeds with gid", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
      "groupadd --gid 1200 -- 'deploy'": { code: 0 },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("groupadd --gid 1200 -- 'deploy'")
  })

  it("apply returns failed when groupadd exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
      "groupadd --gid 1200 -- 'deploy'": { code: 1 },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns ok when a parallel run creates the group after the initial probe", async () => {
    const ssh = createGroupLookupSequenceSsh([{ code: 1 }, { code: 0, stdout: "deploy:x:1234:" }], {
      "groupadd -- 'deploy'": { code: 9, stderr: "groupadd: group 'deploy' already exists" },
    })
    const mod = group.present("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls.filter((c) => c === "getent group 'deploy'")).toHaveLength(2)
  })

  it("apply returns ok when a parallel run creates the group with the desired GID", async () => {
    const ssh = createGroupLookupSequenceSsh([{ code: 1 }, { code: 0, stdout: "deploy:x:1200:" }], {
      "groupadd --gid 1200 -- 'deploy'": {
        code: 9,
        stderr: "groupadd: group 'deploy' already exists",
      },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls.some((c) => c.startsWith("groupmod"))).toBe(false)
  })

  it("apply heals GID drift when a parallel run creates the group with the wrong GID", async () => {
    const ssh = createGroupLookupSequenceSsh([{ code: 1 }, { code: 0, stdout: "deploy:x:1234:" }], {
      "groupadd --gid 1200 -- 'deploy'": {
        code: 9,
        stderr: "groupadd: group 'deploy' already exists",
      },
      "groupmod -g 1200 -- 'deploy'": { code: 0 },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("groupmod -g 1200 -- 'deploy'")
  })

  it("apply returns the original groupadd failure when the group is still missing", async () => {
    const ssh = createGroupLookupSequenceSsh([{ code: 1 }, { code: 1 }], {
      "groupadd --gid 1200 -- 'deploy'": { code: 1, stderr: "permission denied" },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls.filter((c) => c === "getent group 'deploy'")).toHaveLength(2)
  })

  // R-0000048 regression: an existing group with a matching GID converges
  // immediately to "ok" — neither groupadd nor groupmod is invoked.
  it("apply returns ok without calling groupadd/groupmod when group exists with matching GID", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1200:" },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls.some((c) => c.startsWith("groupadd"))).toBe(false)
    expect(ssh.calls.some((c) => c.startsWith("groupmod"))).toBe(false)
  })

  // R-0000048 regression: when the group exists with a different GID, apply
  // heals the drift via `groupmod -g <gid>` instead of failing on
  // `groupadd: group already exists`.
  it("apply runs groupmod -g <gid> when group exists with mismatched GID", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
      "groupmod -g 1200 -- 'deploy'": { code: 0 },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("groupmod -g 1200 -- 'deploy'")
    expect(ssh.calls.some((c) => c.startsWith("groupadd"))).toBe(false)
  })

  it("apply returns failed when groupmod exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
      "groupmod -g 1200 -- 'deploy'": { code: 1 },
    })
    const mod = group.present("deploy", { gid: 1200 })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = group.present("deploy")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("uses the expected module name", () => {
    const mod = group.present("deploy")
    expect(mod.name).toBe("group.present: deploy")
  })

  it("throws when the group name is empty", () => {
    expect(() => group.present("")).toThrow("group name")
  })

  it("throws when the group name starts with a flag", () => {
    expect(() => group.present("--badgroup")).toThrow("group name")
  })

  it("throws when the group name contains a newline", () => {
    expect(() => group.present("deploy\nadmin")).toThrow("group name")
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, 2 ** 32])(
    "throws when gid is invalid: %s",
    (gid) => {
      expect(() => group.present("deploy", { gid })).toThrow("gid")
    }
  )
})

describe("group.absent", () => {
  it("check returns needs-apply when the group exists", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0 },
    })
    const mod = group.absent("deploy")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when the group does not exist", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
    })
    const mod = group.absent("deploy")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = group.absent("deploy")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when groupdel succeeds", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
      "groupdel -- 'deploy'": { code: 0 },
    })
    const mod = group.absent("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("groupdel -- 'deploy'")
  })

  it("apply returns failed when groupdel exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
      "groupdel -- 'deploy'": { code: 1 },
    })
    const mod = group.absent("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000080: when the group is already gone, the getent probe must
  // short-circuit so groupdel is never invoked. This mirrors the early
  // return in cron.absent and user.absent (after R-0000077) and prevents
  // apply from reporting failedCommand for an already-satisfied state.
  it("apply returns ok and skips groupdel when the group does not exist", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 1 },
    })
    const mod = group.absent("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls.some((c) => c.startsWith("groupdel"))).toBe(false)
  })

  // R-0000080 defensive fallback: even when the getent probe says the
  // group exists, a concurrent removal can cause groupdel to exit with
  // code 6 ("specified group doesn't exist"). Treat that as idempotent
  // success.
  it("apply returns ok when groupdel exits with code 6 (group already gone)", async () => {
    const ssh = createMockSsh({
      "getent group 'deploy'": { code: 0, stdout: "deploy:x:1234:" },
      "groupdel -- 'deploy'": { code: 6 },
    })
    const mod = group.absent("deploy")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = group.absent("deploy")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("uses the expected module name", () => {
    const mod = group.absent("deploy")
    expect(mod.name).toBe("group.absent: deploy")
  })

  it("throws when the group name is empty", () => {
    expect(() => group.absent("")).toThrow("group name")
  })

  it("throws when the group name starts with a flag", () => {
    expect(() => group.absent("--badgroup")).toThrow("group name")
  })
})
