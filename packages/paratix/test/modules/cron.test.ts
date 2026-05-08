import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import { cron } from "../../src/modules/cron.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

/**
 * R-0000168: replicate the marker comment cron.ts writes (legacy form
 * `# paratix: <name>` plus the sha256-tagged form). Tests stub the tagged
 * form so direct checks see the same marker the module emits on apply.
 *
 * @param name - Logical job name written into the marker comment.
 * @param cronJob - The crontab line whose digest the marker records.
 * @returns The full sha256-tagged marker line.
 */
function taggedMarker(name: string, cronJob: string): string {
  const digest = createHash("sha256").update(cronJob).digest("hex")
  return `# paratix: ${name} sha256=${digest}`
}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: /^crontab -u '[^']+' /v, result: { code: 0 } },
    ],
  })

type MockSsh = ReturnType<typeof createMockSsh>

function findCrontabWriteCall(mockSsh: MockSsh) {
  return mockSsh.execCalls.find((call) => /^crontab -u '[^']+' -$/v.test(call.command))
}

function findCrontabWriteInput(mockSsh: MockSsh): string | undefined {
  return findCrontabWriteCall(mockSsh)?.options?.input
}

const emptyEnv = {}

const crontabWriteFailureStub = {
  command: "crontab -u 'alice' -",
  result: { code: 1, stderr: "install failed\n" },
}

describe("cron.job", () => {
  // ---------------------------------------------------------------------------
  // check (state: present)
  // ---------------------------------------------------------------------------

  it("check returns ok when marker and correct job line exist (state: present)", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", job)}\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000168: legacy markers (without the sha256 tag) must trigger
  // needs-apply during check so apply can refresh the marker line into
  // the tagged form on disk.
  it("check returns needs-apply when marker is legacy form without hash tag", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `# paratix: backup\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when no crontab exists (exit code 1) (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "no crontab for alice\n", stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when marker is missing (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check throws when crontab cannot be read (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(/failed to read crontab/v)
  })

  it("check returns needs-apply when marker exists but job line differs (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null (state: present)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // ---------------------------------------------------------------------------
  // check (state: absent)
  // ---------------------------------------------------------------------------

  it("check returns ok when marker is not found (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when no crontab exists (exit code 1) (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "no crontab for alice\n", stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when marker is found (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // ---------------------------------------------------------------------------
  // apply (state: present)
  // ---------------------------------------------------------------------------

  it("apply appends marker and job to empty crontab (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "no crontab for alice\n", stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = findCrontabWriteCall(mockSsh)
    expect(writeCall?.command).toBe("crontab -u 'alice' -")
    expect(writeCall?.options).toMatchObject({ silent: true })
    expect(writeCall?.options?.input).toContain("# paratix: backup")
    expect(writeCall?.options?.input).toContain("0 3 * * * /backup.sh")
  })

  it("regression — writes crontab content via stdin instead of exposing secrets in the command", async () => {
    const secret = "token=super-secret-value"
    const job = `0 3 * * * curl -H 'Authorization: Bearer ${secret}' https://example.test/backup`
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "no crontab for alice\n", stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const writeCall = findCrontabWriteCall(mockSsh)
    expect(writeCall?.command).toBe("crontab -u 'alice' -")
    expect(writeCall?.command).not.toContain(secret)
    expect(writeCall?.options?.input).toContain(secret)
    expect(mockSsh.calls.some((call) => call.includes(secret))).toBe(false)
  })

  it("apply throws when crontab cannot be read (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(/failed to read crontab/v)
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })

  it("apply returns failed when installing a present crontab fails", async () => {
    // R-0000157: crontab install errors (invalid syntax, permission denied,
    // missing user) must surface as a failedCommand result with masked
    // stdout/stderr instead of an uncaught CommandError exception.
    const mockSsh = createMockSsh(
      {
        "crontab -u 'alice' -l": {
          code: 0,
          stdout: "0 5 * * * /other.sh\n",
        },
      },
      {
        responseStubs: [crontabWriteFailureStub],
      }
    )
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[cron.job: backup (alice)] crontab removal failed (exit code 1)"
    )
    expect(result.error?.message).toContain("install failed")
    const writeCall = findCrontabWriteCall(mockSsh)
    expect(writeCall).toBeDefined()
    expect(writeCall?.command).toBe("crontab -u 'alice' -")
    expect(writeCall?.options?.ignoreExitCode).toBe(true)
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("0 5 * * * /other.sh")
    expect(writeInput).toContain("# paratix: backup")
    expect(writeInput).toContain("0 3 * * * /backup.sh")
  })

  it("apply returns failed when crontab rejects invalid syntax (state: present)", async () => {
    // R-0000157: simulate `crontab -u alice -` rejecting an invalid crontab
    // (e.g. syntax error). The module must report failed with the stderr
    // surfaced through the failedCommand path, not throw.
    const mockSsh = createMockSsh(
      {
        "crontab -u 'alice' -l": {
          code: 0,
          stdout: "0 5 * * * /other.sh\n",
        },
      },
      {
        responseStubs: [
          {
            command: "crontab -u 'alice' -",
            result: {
              code: 1,
              stderr: 'errors in crontab file, can\'t install.\n"-":1: bad minute\n',
            },
          },
        ],
      }
    )
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("crontab removal failed (exit code 1)")
    expect(result.error?.message).toContain("errors in crontab file")
  })

  it("apply appends marker and job to existing crontab with other entries (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("0 5 * * * /other.sh")
    expect(writeInput).toContain("# paratix: backup")
    expect(writeInput).toContain("0 3 * * * /backup.sh")
  })

  it("apply returns ok and does not write when marker and job line already match (state: present)", async () => {
    // R-0000081: when the marker exists and the following line already
    // equals the desired cron job, apply must short-circuit, return
    // status ok, and skip the crontab write so direct apply invocations
    // (e.g. via signal targets) do not report spurious "changed". Mirrors
    // the no-op returns that R-0000075 added to file.replace.apply and
    // R-0000077 added to user.absent.apply.
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", job)}\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })

  // R-0000168: when the on-disk marker is the legacy untagged form, apply
  // rewrites the crontab so the marker gains the sha256 tag.
  it("apply rewrites legacy marker into tagged form (state: present)", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `# paratix: backup\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain(taggedMarker("backup", job))
    expect(writeInput).toContain(job)
  })

  it("apply replaces job line when marker exists but job differs (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("# paratix: backup")
    expect(writeInput).toContain("0 3 * * * /backup.sh")
    expect(writeInput).not.toContain("0 5 * * * /backup.sh")
  })

  it("apply returns failed when ssh is null (state: present)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // ---------------------------------------------------------------------------
  // apply (state: absent)
  // ---------------------------------------------------------------------------

  it("apply removes marker and job from crontab (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("# paratix: backup")
    expect(writeInput).not.toContain("0 3 * * * /backup.sh")
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  it("apply returns ok when marker is not found (nothing to remove) (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })

  it("apply removes crontab entirely when last job is removed (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })

  it("apply returns failed when crontab removal fails (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
      "crontab -u 'alice' -r": {
        code: 1,
        stderr: "permission denied",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[cron.job: backup (alice)] crontab removal failed (exit code 1)"
    )
    expect(result.error?.message).toContain("permission denied")
  })

  // R-0000227: `crontab -r` exits non-zero ("no crontab for <user>") when the
  // crontab is already empty. That outcome already matches the desired state,
  // so writeCrontab must report success instead of failedCommand.
  it("R-0000227: tolerates crontab -r exiting non-zero with 'no crontab for'", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
      "crontab -u 'alice' -r": {
        code: 1,
        stderr: "no crontab for alice\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
  })

  it("apply returns failed when installing a non-empty absent crontab fails", async () => {
    // R-0000157: crontab install errors must surface as failedCommand even
    // on the absent path so callers see a maskable failure result instead
    // of an uncaught exception.
    const mockSsh = createMockSsh(
      {
        "crontab -u 'alice' -l": {
          code: 0,
          stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
        },
      },
      {
        responseStubs: [crontabWriteFailureStub],
      }
    )
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("install failed")
    const writeCall = findCrontabWriteCall(mockSsh)
    expect(writeCall).toBeDefined()
    expect(writeCall?.command).toBe("crontab -u 'alice' -")
    expect(writeCall?.options?.ignoreExitCode).toBe(true)
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("0 5 * * * /other.sh")
    expect(writeInput).not.toContain("# paratix: backup")
    expect(writeInput).not.toContain("0 3 * * * /backup.sh")
  })

  it("apply returns failed when ssh is null (state: absent)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // ---------------------------------------------------------------------------
  // name
  // ---------------------------------------------------------------------------

  it("has correct name format: cron.job: <name> (<user>)", () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    expect(mod.name).toBe("cron.job: backup (alice)")
  })

  // ---------------------------------------------------------------------------
  // edge cases
  // ---------------------------------------------------------------------------

  it("check returns needs-apply when marker is last line without job line", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 0, stdout: "# paratix: backup\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    expect(await mod.check(mockSsh, emptyEnv)).toBe("needs-apply")
  })

  // R-0000047 regression: a `present` apply must not silently overwrite a
  // user-authored line that ended up between the marker and the previous
  // job. The line at marker+1 is only replaced when it actually looks like
  // a cron job (non-empty, non-comment). Otherwise the new job is spliced
  // in instead.
  it("regression — present apply inserts (not overwrites) when marker is followed by a comment", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n# user note: do not delete\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "5 5 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    // The user-authored comment must still be present.
    expect(writeInput).toContain("# user note: do not delete")
    // The new job line is added (without overwriting the user comment).
    expect(writeInput).toContain("5 5 * * * /backup.sh")
    expect(writeInput).toContain("# paratix: backup")
  })

  it("regression — present apply appends a job line when the marker is the last line", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("# paratix: backup")
    expect(writeInput).toContain("0 3 * * * /backup.sh")
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  // R-0000047 regression: an `absent` apply must not blindly splice two
  // lines starting at the marker when the user has already removed the
  // previous job line. Only the marker is dropped; surrounding content
  // is preserved.
  it("regression — absent apply only removes the marker when the next line is unrelated", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("# paratix: backup")
    // The unrelated cron entry that immediately followed the marker must
    // still be present.
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  it("apply only modifies the targeted marker when multiple exist", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout:
          "# paratix: cleanup\n0 1 * * * /cleanup.sh\n# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("0 1 * * * /cleanup.sh")
    expect(writeInput).toContain("0 3 * * * /backup.sh")
    expect(writeInput).not.toContain("0 5 * * * /backup.sh")
  })

  // ---------------------------------------------------------------------------
  // input validation
  // ---------------------------------------------------------------------------

  it("throws when name contains a newline", () => {
    expect(() => cron.job("alice", "bad\nname", { job: "0 3 * * * /backup.sh" })).toThrow(
      "must not contain newlines"
    )
  })

  it("throws when job contains a newline", () => {
    expect(() => cron.job("alice", "backup", { job: "0 3 * * *\n/backup.sh" })).toThrow(
      "must not contain newlines"
    )
  })
})

describe("cron.absent", () => {
  it("check returns ok when marker is not in the crontab", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 0, stdout: "0 5 * * * /other.sh\n" },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("ok")
  })

  it("check returns ok when no crontab exists", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "no crontab for alice\n", stdout: "" },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when marker is found", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  it("apply removes marker and following job line from crontab", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("# paratix: backup")
    expect(writeInput).not.toContain("0 3 * * * /backup.sh")
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  // R-0000168: when the marker carries a sha256 hash and the line below it
  // does NOT match (because the user replaced the managed job with their
  // own), cron.absent must drop only the marker and keep the user's line.
  it("apply preserves user-replaced follow-up line when marker hash differs", async () => {
    const previousJob = "0 3 * * * /backup.sh"
    const userReplacedJob = "0 4 * * * /custom-job.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", previousJob)}\n${userReplacedJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("# paratix: backup")
    // The user's replacement job must survive cron.absent.
    expect(writeInput).toContain(userReplacedJob)
  })

  it("apply removes marker and follow-up line when marker hash matches", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", job)}\n${job}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
  })

  it("apply removes the crontab entirely when last managed entry is removed", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
  })

  it("apply returns failed when crontab removal fails", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
      "crontab -u 'alice' -r": {
        code: 1,
        stderr: "permission denied",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[cron.absent: backup (alice)] crontab removal failed (exit code 1)"
    )
    expect(result.error?.message).toContain("permission denied")
  })

  it("apply returns ok when marker is not present (nothing to remove)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = cron.absent("alice", "backup")
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("has correct name format: cron.absent: <name> (<user>)", () => {
    const mod = cron.absent("alice", "backup")
    expect(mod.name).toBe("cron.absent: backup (alice)")
  })

  it("only touches the targeted marker when multiple managed entries exist", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout:
          "# paratix: cleanup\n0 1 * * * /cleanup.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("# paratix: cleanup")
    expect(writeInput).toContain("0 1 * * * /cleanup.sh")
    expect(writeInput).not.toContain("# paratix: backup")
    expect(writeInput).not.toContain("0 3 * * * /backup.sh")
  })

  it("apply removes a trailing marker without a following job line", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("# paratix: backup")
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  it("throws when name contains a newline", () => {
    expect(() => cron.absent("alice", "bad\nname")).toThrow("must not contain newlines")
  })
})
