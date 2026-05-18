import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import { cron } from "../../src/modules/cron.js"
import { FLAGS_DIRECTORY } from "../../src/modules/moduleHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import {
  isFlagLockInternalSuccessCommand,
  MOCK_FLAG_LOCK_HOLDER_TOKEN,
} from "../helpers/mockSshFlagLock.js"

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
      {
        command: "mkdir -p /var/lib/paratix/flags",
        result: { code: 0 },
      },
      {
        command: /^mkdir \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'/v,
        result: { code: 0 },
      },
      {
        // R-0000494: hostname is now captured via `ssh.output("hostname")`
        // before the marker write, so the shell-quoted hostname (or `''` from
        // the catch fallback) is interpolated into the printf.
        command:
          /^printf '%s@%s %s\\n' "\$\$" [^"]+ "\$\(date \+%s\)" > \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'\/holder$/v,
        result: { code: 0 },
      },
      {
        // R-0000634: acquire reads back the `pid@hostname` token via
        // `ssh.output` so release can verify ownership; the stub returns the
        // shared mock token used by `mockSshFlagLock`.
        command:
          /^awk 'NR==1\{print \$1\}' -- \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'\/holder$/v,
        result: { code: 0, stdout: MOCK_FLAG_LOCK_HOLDER_TOKEN },
      },
      {
        // R-0000634: release is a single shell statement that runs the
        // ownership check, marker removal and `rmdir` atomically.
        command:
          /^awk_token=\$\(awk 'NR==1\{print \$1\}' -- \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'\/holder 2>\/dev\/null\); awk_status=\$\?; \[ "\$awk_status" = 0 \] && \[ "x\$awk_token" = 'x[^']*' \] && rm -f -- \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'\/holder && rmdir -- \/var\/lib\/paratix\/flags\/'cron-crontab-[\da-f]+'$/v,
        result: { code: 0 },
      },
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

async function waitForCrontabWriteContaining(mockSsh: MockSsh, text: string): Promise<boolean> {
  const deadline = Date.now() + 500

  return new Promise<boolean>((resolve) => {
    const poll = (): void => {
      const found = mockSsh.execCalls.some(
        (call) => call.command === "crontab -u 'alice' -" && call.options?.input?.includes(text)
      )
      if (found) {
        resolve(true)
        return
      }
      if (Date.now() >= deadline) {
        resolve(false)
        return
      }
      setTimeout(poll, 1)
    }

    poll()
  })
}

const emptyEnv = {}

const crontabWriteFailureStub = {
  command: "crontab -u 'alice' -",
  result: { code: 1, stderr: "install failed\n" },
}
const CRONTAB_LOCK_DIGEST_LENGTH = 16

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolvePromise: (() => void) | undefined
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve
  })
  return {
    promise,
    resolve() {
      resolvePromise?.()
    },
  }
}

function crontabLockName(user: string): string {
  const digest = createHash("sha256")
    .update(user)
    .digest("hex")
    .slice(0, CRONTAB_LOCK_DIGEST_LENGTH)
  return `cron-crontab-${digest}`
}

type SharedCrontabBlocker = {
  allow: Promise<void>
  observed: () => void
  text: string
}
type SharedCrontabExecResult = Awaited<ReturnType<MockSsh["exec"]>>

function createSharedCrontabMockSsh(
  user: string,
  initialCrontab: string,
  options?: { blockFirstWriteContaining?: SharedCrontabBlocker }
): MockSsh {
  const base = createMockSsh(
    {},
    {
      allowUnstubbedDefaults: true,
      defaultExecResult: { code: 0 },
    }
  )
  const lockName = crontabLockName(user)
  const lockMkdirCommand = `mkdir ${FLAGS_DIRECTORY}/'${lockName}'`
  // R-0000634: release is a single shell statement (ownership check + marker
  // removal + rmdir). The mock recognises the deterministic token returned
  // by the holder readback stub in `createMockSsh`.
  const markerPath = `${FLAGS_DIRECTORY}/'${lockName}'/holder`
  const lockPath = `${FLAGS_DIRECTORY}/'${lockName}'`
  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  // R-0000758: release captures the awk readback in `$awk_token` and uses
  // the POSIX `x`-prefix comparison.
  const verifiedReleaseCommand =
    `awk_token=$(awk 'NR==1{print $1}' -- ${markerPath} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = 'x${MOCK_FLAG_LOCK_HOLDER_TOKEN}' ] && ` +
    `rm -f -- ${markerPath} && ` +
    `rmdir -- ${lockPath}`
  const readCommand = `crontab -u '${user}' -l`
  const writeCommand = `crontab -u '${user}' -`
  const removeCommand = `crontab -u '${user}' -r`
  let crontab = initialCrontab
  let lockExists = false
  let consumedWriteBlocker = false
  const waiters: Array<() => void> = []

  function resolveWaiters(): void {
    for (const resolve of waiters.splice(0)) resolve()
  }

  const handlers = new Map<
    string,
    (
      execOptions?: Parameters<MockSsh["exec"]>[1]
    ) => Promise<SharedCrontabExecResult> | SharedCrontabExecResult
  >([
    [
      lockMkdirCommand,
      () => {
        if (lockExists) return { code: 1, stderr: "", stdout: "" }
        lockExists = true
        return { code: 0, stderr: "", stdout: "" }
      },
    ],
    [
      readCommand,
      () =>
        crontab === ""
          ? { code: 1, stderr: `no crontab for ${user}\n`, stdout: "" }
          : { code: 0, stderr: "", stdout: crontab },
    ],
    [
      removeCommand,
      () => {
        crontab = ""
        return { code: 0, stderr: "", stdout: "" }
      },
    ],
    [
      verifiedReleaseCommand,
      () => {
        lockExists = false
        resolveWaiters()
        return { code: 0, stderr: "", stdout: "" }
      },
    ],
    [
      writeCommand,
      async (execOptions) => {
        const input = execOptions?.input ?? ""
        const blocker = options?.blockFirstWriteContaining
        if (!consumedWriteBlocker && blocker && input.includes(blocker.text)) {
          consumedWriteBlocker = true
          blocker.observed()
          await blocker.allow
        }
        crontab = input
        return { code: 0, stderr: "", stdout: "" }
      },
    ],
  ])

  return {
    ...base,
    async exec(command, execOptions) {
      base.calls.push(command)
      base.execCalls.push({ command, options: execOptions })
      const handler = handlers.get(command)
      if (handler) return handler(execOptions)
      if (command.startsWith("i=0; while [ -d")) {
        if (lockExists) {
          await new Promise<void>((resolve) => {
            waiters.push(resolve)
          })
        }
        return { code: 0, stderr: "", stdout: "" }
      }
      if (isFlagLockInternalSuccessCommand(command)) return { code: 0, stderr: "", stdout: "" }
      throw new Error(`unexpected shared crontab exec command: ${command}`)
    },
  }
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

  // R-0000272: check must NOT throw when crontab read fails; instead it
  // returns NEEDS_APPLY so apply gets a chance to heal the underlying
  // problem (mirrors package.installed.check).
  it("check returns needs-apply when crontab cannot be read (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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

  // R-0000760: when an orphan-job duplicate sits outside the managed pair
  // (typically left behind by a legacy-marker cron.absent), check must
  // report needs-apply so the runner schedules the consolidation that
  // `computePresentMutation` performs.
  it("R-0000760: check returns needs-apply when an orphan duplicate exists outside the marker pair (state: present)", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", job)}\n${job}\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000760: check returns ok when the marker pair has no orphan duplicate (state: present)", async () => {
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

  // R-0000272: apply must NOT throw when crontab read fails; instead it
  // returns a failedCommand ModuleResult so the runner can render masked
  // stdout/stderr like every other apply failure path.
  it("apply returns a failed ModuleResult when crontab cannot be read (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("crontab read failed"),
      }),
      status: "failed",
    })
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

  it("serializes parallel apply calls for the same user and preserves both mutations", async () => {
    const user = "alice"
    const firstWriteObserved = deferred()
    const allowFirstWriteToFinish = deferred()
    const mockSsh = createSharedCrontabMockSsh(user, "0 5 * * * /other.sh\n", {
      blockFirstWriteContaining: {
        allow: allowFirstWriteToFinish.promise,
        observed: firstWriteObserved.resolve,
        text: "/backup.sh",
      },
    })

    const backup = cron.job(user, "backup", { job: "0 3 * * * /backup.sh" })
    const cleanup = cron.job(user, "cleanup", { job: "30 4 * * * /cleanup.sh" })
    const first = backup.apply(mockSsh, emptyEnv)
    await firstWriteObserved.promise
    const second = cleanup.apply(mockSsh, emptyEnv)

    allowFirstWriteToFinish.resolve()
    const results = await Promise.all([first, second])

    expect(results).toStrictEqual([{ status: "changed" }, { status: "changed" }])
    const writes = mockSsh.execCalls.filter((call) => call.command === "crontab -u 'alice' -")
    expect(writes).toHaveLength(2)
    expect(writes[1]?.options?.input).toContain("/other.sh")
    expect(writes[1]?.options?.input).toContain("/backup.sh")
    expect(writes[1]?.options?.input).toContain("/cleanup.sh")
  })

  it("uses independent crontab mutexes for different users", async () => {
    const aliceSsh = createSharedCrontabMockSsh("alice", "")
    const bobSsh = createSharedCrontabMockSsh("bob", "")

    await cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" }).apply(aliceSsh, emptyEnv)
    await cron.job("bob", "backup", { job: "0 3 * * * /backup.sh" }).apply(bobSsh, emptyEnv)

    expect(aliceSsh.calls).toContain(`mkdir ${FLAGS_DIRECTORY}/'${crontabLockName("alice")}'`)
    expect(bobSsh.calls).toContain(`mkdir ${FLAGS_DIRECTORY}/'${crontabLockName("bob")}'`)
    expect(crontabLockName("alice")).not.toBe(crontabLockName("bob"))
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

  // R-0000676: when cron.absent left an orphan job line behind (legacy
  // marker without recorded digest), a subsequent state="present" apply
  // with `adoptOrphans: true` re-adopts the orphan by splicing the marker
  // in front of the existing line so the job stays single.
  // R-0000697: the adoption now requires the `adoptOrphans` opt-in so an
  // identical user-authored line that paratix never managed cannot be
  // silently grabbed by the present mutation.
  it("apply re-adopts an orphan job line when adoptOrphans is enabled (state: present)", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `0 5 * * * /other.sh\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { adoptOrphans: true, job })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toBeDefined()
    // The job must appear exactly once.
    const jobOccurrences = writeInput!.split("\n").filter((line) => line === job).length
    expect(jobOccurrences).toBe(1)
    // The marker must sit immediately above the orphan line we adopted.
    const expectedMarker = taggedMarker("backup", job)
    expect(writeInput).toContain(`${expectedMarker}\n${job}`)
    // The unrelated entry must remain.
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  // R-0000760: a pre-existing identical line must NOT trigger a duplicate
  // append. The previous R-0000697 behaviour appended a fresh marker + job
  // pair and accepted the visible duplicate; R-0000760 strengthens the
  // contract so the present mutation splices the marker in front of the
  // existing exact-match line instead, leaving a single managed entry
  // regardless of the `adoptOrphans` opt-in.
  it("R-0000760: splices marker in front of existing exact match without adoptOrphans (state: present)", async () => {
    const job = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `0 5 * * * /other.sh\n${job}\n`,
      },
    })
    const mod = cron.job("alice", "backup", { job })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toBeDefined()
    // The job line appears exactly once — the marker was spliced in front
    // of the existing line rather than producing a parallel duplicate.
    const jobOccurrences = writeInput!.split("\n").filter((line) => line === job).length
    expect(jobOccurrences).toBe(1)
    const expectedMarker = taggedMarker("backup", job)
    expect(writeInput).toContain(`${expectedMarker}\n${job}`)
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

  // R-0000532: name validation switched from newline-only check to a strict
  // pattern that rejects whitespace, colons, equals signs and other characters
  // that could collide with the marker format.
  it("throws when name contains a newline", () => {
    expect(() => cron.job("alice", "bad\nname", { job: "0 3 * * * /backup.sh" })).toThrow(
      "must match"
    )
  })

  it("throws when job contains a newline", () => {
    expect(() => cron.job("alice", "backup", { job: "0 3 * * *\n/backup.sh" })).toThrow(
      "must not contain newlines"
    )
  })

  // R-0000748: validate `user` against the posix name pattern before the
  // crontab mutex acquires a lock for a bogus identifier.
  it("throws when user contains a newline", () => {
    expect(() => cron.job("bad\nuser", "backup", { job: "0 3 * * * /backup.sh" })).toThrow(
      "user name"
    )
  })

  it("throws when user starts with a hyphen", () => {
    expect(() => cron.job("-alice", "backup", { job: "0 3 * * * /backup.sh" })).toThrow(
      "user name"
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

  // R-0000567: a legacy marker (without recorded digest) does not prove that
  // the follow-up line was the one paratix wrote, so apply only removes the
  // marker and intentionally leaves the orphaned job line in place.
  it("apply removes legacy marker but preserves the follow-up line for manual cleanup", async () => {
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
    expect(writeInput).toContain("0 3 * * * /backup.sh")
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  // R-0000635: when a legacy marker is encountered, the warning that was
  // previously written directly to `process.stderr` now flows through
  // ModuleResult.detail so the runner can render and mask it consistently.
  it("apply surfaces the legacy-marker warning through ModuleResult.detail", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.detail).toBe(
      "legacy marker without recorded digest — keeping follow-up line and removing only the marker"
    )
  })

  // R-0000635: a tagged marker whose follow-up line matches the recorded
  // digest must not produce the legacy-marker warning detail.
  it("apply does not attach a legacy-marker detail when the marker carries a digest", async () => {
    const backupJob = "0 3 * * * /backup.sh"
    const taggedBackupMarker = taggedMarker("backup", backupJob)
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `0 5 * * * /other.sh\n${taggedBackupMarker}\n${backupJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.detail).toBeUndefined()
  })

  // R-0000168: a marker that carries a recorded sha256 digest and a matching
  // follow-up line is removed together so the managed job is fully purged.
  it("apply removes marker and matching follow-up job line when the marker carries a digest", async () => {
    const backupJob = "0 3 * * * /backup.sh"
    const taggedBackupMarker = taggedMarker("backup", backupJob)
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `0 5 * * * /other.sh\n${taggedBackupMarker}\n${backupJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).not.toContain("paratix: backup")
    expect(writeInput).not.toContain(backupJob)
    expect(writeInput).toContain("0 5 * * * /other.sh")
  })

  it("serializes apply with parallel crontab mutations and preserves both changes", async () => {
    const user = "alice"
    const backupJob = "0 3 * * * /backup.sh"
    const firstWriteObserved = deferred()
    const allowFirstWriteToFinish = deferred()
    const mockSsh = createSharedCrontabMockSsh(
      user,
      `0 5 * * * /other.sh\n${taggedMarker("backup", backupJob)}\n${backupJob}\n`,
      {
        blockFirstWriteContaining: {
          allow: allowFirstWriteToFinish.promise,
          observed: firstWriteObserved.resolve,
          text: "/other.sh",
        },
      }
    )

    const removeBackup = cron.absent(user, "backup")
    const cleanup = cron.job(user, "cleanup", { job: "30 4 * * * /cleanup.sh" })
    const first = removeBackup.apply(mockSsh, emptyEnv)
    await firstWriteObserved.promise
    const second = cleanup.apply(mockSsh, emptyEnv)
    const cleanupWroteBeforeAbsentFinished = await waitForCrontabWriteContaining(
      mockSsh,
      "/cleanup.sh"
    )

    allowFirstWriteToFinish.resolve()
    const results = await Promise.all([first, second])
    const finalCrontab = await mockSsh.exec(`crontab -u '${user}' -l`)

    expect(results).toStrictEqual([{ status: "changed" }, { status: "changed" }])
    expect(cleanupWroteBeforeAbsentFinished).toBe(false)
    expect(finalCrontab.stdout).toContain("/other.sh")
    expect(finalCrontab.stdout).toContain("/cleanup.sh")
    expect(finalCrontab.stdout).not.toContain("# paratix: backup")
    expect(finalCrontab.stdout).not.toContain("/backup.sh")
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

  // R-0000699: when a tagged marker records a sha256 digest but the follow-up
  // line differs from the marker's recorded line only in whitespace (e.g. a
  // hand-edited extra space or tab vs space), the byte-exact digest compare
  // intentionally rejects the line. Surface that near-miss as an operator
  // hint via `ModuleResult.detail` so the divergence does not vanish silently.
  it("apply surfaces a whitespace-mismatch hint when only spacing differs", async () => {
    const managedJob = "0 3 * * * /backup.sh"
    const reformattedJob = "0  3  *  *  *  /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", managedJob)}\n${reformattedJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.detail).toContain("differs from the recorded digest only in whitespace")
    // The reformatted follow-up line must survive because the digest check is
    // byte-exact and intentionally does not normalize whitespace.
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain(reformattedJob)
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

  // R-0000168 / R-0000567: with a recorded digest the marker and its
  // matching follow-up line are removed together; if that empties the
  // crontab, the module deletes the crontab entirely via `crontab -r`.
  it("apply removes the crontab entirely when last managed entry is removed", async () => {
    const backupJob = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", backupJob)}\n${backupJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
  })

  it("apply returns failed when crontab removal fails", async () => {
    const backupJob = "0 3 * * * /backup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("backup", backupJob)}\n${backupJob}\n`,
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

  // R-0000168 / R-0000567: ensure only the targeted marker (and its
  // matching follow-up line, when the digest still validates) is touched —
  // other managed entries with their own digests must remain intact.
  it("only touches the targeted marker when multiple managed entries exist", async () => {
    const backupJob = "0 3 * * * /backup.sh"
    const cleanupJob = "0 1 * * * /cleanup.sh"
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: `${taggedMarker("cleanup", cleanupJob)}\n${cleanupJob}\n${taggedMarker("backup", backupJob)}\n${backupJob}\n`,
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeInput = findCrontabWriteInput(mockSsh)
    expect(writeInput).toContain("paratix: cleanup")
    expect(writeInput).toContain(cleanupJob)
    expect(writeInput).not.toContain("paratix: backup")
    expect(writeInput).not.toContain(backupJob)
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

  // R-0000532: name validation now uses a strict pattern check.
  it("throws when name contains a newline", () => {
    expect(() => cron.absent("alice", "bad\nname")).toThrow("must match")
  })

  // R-0000748: validate `user` against the posix name pattern up-front so an
  // invalid identifier never reaches the crontab mutex / readCrontab path.
  it("throws when user contains a newline", () => {
    expect(() => cron.absent("bad\nuser", "backup")).toThrow("user name")
  })

  it("throws when user starts with a hyphen", () => {
    expect(() => cron.absent("-alice", "backup")).toThrow("user name")
  })

  // R-0000272: cron.absent uses the same readCrontab helper as cron.job.
  // A crontab read failure (e.g. permission denied) must surface as
  // NEEDS_APPLY in check and as a failedCommand ModuleResult in apply.
  it("check returns needs-apply when crontab cannot be read", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns a failed ModuleResult when crontab cannot be read", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stderr: "permission denied\n" },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("crontab read failed"),
      }),
      status: "failed",
    })
    expect(findCrontabWriteCall(mockSsh)).toBeUndefined()
  })
})
