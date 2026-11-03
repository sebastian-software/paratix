import { afterEach, describe, expect, it, vi } from "vitest"

import type { FlagLockAcquireResult } from "../src/modules/flagLock.js"

import { createFlagLockWaitBudget } from "../src/modules/flagLockWait.js"
import { withMutexLock } from "../src/modules/mutexLock.js"
import { sshdLeaseAcquisition } from "../src/modules/sshdLeaseAcquisition.js"
import { createMockSsh } from "./helpers/mockSsh.js"
import { MOCK_FLAG_LOCK_HOLDER_TOKEN } from "./helpers/mockSshFlagLock.js"

const TOKEN = "11111111-1111-4111-8111-111111111111"

function acquisition(code = 0, stdout = TOKEN) {
  const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })
  const execute = vi.spyOn(ssh, "exec").mockResolvedValue({
    code,
    stderr: "foreign-diagnostic-sentinel",
    stdout,
  })
  return {
    execute,
    lease: sshdLeaseAcquisition(ssh, {
      lockName: "etc-ssh-sshd-config-mutex",
      staleSeconds: 120,
      token: TOKEN,
    }),
  }
}

describe("sshd atomic acquisition adapter", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("requires a recoverable UUID identity before any target operation", () => {
    const ssh = createMockSsh({})
    expect(() =>
      sshdLeaseAcquisition(ssh, {
        lockName: "etc-ssh-sshd-config-mutex",
        staleSeconds: 120,
        token: "non-uuid-controller-token",
      })
    ).toThrow("requires a controller UUID token")
    expect(ssh.calls).toStrictEqual([])
  })

  it("accepts only a successful readback of its own token", async () => {
    const { lease } = acquisition()
    expect(await lease.tryAcquire()).toStrictEqual({ holderToken: TOKEN, kind: "acquired" })
  })

  it("distinguishes contention from kernel-lock and initialization failures", async () => {
    const { lease } = acquisition(77, "")
    expect(await lease.tryAcquire()).toStrictEqual({ kind: "contended" })
  })

  it.each([
    { code: 73, stdout: "" },
    { code: 76, stdout: "" },
    { code: 0, stdout: "foreign-holder-token" },
  ])("fails closed on exit $code and unconfirmed ownership", async ({ code, stdout }) => {
    const { lease } = acquisition(code, stdout)
    const result = await lease.tryAcquire()
    expect(result).toMatchObject({
      failure: {
        error: { message: "sshd atomic lease acquisition failed; retained lease evidence" },
      },
      kind: "failed",
    })
    expect(JSON.stringify(result)).not.toContain("foreign-diagnostic-sentinel")
    expect(JSON.stringify(result)).not.toContain("foreign-holder-token")
  })

  it("waits without remote operations and charges one shared finite deadline", async () => {
    vi.useFakeTimers()
    const { execute, lease } = acquisition()
    const budget = createFlagLockWaitBudget(2)
    const first = lease.waitForRetry(budget)
    expect(execute).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1000)
    expect(await first).toBe(true)
    const last = lease.waitForRetry(budget)
    await vi.advanceTimersByTimeAsync(1000)
    expect(await last).toBe(false)
    expect(await lease.waitForRetry(budget)).toBe(false)
    expect(budget.rounds()).toBe(2)
    expect(vi.getTimerCount()).toBe(0)
    expect(execute).not.toHaveBeenCalled()
  })

  it("keeps the mutex refresh and token-compared release lifecycle with opt-in acquisition", async () => {
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })
    const tryAcquire = vi
      .fn<() => Promise<FlagLockAcquireResult>>()
      .mockResolvedValueOnce({ kind: "contended" })
      .mockResolvedValueOnce({ holderToken: MOCK_FLAG_LOCK_HOLDER_TOKEN, kind: "acquired" })
    const waitForRetry = vi.fn().mockResolvedValue(true)
    const result = await withMutexLock(ssh, {
      acquisition: { tryAcquire, waitForRetry },
      failureMessage: "lease test",
      lockName: "lease-test",
      async section(handle) {
        expect(await handle.refresh()).toBe(true)
        return handle.token
      },
    })
    expect(result).toStrictEqual({ kind: "ok", value: MOCK_FLAG_LOCK_HOLDER_TOKEN })
    expect(tryAcquire).toHaveBeenCalledTimes(2)
    expect(waitForRetry).toHaveBeenCalledTimes(1)
    expect(ssh.calls.some((command) => command.includes("rm -f --"))).toBe(true)
    expect(ssh.calls.some((command) => command.startsWith("i=0; while"))).toBe(false)
  })

  it("returns a bounded wait failure without a remote polling loop or section entry", async () => {
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })
    const section = vi.fn().mockResolvedValue("must not run")
    const result = await withMutexLock(ssh, {
      acquisition: {
        tryAcquire: vi.fn().mockResolvedValue({ kind: "contended" }),
        waitForRetry: vi.fn().mockResolvedValue(false),
      },
      failureMessage: "lease test",
      lockName: "lease-test",
      section,
    })
    expect(result).toMatchObject({
      failure: { error: { message: "lease test: timed out waiting for mutex lock lease-test" } },
      kind: "failed",
    })
    expect(section).not.toHaveBeenCalled()
    expect(ssh.calls).toStrictEqual([])
  })
})
