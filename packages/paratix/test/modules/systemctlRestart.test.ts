import { describe, expect, it } from "vitest"

import type { ModuleResult } from "../../src/types.js"

import { restartSystemdUnit } from "../../src/modules/systemctlRestart.js"
import { createMockSsh } from "../helpers/mockSsh.js"

function messageOf(result: ModuleResult | null): string {
  if (result?.error == null) {
    throw new TypeError("expected a failed ModuleResult carrying an error")
  }
  return result.error.message
}

const UNIT = "dependency-track-postgres"
const RESTART = `systemctl restart -- '${UNIT}'`
const HOST_DATE = `date '+%Y-%m-%d %H:%M:%S'`
const FAILURE_MESSAGE = `[quadlet.updateImage: ${UNIT}] systemctl restart failed`

/** The Podman error from issue #149, which only ever reaches the journal. */
const DEPENDENT_CONTAINERS_ERROR = [
  "Error: container bc7b232c has dependent containers which must be removed before it:",
  "dcf28b41 : container already exists",
].join("\n")

const RESTART_STDERR =
  "Job for dependency-track-postgres.service failed because the control process exited with error code."

function journalSince(since: string): string {
  return `journalctl -u '${UNIT}' --since '${since}' --no-pager --lines=20`
}

const JOURNAL_RECENT = `journalctl -u '${UNIT}' --no-pager --lines=20`

describe("restartSystemdUnit", () => {
  it("returns null and issues no extra command when the restart succeeds", async () => {
    const ssh = createMockSsh({ [RESTART]: { code: 0 } })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    expect(result).toBeNull()
    // A successful restart must stay a single round-trip: no clock read, no journal.
    expect(ssh.execCalls.map((call) => call.command)).toStrictEqual([RESTART])
  })

  it("surfaces the underlying Podman error from the journal on failure", async () => {
    const since = "2026-07-28 10:11:58"
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "2026-07-28 10:12:03\n" },
      [journalSince(since)]: { code: 0, stdout: DEPENDENT_CONTAINERS_ERROR },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    expect(result?.status).toBe("failed")
    const message = messageOf(result)
    expect(message).toContain("systemctl restart failed (exit code 1)")
    expect(message).toContain(RESTART_STDERR)
    expect(message).toContain(`unit ${UNIT} — journal since ${since}:`)
    expect(message).toContain("has dependent containers which must be removed before it")
    expect(message).not.toContain("not attributable")
  })

  it("marks a fallback excerpt as not attributable when the window is empty", async () => {
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "2026-07-28 10:12:03" },
      [JOURNAL_RECENT]: { code: 0, stdout: "stale line from an earlier attempt" },
      [journalSince("2026-07-28 10:11:58")]: { code: 0, stdout: "   \n" },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    const message = messageOf(result)
    expect(message).toContain("not attributable to this attempt")
    expect(message).toContain("stale line from an earlier attempt")
  })

  it("falls back to a recent excerpt when the host clock cannot be read", async () => {
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 1, stderr: "date: not found" },
      [JOURNAL_RECENT]: { code: 0, stdout: DEPENDENT_CONTAINERS_ERROR },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    const message = messageOf(result)
    expect(message).toContain("not attributable to this attempt")
    expect(message).toContain("has dependent containers")
  })

  it("ignores an unparseable host timestamp instead of building a bogus query", async () => {
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "Tue Jul 28 10:12:03 CEST 2026" },
      [JOURNAL_RECENT]: { code: 0, stdout: "recent line" },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    expect(messageOf(result)).toContain("not attributable to this attempt")
    expect(ssh.execCalls.some((call) => call.command.includes("--since"))).toBe(false)
  })

  it("keeps the original failure intact when the journal is unavailable", async () => {
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "2026-07-28 10:12:03" },
      [JOURNAL_RECENT]: { code: 1, stderr: "journalctl: not found" },
      [journalSince("2026-07-28 10:11:58")]: { code: 1, stderr: "journalctl: not found" },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    const message = messageOf(result)
    expect(result?.status).toBe("failed")
    expect(message).toContain("systemctl restart failed (exit code 1)")
    expect(message).toContain(RESTART_STDERR)
    // Without journal access the unit name plus the inspect command is still
    // more actionable than a bare exit code.
    expect(message).toContain(`unit ${UNIT} — inspect with: journalctl -xeu ${UNIT}`)
  })

  it("bounds a large journal excerpt and marks the truncation", async () => {
    const flood = Array.from({ length: 60 }, (_, index) => `journal line ${String(index)}`).join(
      "\n"
    )
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "2026-07-28 10:12:03" },
      [journalSince("2026-07-28 10:11:58")]: { code: 0, stdout: flood },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({ failureMessage: FAILURE_MESSAGE, ssh, unit: UNIT })

    const message = messageOf(result)
    expect(message).toContain("… (journal excerpt truncated)")
    // The tail carries the cause, so the newest lines survive and the oldest go.
    expect(message).toContain("journal line 59")
    expect(message).not.toContain("journal line 0\n")
  })

  it("masks forwarded secrets in the journal excerpt", async () => {
    const ssh = createMockSsh({
      [HOST_DATE]: { code: 0, stdout: "2026-07-28 10:12:03" },
      [journalSince("2026-07-28 10:11:58")]: {
        code: 0,
        stdout: "FATAL: password authentication failed for pw-s3cr3t",
      },
      [RESTART]: { code: 1, stderr: RESTART_STDERR },
    })

    const result = await restartSystemdUnit({
      failureMessage: FAILURE_MESSAGE,
      secrets: ["pw-s3cr3t"],
      ssh,
      unit: UNIT,
    })

    const message = messageOf(result)
    expect(message).not.toContain("pw-s3cr3t")
    expect(message).toContain("[REDACTED]")
  })
})
