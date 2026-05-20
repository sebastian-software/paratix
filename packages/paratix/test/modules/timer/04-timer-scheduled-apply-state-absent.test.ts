/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it } from "vitest"

import { timer } from "../../../src/modules/timer.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const emptyEnv = {}

const SERVICE_PATH = "/etc/systemd/system/backup.service"
const TIMER_PATH = "/etc/systemd/system/backup.timer"

const successfulTimerApplyOptions: MockSshOptions = {
  allowWrites: [
    { options: { mode: "0644" }, remotePath: SERVICE_PATH },
    { options: { mode: "0644" }, remotePath: TIMER_PATH },
  ],
}

function createTimerApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulTimerApplyOptions)
}

function createPresentApplyFromMissingUnitsMockSsh(responses: MockSshResponses = {}) {
  return createTimerApplyMockSsh({
    ...presentApplyFromMissingUnitsResponses,
    ...responses,
  })
}

function createAbsentApplyWithExistingUnitsMockSsh(responses: MockSshResponses = {}) {
  return createTimerApplyMockSsh({
    ...absentApplyWithExistingUnitsResponses,
    ...responses,
  })
}

const baseOptions = {
  exec: "/usr/local/bin/backup",
  onCalendar: "*-*-* 03:00:00",
} as const

const expectedServiceContent =
  "[Unit]\nDescription=Paratix scheduled task: backup\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/backup\n"

const expectedTimerContent =
  "[Unit]\nDescription=Paratix scheduled task: backup (timer)\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nUnit=backup.service\n\n[Install]\nWantedBy=timers.target\n"

const existingServiceContent = "[Unit]\nDescription=old backup service\n"
const existingTimerContent = "[Timer]\nOnCalendar=hourly\n"

const presentApplyFromMissingUnitsResponses = {
  [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
  [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
  [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
  [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
  "systemctl daemon-reload": { code: 0 },
  "systemctl enable --now -- 'backup.timer'": { code: 0 },
  "systemctl restart -- 'backup.timer'": { code: 0 },
} satisfies MockSshResponses

const absentApplyWithExistingUnitsResponses = {
  [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
  [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
  [`cat '${SERVICE_PATH}'`]: { stdout: existingServiceContent },
  [`cat '${TIMER_PATH}'`]: { stdout: existingTimerContent },
  [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
  [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "644\n" },
  [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "644\n" },
  "systemctl daemon-reload": { code: 0 },
  "systemctl disable --now -- 'backup.timer'": { code: 0 },
  "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
  "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
} satisfies MockSshResponses

describe("timer.scheduled — apply (state: absent)", () => {
  it("disables the timer, removes both unit files and reloads", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh()
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("ignores disable failure but still removes files and reloads", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl disable --now -- 'backup.timer'": { code: 1, stderr: "no such unit" },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("disables residual active timer state even when unit files are absent", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("returns failed when rm fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when daemon-reload fails after removal", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("restores an active timer when cleanup fails after disable", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
      "systemctl start -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain("systemctl start -- 'backup.timer'")
  })

  // R-0000655: when the post-rm daemon-reload fails, we restore the unit
  // files and then must run another daemon-reload + replay the original
  // enable/active state. Without these two follow-up steps the timer
  // would end up in "files present but disabled" — files back on disk
  // but systemd thinks they are gone and the timer no longer fires.
  it("R-0000655: reloads daemon and restores activation after post-rm daemon-reload fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
      // Pre-apply state: timer was enabled and active.
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    // The rollback path must re-issue daemon-reload after the unit-file
    // restore so systemd sees the restored content, and replay the
    // enable+active state via `enable --now`.
    expect(ssh.calls.filter((c) => c === "systemctl daemon-reload").length).toBeGreaterThanOrEqual(
      2
    )
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
  })

  // R-0000655: when the second daemon-reload (after restore) also fails,
  // the failure message must surface both the original reload failure
  // and the rollback-reload failure so an operator can diagnose them.
  it("R-0000655: surfaces both failures when the post-restore daemon-reload also fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
      // Pre-apply: timer not enabled, not active, so no activation
      // rollback is attempted — the test focuses on the daemon-reload
      // chain only.
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("daemon-reload")
    expect(result.error?.message).toContain("rollback")
  })
})
