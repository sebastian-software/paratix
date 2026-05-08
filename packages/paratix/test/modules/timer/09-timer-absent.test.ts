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
  // R-0000217: snapshot captures the unit-file mode so a rollback can
  // restore the operator's manual chmod settings.
  [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "0644" },
  [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "0644" },
  "systemctl daemon-reload": { code: 0 },
  "systemctl disable --now -- 'backup.timer'": { code: 0 },
  "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
  "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
} satisfies MockSshResponses

describe("timer.absent", () => {
  it("check returns ok when neither unit file exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.absent("backup")
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when service file still exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
    })
    const mod = timer.absent("backup")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when timer file still exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
    })
    const mod = timer.absent("backup")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = timer.absent("backup")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  it("apply disables the timer, removes both unit files and reloads", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh()
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply tolerates a missing unit during disable", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl disable --now -- 'backup.timer'": { code: 1, stderr: "no such unit" },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when disable reports a real stop error", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl disable --now -- 'backup.timer'": {
        code: 1,
        stderr: "Failed to stop backup.timer: Access denied",
      },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("systemctl disable --now failed")
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
  })

  it("apply returns failed when rm fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when daemon-reload fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`cat '${SERVICE_PATH}'`]: { stdout: existingServiceContent },
      [`cat '${TIMER_PATH}'`]: { stdout: existingTimerContent },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.writeFileCalls).toStrictEqual([
      {
        content: existingServiceContent,
        options: { mode: "0644" },
        remotePath: SERVICE_PATH,
      },
      {
        content: existingTimerContent,
        options: { mode: "0644" },
        remotePath: TIMER_PATH,
      },
    ])
  })

  it("apply returns ok when neither unit file exists (idempotent no-op)", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl disable --now -- 'backup.timer'")
  })

  it("apply runs full cleanup when only one of the two unit files still exists", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`cat '${SERVICE_PATH}'`]: { stdout: existingServiceContent },
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "644\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = timer.absent("backup")
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("has correct name format: timer.absent: <name>", () => {
    const mod = timer.absent("backup")
    expect(mod.name).toBe("timer.absent: backup")
  })

  it("uses timer.absent as failure message prefix, not timer.scheduled", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("timer.absent")
    expect(result.error?.message).not.toContain("timer.scheduled")
  })

  it("throws when name does not match the pattern", () => {
    expect(() => timer.absent("backup.daily")).toThrow(/name must match/v)
  })
})
