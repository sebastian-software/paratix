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
})
