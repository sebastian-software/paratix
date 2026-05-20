/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

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

const presentApplyFromMissingUnitsResponses = {
  [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
  [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
  "systemctl daemon-reload": { code: 0 },
  "systemctl enable --now -- 'backup.timer'": { code: 0 },
  "systemctl restart -- 'backup.timer'": { code: 0 },
} satisfies MockSshResponses

const absentApplyWithExistingUnitsResponses = {
  [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
  [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
  [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
  "systemctl daemon-reload": { code: 0 },
  "systemctl disable --now -- 'backup.timer'": { code: 0 },
  "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
  "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
} satisfies MockSshResponses

describe("timer.scheduled — check (state: present)", () => {
  it("returns ok when files match and timer is enabled and active", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("returns needs-apply when service unit mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "600\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer unit mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "600\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when the service unit path is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
    expect(ssh.calls).not.toContain(`cat '${SERVICE_PATH}'`)
  })

  it("returns needs-apply when the timer unit path is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
    expect(ssh.calls).not.toContain(`cat '${TIMER_PATH}'`)
  })

  it("returns needs-apply when stat for the service unit mode fails", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 1, stdout: "" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when service file is missing", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer file is missing", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when reading the service unit fails", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
    })
    vi.spyOn(ssh, "readFile").mockRejectedValueOnce(new Error("SFTP read failed"))
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when reading the timer unit fails", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(expectedServiceContent)
      .mockRejectedValueOnce(new Error("SFTP read failed"))
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when service content differs", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: "[Unit]\nDescription=stale\n" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer is not enabled", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer is enabled but not active", async () => {
    const ssh = createMockSsh({
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })
})
