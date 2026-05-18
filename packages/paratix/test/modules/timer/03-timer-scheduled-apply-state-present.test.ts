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
  [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
  [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
  "systemctl daemon-reload": { code: 0 },
  "systemctl enable --now -- 'backup.timer'": { code: 0 },
  "systemctl restart -- 'backup.timer'": { code: 0 },
} satisfies MockSshResponses

const absentApplyWithExistingUnitsResponses = {
  [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
  [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
  [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
  "systemctl daemon-reload": { code: 0 },
  "systemctl disable --now -- 'backup.timer'": { code: 0 },
  "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
  "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
} satisfies MockSshResponses

describe("timer.scheduled — apply (state: present)", () => {
  it("writes both unit files, reloads, enables and restarts the timer", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl restart -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
    expect(ssh.calls).toContain("systemctl restart -- 'backup.timer'")
  })

  it("returns failed when daemon-reload fails", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`rm -f '${SERVICE_PATH}'`]: { code: 0 },
      [`rm -f '${TIMER_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain(`rm -f '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}'`)
  })

  it("restores previous unit files when daemon-reload fails", async () => {
    const previousService = "[Unit]\nDescription=old service\n"
    const previousTimer = "[Unit]\nDescription=old timer\n"
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { stdout: previousService },
      [`cat '${TIMER_PATH}'`]: { stdout: previousTimer },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "0644" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "0644" },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.writeFileCalls.at(-2)?.content).toBe(previousService)
    expect(ssh.writeFileCalls.at(-1)?.content).toBe(previousTimer)
  })

  it("returns a structured failure when daemon-reload rollback fails", async () => {
    const previousService = "[Unit]\nDescription=old service\n"
    const previousTimer = "[Unit]\nDescription=old timer\n"
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { stdout: previousService },
      [`cat '${TIMER_PATH}'`]: { stdout: previousTimer },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "0644" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "0644" },
      "systemctl daemon-reload": { code: 1, stderr: "reload boom" },
    })
    vi.spyOn(ssh, "writeFile")
      .mockResolvedValueOnce()
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("restore denied"))
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl daemon-reload failed")
    expect(String(result.error)).toContain("rollback of timer unit files also failed")
    expect(String(result.error)).toContain("restore denied")
    expect(String(result.error)).toContain("reload boom")
  })

  // R-0000217: timer snapshots must capture the existing unit-file mode so
  // the rollback restores the operator's manual chmod (e.g. 0600 because of
  // an EnvironmentFile reference). The previous implementation hardcoded
  // 0644 on restore and silently overwrote that hardening.
  it("R-0000217: rollback restores the original mode captured in the snapshot", async () => {
    const previousService = "[Unit]\nDescription=old service\n"
    const previousTimer = "[Unit]\nDescription=old timer\n"
    const ssh = createMockSsh(
      {
        [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
        [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
        [`cat '${SERVICE_PATH}'`]: { stdout: previousService },
        [`cat '${TIMER_PATH}'`]: { stdout: previousTimer },
        // Operator hardened service mode to 0600; timer stays at 0644.
        [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "0600" },
        [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "0644" },
        "systemctl daemon-reload": { code: 1, stderr: "boom" },
      },
      {
        allowWrites: [
          { options: { mode: "0644" }, remotePath: SERVICE_PATH },
          { options: { mode: "0600" }, remotePath: SERVICE_PATH },
          { options: { mode: "0644" }, remotePath: TIMER_PATH },
        ],
      }
    )
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    // Last two writes are the restore: service must use 0600, timer 0644.
    expect(ssh.writeFileCalls.at(-2)).toStrictEqual({
      content: previousService,
      options: { mode: "0600" },
      remotePath: SERVICE_PATH,
    })
    expect(ssh.writeFileCalls.at(-1)).toStrictEqual({
      content: previousTimer,
      options: { mode: "0644" },
      remotePath: TIMER_PATH,
    })
  })

  // R-0000216: when the second writeFile throws, the first file is left
  // modified. The shared try/catch around both writeFile calls must
  // restore both snapshots and surface a failed result.
  it("R-0000216: restores both unit files when the second writeFile throws", async () => {
    const previousService = "[Unit]\nDescription=old service\n"
    const previousTimer = "[Unit]\nDescription=old timer\n"
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { stdout: previousService },
      [`cat '${TIMER_PATH}'`]: { stdout: previousTimer },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "0644" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "0644" },
    })
    // First call writes the new service content; second call (timer) throws;
    // the catch block then issues two restore writes.
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("SFTP write timer.timer failed: ENOSPC"))
      .mockResolvedValue()
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write timer unit files")
    expect(String(result.error)).toContain("ENOSPC")
    // First two calls are the failing apply; last two are the restore.
    expect(writeFile).toHaveBeenNthCalledWith(1, SERVICE_PATH, expectedServiceContent, {
      mode: "0644",
    })
    expect(writeFile).toHaveBeenNthCalledWith(2, TIMER_PATH, expectedTimerContent, {
      mode: "0644",
    })
    expect(writeFile).toHaveBeenNthCalledWith(3, SERVICE_PATH, previousService, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(4, TIMER_PATH, previousTimer, { mode: "0644" })
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  it("returns a structured failure when write rollback also fails", async () => {
    const previousService = "[Unit]\nDescription=old service\n"
    const previousTimer = "[Unit]\nDescription=old timer\n"
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { stdout: previousService },
      [`cat '${TIMER_PATH}'`]: { stdout: previousTimer },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { stdout: "0644" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { stdout: "0644" },
    })
    vi.spyOn(ssh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("timer write failed: ENOSPC"))
      .mockRejectedValueOnce(new Error("restore denied"))

    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write timer unit files")
    expect(String(result.error)).toContain("timer write failed")
    expect(String(result.error)).toContain("rollback of timer unit files also failed")
    expect(String(result.error)).toContain("restore denied")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  it("returns failed when enable --now fails", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 1, stderr: "denied" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when restart fails", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl restart -- 'backup.timer'": { code: 1, stderr: "no" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when ssh is null", async () => {
    const mod = timer.scheduled("backup", baseOptions)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000720: a pre-write snapshot read failure (TOCTOU race, transient
  // SFTP error, permission denial) must surface as a failed ModuleResult
  // instead of bubbling an unstructured exception out of the module. The
  // writeFile step must NOT run because the rollback would have no
  // usable snapshot to restore.
  it("R-0000720: refuses to write timer files when snapshot read fails", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "0644" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "0644" },
    })
    // `fileMatches` reads each path once during the diff (returns mismatching
    // content), then `readFileSnapshot` reads each path once for the
    // pre-write snapshot. The 3rd read (service snapshot) throws.
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce("[Unit]\nDescription=existing service\n")
      .mockResolvedValueOnce("[Unit]\nDescription=existing timer\n")
      .mockRejectedValueOnce(new Error("SFTP read failed: connection reset"))
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to snapshot timer unit file")
    expect(String(result.error)).toContain(SERVICE_PATH)
    expect(String(result.error)).toContain("connection reset")
    // The writeFile must NOT have been issued — there is no recoverable
    // snapshot, so the apply must abort before touching the live unit files.
    expect(writeFile).not.toHaveBeenCalled()
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })
})
