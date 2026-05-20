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
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
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
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
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

  // R-0000977: apply reads the activation snapshot before mutating timer
  // state. A toolchain error from `is-enabled` must abort the apply with a
  // structured failure instead of being coerced to disabled/inactive and
  // allowing disable/rm/daemon-reload to run.
  it("R-0000977: apply fails before mutations when is-enabled snapshot probe reports a toolchain error", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": {
        code: 4,
        stderr: "Failed to connect to bus",
      },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[timer.absent: backup] systemctl is-enabled failed while probing timer state"
    )
    expect(result.error?.message).toContain("Failed to connect to bus")
    expect(ssh.calls).not.toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  // R-0000977: when `is-enabled` succeeds, an `is-active` toolchain error
  // is the second half of the same activation-snapshot guard. It must also
  // fail before any absent-path mutation.
  it("R-0000977: apply fails before mutations when is-active snapshot probe reports a toolchain error", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": {
        code: 5,
        stderr: "Internal systemctl error",
      },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[timer.absent: backup] systemctl is-active failed while probing timer state"
    )
    expect(result.error?.message).toContain("Internal systemctl error")
    expect(ssh.calls).not.toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  // R-0000780: a "no such unit" diagnostic from `disable --now` can mask
  // a real stop failure. When systemd reports the unit file as missing
  // but `is-enabled` / `is-active` still report the timer as live, the
  // apply must surface a structured failure rather than silently
  // dropping the unit files.
  it("R-0000780: fails when disable swallows the stop failure but the timer is still active", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl disable --now -- 'backup.timer'": {
        code: 1,
        stderr: "Failed to disable unit: Unit file backup.timer does not exist.",
      },
      // The pre-disable activation snapshot reports the timer as active
      // and enabled so the rollback path replays the snapshot when the
      // disable returns a structured failure.
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "systemctl disable --now reported missing unit but the timer is still enabled or active"
    )
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
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

  // R-0000774: when `disable --now` fails on a timer that was enabled and
  // active before the apply, the pre-apply activation snapshot must be
  // replayed via `restoreTimerActivationForAbsent` so the timer ends up
  // in its original state rather than half-disabled. The unit-file
  // removal must NOT run after a disable failure.
  it("R-0000774: restores activation snapshot when disable fails on an active timer", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl disable --now -- 'backup.timer'": {
        code: 1,
        stderr: "Failed to stop backup.timer: Access denied",
      },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl disable --now failed")
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
  })

  // R-0000774: chain a rollback failure into the disable failure so
  // operators see both errors. Mirrors the chained rollback messages in
  // `handleAbsentRemoveFailure` (R-0000552).
  it("R-0000774: chains rollback failures into the disable failure", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl disable --now -- 'backup.timer'": {
        code: 1,
        stderr: "Failed to stop backup.timer: Access denied",
      },
      "systemctl enable --now -- 'backup.timer'": {
        code: 1,
        stderr: "enable rollback boom",
      },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl disable --now failed")
    expect(String(result.error)).toContain("rollback enable failed")
    expect(String(result.error)).toContain("enable rollback boom")
  })

  it("apply returns failed when rm fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
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
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("reports rollback failures when rm fails after partially deleting unit files", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
    })
    vi.spyOn(ssh, "writeFile").mockRejectedValueOnce(new Error("restore denied"))

    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to remove unit files")
    expect(String(result.error)).toContain("EACCES")
    expect(String(result.error)).toContain("rollback of timer unit files also failed")
    expect(String(result.error)).toContain("restore denied")
  })

  it("reports daemon-reload failures after restoring unit files for rm failure", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })

    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to remove unit files")
    expect(String(result.error)).toContain("daemon-reload after unit-file rollback also failed")
    expect(String(result.error)).toContain("reload failed")
  })

  it("restores an enabled active timer when rm fails after disable", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain("systemctl disable --now -- 'backup.timer'")
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
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

  it("restores an enabled inactive timer when daemon-reload fails after disable", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
      "systemctl enable -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain("systemctl enable -- 'backup.timer'")
  })

  it("returns a structured failure when daemon-reload rollback fails", async () => {
    const ssh = createAbsentApplyWithExistingUnitsMockSsh({
      "systemctl daemon-reload": { code: 1, stderr: "reload boom" },
      "systemctl enable -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    vi.spyOn(ssh, "writeFile").mockRejectedValueOnce(new Error("restore denied"))
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl daemon-reload failed")
    expect(String(result.error)).toContain("rollback of timer unit files also failed")
    expect(String(result.error)).toContain("restore denied")
    expect(String(result.error)).toContain("reload boom")
  })

  it("apply returns ok when neither unit file exists (idempotent no-op)", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
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
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
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

  // R-0000720: a pre-rm snapshot capture failure (transient SFTP error or
  // permission denial between `ssh.exists` and `ssh.readFile`) must surface
  // as a structured failed ModuleResult. Because `disableTimerForAbsent`
  // already changed the timer's enable/active state, the rollback must
  // replay `restoreTimerActivationForAbsent` before returning so the timer
  // does not end up silently disabled.
  it("R-0000720: rolls back activation when snapshot read fails", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl disable --now -- 'backup.timer'": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    vi.spyOn(ssh, "readFile").mockRejectedValueOnce(new Error("SFTP read failed: connection reset"))
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to snapshot timer unit file")
    expect(String(result.error)).toContain("connection reset")
    // Activation must have been replayed so the timer is back to enabled+active.
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
    // The rm step must NOT have run because the snapshot capture refused
    // to proceed.
    expect(ssh.calls).not.toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
  })

  // R-0000720: chain the activation rollback failure into the snapshot
  // failure message so both diagnostic strings remain visible. Without
  // chaining the user would lose either the rollback reason or the
  // original snapshot capture reason.
  it("R-0000720: chains activation rollback failure into snapshot failure", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      "systemctl disable --now -- 'backup.timer'": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": {
        code: 1,
        stderr: "enable rollback boom",
      },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    vi.spyOn(ssh, "readFile").mockRejectedValueOnce(new Error("SFTP read failed: connection reset"))
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to snapshot timer unit file")
    expect(String(result.error)).toContain("connection reset")
    expect(String(result.error)).toContain("rollback enable failed")
    expect(String(result.error)).toContain("enable rollback boom")
  })

  // R-0000773: the check phase has no failure channel; a toolchain error
  // from `systemctl is-enabled` (exit code 4 == "no such unit", or any
  // other code outside the well-formed enabled/disabled set) must
  // downgrade to `needs-apply` so the apply phase can resurface the
  // structured failure. Previously the legacy `ssh.test` path collapsed
  // every non-zero exit into `false` and rendered the timer as
  // "not enabled" — the probe error was invisible.
  it("R-0000773: check returns needs-apply when is-enabled probe reports a toolchain error", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": {
        code: 4,
        stderr: "Failed to connect to bus",
      },
    })
    const mod = timer.absent("backup")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  // R-0000773: a toolchain error from `is-active` (e.g. exit code 5) on
  // an enabled timer must also surface as `needs-apply` rather than
  // silently returning `ok`.
  it("R-0000773: check returns needs-apply when is-active probe reports a toolchain error", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl is-active --quiet -- 'backup.timer'": {
        code: 5,
        stderr: "Internal error",
      },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
    })
    const mod = timer.absent("backup")
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })
})
