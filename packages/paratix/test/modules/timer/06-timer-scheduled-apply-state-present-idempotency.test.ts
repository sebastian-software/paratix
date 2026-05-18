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

describe("timer.scheduled — apply (state: present, idempotency)", () => {
  it("returns ok without side effects when files match and timer is already enabled and active", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl restart -- 'backup.timer'")
    expect(ssh.calls).not.toContain("systemctl enable --now -- 'backup.timer'")
  })

  it("runs enable --now, daemon-reload and restart when files match but timer is not enabled (stale RAM state)", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 1 },
      "systemctl restart -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain("systemctl restart -- 'backup.timer'")
  })

  it("runs daemon-reload and restart when files match but timer is enabled and inactive (stale RAM state)", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl is-active --quiet -- 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet -- 'backup.timer'": { code: 0 },
      "systemctl restart -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl enable --now -- 'backup.timer'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain("systemctl restart -- 'backup.timer'")
  })

  it("does not restart when only the service file changed", async () => {
    const ssh = createTimerApplyMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: "[Unit]\nDescription=stale\n" },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl restart -- 'backup.timer'")
  })

  it("rewrites the service unit when its mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "600\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
    })
    const writes: Array<{ content: string; mode: string | undefined; path: string }> = []
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string, opts?: { mode?: string }) => {
      writes.push({ content, mode: opts?.mode, path })
    }
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    const servicePaths = writes.filter((w) => w.path === SERVICE_PATH)
    expect(servicePaths).toHaveLength(1)
    expect(servicePaths[0]?.mode).toBe("0644")
    expect(writes.some((w) => w.path === TIMER_PATH)).toBe(false)
  })

  it("rewrites the timer unit when its mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now -- 'backup.timer'": { code: 0 },
      "systemctl restart -- 'backup.timer'": { code: 0 },
    })
    const writes: Array<{ content: string; mode: string | undefined; path: string }> = []
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string, opts?: { mode?: string }) => {
      writes.push({ content, mode: opts?.mode, path })
    }
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    const timerWrites = writes.filter((w) => w.path === TIMER_PATH)
    expect(timerWrites).toHaveLength(1)
    expect(timerWrites[0]?.mode).toBe("0644")
    expect(writes.some((w) => w.path === SERVICE_PATH)).toBe(false)
    expect(ssh.calls).toContain("systemctl restart -- 'backup.timer'")
  })

  // R-0000773: when the on-disk files match and `is-enabled` reports a
  // toolchain error (e.g. exit code 4 == "no such unit", or a higher
  // code from a missing dbus session), the apply must surface a
  // structured failure rather than running `enable --now` against a
  // unit whose state could not be probed. Previously the legacy
  // `ssh.test` rendered the probe error as "not fully active" and the
  // apply silently re-enabled the timer.
  it("R-0000773: apply returns failed when is-enabled probe reports a toolchain error", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      [`stat -c '%a' '${SERVICE_PATH}'`]: { code: 0, stdout: "644\n" },
      [`stat -c '%a' '${TIMER_PATH}'`]: { code: 0, stdout: "644\n" },
      "systemctl is-enabled --quiet -- 'backup.timer'": {
        code: 4,
        stderr: "Failed to connect to bus",
      },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(
      "systemctl is-enabled failed while probing timer state"
    )
    expect(ssh.calls).not.toContain("systemctl enable --now -- 'backup.timer'")
  })
})
