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
  [`[ ! -L '${SERVICE_PATH}' ] && [ -f '${SERVICE_PATH}' ]`]: { code: 1 },
  [`[ ! -L '${TIMER_PATH}' ] && [ -f '${TIMER_PATH}' ]`]: { code: 1 },
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

describe("timer.scheduled — unit content", () => {
  it("writes the exact expected service and timer file contents for baseOptions", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", baseOptions)
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toBe(expectedServiceContent)
    expect(writes[TIMER_PATH]).toBe(expectedTimerContent)
  })

  it("renders multiple OnCalendar lines when an array is supplied", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      exec: "/usr/local/bin/backup",
      onCalendar: ["Mon..Fri 02:00", "Sat 04:00"],
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[TIMER_PATH]).toContain("OnCalendar=Mon..Fri 02:00")
    expect(writes[TIMER_PATH]).toContain("OnCalendar=Sat 04:00")
  })

  it("includes optional service hardening lines when supplied", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { LOG_LEVEL: "info" },
      exec: "/usr/local/bin/backup",
      group: "deploy",
      onCalendar: "daily",
      user: "deploy",
      workingDirectory: "/srv/app",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain("User=deploy")
    expect(writes[SERVICE_PATH]).toContain("Group=deploy")
    expect(writes[SERVICE_PATH]).toContain("WorkingDirectory=/srv/app")
    expect(writes[SERVICE_PATH]).toContain("Environment=LOG_LEVEL=info")
    expect(writes[SERVICE_PATH]).toContain("ExecStart=/usr/local/bin/backup")
  })

  it("omits Persistent= when explicitly set to false", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
      persistent: false,
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[TIMER_PATH]).not.toContain("Persistent=")
  })

  it("includes RandomizedDelaySec and AccuracySec when supplied", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      accuracySec: "1min",
      exec: "/usr/local/bin/backup",
      onCalendar: "hourly",
      randomizedDelaySec: 300,
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[TIMER_PATH]).toContain("RandomizedDelaySec=300")
    expect(writes[TIMER_PATH]).toContain("AccuracySec=1min")
  })
})
