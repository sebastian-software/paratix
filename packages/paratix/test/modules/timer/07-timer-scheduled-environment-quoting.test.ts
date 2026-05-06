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

describe("timer.scheduled — environment quoting", () => {
  it("quotes environment values that contain whitespace", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { TOKEN: "abc def" },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain('Environment=TOKEN="abc def"')
  })

  it("escapes embedded quotes and backslashes in environment values", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { JSON: 'a"b\\c' },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain('Environment=JSON="a\\"b\\\\c"')
  })

  it("leaves simple environment values unquoted", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { LEVEL: "info" },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain("Environment=LEVEL=info")
    expect(writes[SERVICE_PATH]).not.toContain('Environment=LEVEL="info"')
  })

  it("quotes environment values containing shell command substitution", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { TOKEN: "$(rm -rf /)" },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain('Environment=TOKEN="$(rm -rf /)"')
  })

  it("quotes environment values containing bidirectional Unicode codepoints", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    // U+202E RIGHT-TO-LEFT OVERRIDE -- must not appear unquoted in the unit
    const bidi = "\u{202E}BAD"
    const mod = timer.scheduled("backup", {
      environment: { LABEL: bidi },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain(`Environment=LABEL="${bidi}"`)
  })

  it("quotes environment values containing non-ASCII letters", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      environment: { GREETING: "grüße" },
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain('Environment=GREETING="grüße"')
  })
})
