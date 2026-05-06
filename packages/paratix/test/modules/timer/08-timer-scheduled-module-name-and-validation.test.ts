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

describe("timer.scheduled — module name and validation", () => {
  it("has correct name format: timer.scheduled: <name>", () => {
    const mod = timer.scheduled("backup", baseOptions)
    expect(mod.name).toBe("timer.scheduled: backup")
  })

  it("throws when name contains a dot (would clash with .service/.timer suffix)", () => {
    expect(() => timer.scheduled("backup.daily", baseOptions)).toThrow(/name must match/v)
  })

  it("throws when name contains a path separator", () => {
    expect(() => timer.scheduled("../etc", baseOptions)).toThrow(/name must match/v)
  })

  it("throws when name contains shell metacharacters", () => {
    expect(() => timer.scheduled("a;rm", baseOptions)).toThrow(/name must match/v)
  })

  it("throws when name contains non-ASCII word characters", () => {
    expect(() => timer.scheduled("bäckup", baseOptions)).toThrow(/name must match/v)
  })

  it("throws when name looks like a systemctl option", () => {
    expect(() => timer.scheduled("--user", baseOptions)).toThrow(/name must not start with '-'/v)
  })

  it("throws when exec contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", { exec: "/bin/sh\n-c bad", onCalendar: "daily" })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when exec is empty", () => {
    expect(() => timer.scheduled("backup", { exec: "   ", onCalendar: "daily" })).toThrow(
      /must not be empty/v
    )
  })

  it("throws when onCalendar is an empty array", () => {
    expect(() =>
      timer.scheduled("backup", { exec: "/usr/local/bin/backup", onCalendar: [] })
    ).toThrow(/at least one entry/v)
  })

  it("throws when an onCalendar entry contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: ["daily\nmonthly"],
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when description contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        description: "ok\nFoo=bar",
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when user contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "deploy\nFoo=bar",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when group contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        group: "deploy\nFoo=bar",
        onCalendar: "daily",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when workingDirectory contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        workingDirectory: "/srv\nFoo=bar",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when an environment key contains an invalid character", () => {
    expect(() =>
      timer.scheduled("backup", {
        environment: { "BAD KEY": "value" },
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
      })
    ).toThrow(/environment key must match/v)
  })

  it("throws when an environment value contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        environment: { BAD: "value\nmalicious" },
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when randomizedDelaySec contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        randomizedDelaySec: "60\n[Service]\nExecStart=/bin/evil",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when accuracySec contains a newline", () => {
    expect(() =>
      timer.scheduled("backup", {
        accuracySec: "1min\n[Service]\nExecStart=/bin/evil",
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
      })
    ).toThrow(/must not contain newlines/v)
  })

  it("throws when description is whitespace-only", () => {
    expect(() =>
      timer.scheduled("backup", {
        description: "   ",
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
      })
    ).toThrow(/description must not be empty/v)
  })

  it("throws when user is whitespace-only", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "   ",
      })
    ).toThrow(/user must not be empty/v)
  })

  it("throws when group is whitespace-only", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        group: "\t",
        onCalendar: "daily",
      })
    ).toThrow(/group must not be empty/v)
  })

  it("throws when workingDirectory is whitespace-only", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        workingDirectory: "   ",
      })
    ).toThrow(/workingDirectory must not be empty/v)
  })

  it("throws when user contains shell command substitution", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "deploy$(whoami)",
      })
    ).toThrow(/user must match/v)
  })

  it("throws when user contains uppercase letters", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "Deploy",
      })
    ).toThrow(/user must match/v)
  })

  it("throws when user is purely numeric (UID strings are rejected)", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "1000",
      })
    ).toThrow(/user must match/v)
  })

  it("throws when user contains a bidirectional Unicode codepoint", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        user: "deploy\u{202E}root",
      })
    ).toThrow(/user must match/v)
  })

  it("throws when group contains a hash character", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        group: "deploy#admin",
        onCalendar: "daily",
      })
    ).toThrow(/group must match/v)
  })

  it("throws when group contains a space", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        group: "dep loy",
        onCalendar: "daily",
      })
    ).toThrow(/group must match/v)
  })

  it("throws when workingDirectory is a relative path", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        workingDirectory: "srv/app",
      })
    ).toThrow(/workingDirectory must be an absolute POSIX path/v)
  })

  it("throws when workingDirectory contains a hash character", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        workingDirectory: "/srv/app#hack",
      })
    ).toThrow(/workingDirectory must be an absolute POSIX path/v)
  })

  it("throws when workingDirectory contains a bidirectional Unicode codepoint with hash", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "/usr/local/bin/backup",
        onCalendar: "daily",
        workingDirectory: "/srv/\u{202E}#evil",
      })
    ).toThrow(/workingDirectory must be an absolute POSIX path/v)
  })

  it("accepts a Samba-style machine account name with trailing dollar sign", async () => {
    const ssh = createPresentApplyFromMissingUnitsMockSsh()
    const writes: Record<string, string> = {}
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    ssh.writeFile = async (path: string, content: string) => {
      writes[path] = content
    }
    const mod = timer.scheduled("backup", {
      exec: "/usr/local/bin/backup",
      onCalendar: "daily",
      user: "host$",
    })
    await mod.apply(ssh, emptyEnv)
    expect(writes[SERVICE_PATH]).toContain("User=host$")
  })

  it("does not validate exec or onCalendar when state is absent", () => {
    expect(() =>
      timer.scheduled("backup", {
        exec: "",
        onCalendar: [],
        state: "absent",
      })
    ).not.toThrow()
  })
})
