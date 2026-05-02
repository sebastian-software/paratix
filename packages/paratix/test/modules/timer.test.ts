import { describe, expect, it } from "vitest"

import { timer } from "../../src/modules/timer.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const SERVICE_PATH = "/etc/systemd/system/backup.service"
const TIMER_PATH = "/etc/systemd/system/backup.timer"

const baseOptions = {
  exec: "/usr/local/bin/backup",
  onCalendar: "*-*-* 03:00:00",
} as const

const expectedServiceContent =
  "[Unit]\nDescription=Paratix scheduled task: backup\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/backup\n"

const expectedTimerContent =
  "[Unit]\nDescription=Paratix scheduled task: backup (timer)\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nUnit=backup.service\n\n[Install]\nWantedBy=timers.target\n"

describe("timer.scheduled — check (state: present)", () => {
  it("returns ok when files match and timer is enabled and active", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl is-active --quiet 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("returns needs-apply when service file is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer file is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when service content differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: "[Unit]\nDescription=stale\n" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer is not enabled", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl is-enabled --quiet 'backup.timer'": { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer is enabled but not active", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl is-active --quiet 'backup.timer'": { code: 1 },
      "systemctl is-enabled --quiet 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = timer.scheduled("backup", baseOptions)
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })
})

describe("timer.scheduled — check (state: absent)", () => {
  it("returns ok when neither file exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("returns needs-apply when service file still exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })

  it("returns needs-apply when timer file still exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    expect(await mod.check(ssh, emptyEnv)).toBe("needs-apply")
  })
})

describe("timer.scheduled — apply (state: present)", () => {
  it("writes both unit files, reloads, enables and restarts the timer", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now 'backup.timer'": { code: 0 },
      "systemctl restart 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain("systemctl enable --now 'backup.timer'")
    expect(ssh.calls).toContain("systemctl restart 'backup.timer'")
  })

  it("returns failed when daemon-reload fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when enable --now fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now 'backup.timer'": { code: 1, stderr: "denied" },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when restart fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now 'backup.timer'": { code: 0 },
      "systemctl restart 'backup.timer'": { code: 1, stderr: "no" },
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
})

describe("timer.scheduled — apply (state: absent)", () => {
  it("disables the timer, removes both unit files and reloads", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now 'backup.timer'")
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("ignores disable failure but still removes files and reloads", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now 'backup.timer'": { code: 1, stderr: "no such unit" },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns failed when rm fails", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when daemon-reload fails after removal", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", { ...baseOptions, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("timer.scheduled — unit content", () => {
  it("renders multiple OnCalendar lines when an array is supplied", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
    })
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
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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

describe("timer.scheduled — apply (state: present, idempotency)", () => {
  it("returns ok without side effects when files match and timer is already enabled and active", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl is-active --quiet 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl restart 'backup.timer'")
    expect(ssh.calls).not.toContain("systemctl enable --now 'backup.timer'")
  })

  it("runs enable --now when files match but timer is not enabled", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: expectedServiceContent },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl enable --now 'backup.timer'": { code: 0 },
      "systemctl is-enabled --quiet 'backup.timer'": { code: 1 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl enable --now 'backup.timer'")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl restart 'backup.timer'")
  })

  it("does not restart when only the service file changed", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: { code: 0, stdout: "[Unit]\nDescription=stale\n" },
      [`cat '${TIMER_PATH}'`]: { code: 0, stdout: expectedTimerContent },
      "systemctl daemon-reload": { code: 0 },
      "systemctl enable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.scheduled("backup", baseOptions)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl restart 'backup.timer'")
  })
})

describe("timer.scheduled — environment quoting", () => {
  it("quotes environment values that contain whitespace", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
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
})

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

describe("timer.absent", () => {
  it("check returns ok when neither unit file exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
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
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl disable --now 'backup.timer'")
    expect(ssh.calls).toContain(`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`)
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply tolerates a missing unit during disable", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
      "systemctl disable --now 'backup.timer'": { code: 1, stderr: "no such unit" },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when rm fails", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when daemon-reload fails", async () => {
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "boom" },
      "systemctl disable --now 'backup.timer'": { code: 0 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns ok when neither unit file exists (idempotent no-op)", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.absent("backup")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
    expect(ssh.calls).not.toContain("systemctl disable --now 'backup.timer'")
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
    const ssh = createMockSsh({
      [`rm -f '${TIMER_PATH}' '${SERVICE_PATH}'`]: { code: 1, stderr: "EACCES" },
      "systemctl disable --now 'backup.timer'": { code: 0 },
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
