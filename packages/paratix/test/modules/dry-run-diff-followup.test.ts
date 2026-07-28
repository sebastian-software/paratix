import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import { cron } from "../../src/modules/cron.js"
import { net } from "../../src/modules/net.js"
import { quadlet } from "../../src/modules/quadlet.js"
import { swap } from "../../src/modules/swap.js"
import { timer } from "../../src/modules/timer.js"
import { createQuadletMockSsh } from "../helpers/mockQuadletSsh.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

function taggedMarker(name: string, cronJob: string): string {
  const digest = createHash("sha256").update(cronJob).digest("hex")
  return `# paratix: ${name} sha256=${digest}`
}

describe("cron.job — dry-run diff", () => {
  it("declares itself as a dry-run diff producer", () => {
    const mod = cron.job("root", "backup", { job: "0 3 * * * /usr/bin/backup" })
    expect(mod._dryRunDiffProducer).toBe(true)
    expect(typeof mod._applyDryRun).toBe("function")
  })

  it("renders a diff that inserts a new managed marker and job", async () => {
    const job = "0 3 * * * /usr/bin/backup"
    const ssh = createMockSsh({
      "crontab -u 'root' -l": { code: 0, stdout: "" },
    })
    const mod = cron.job("root", "backup", { job })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toContain("+# paratix: backup")
    expect(result.diff).toContain(`+${job}`)
  })

  it("returns no diff when the crontab is already converged", async () => {
    const job = "0 3 * * * /usr/bin/backup"
    const marker = taggedMarker("backup", job)
    const ssh = createMockSsh({
      "crontab -u 'root' -l": { code: 0, stdout: `${marker}\n${job}\n` },
    })
    const mod = cron.job("root", "backup", { job })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBeUndefined()
  })
})

describe("cron.absent — dry-run diff", () => {
  it("declares itself as a dry-run diff producer", () => {
    const mod = cron.absent("root", "backup")
    expect(mod._dryRunDiffProducer).toBe(true)
  })

  it("renders a removal diff for an existing managed entry", async () => {
    const job = "0 3 * * * /usr/bin/backup"
    const marker = taggedMarker("backup", job)
    const ssh = createMockSsh({
      "crontab -u 'root' -l": { code: 0, stdout: `${marker}\n${job}\n` },
    })
    const mod = cron.absent("root", "backup")
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toContain(`-${marker}`)
    expect(result.diff).toContain(`-${job}`)
  })

  it("returns no diff when there is no managed marker", async () => {
    const ssh = createMockSsh({
      "crontab -u 'root' -l": { code: 0, stdout: "" },
    })
    const mod = cron.absent("root", "backup")
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBeUndefined()
  })
})

describe("timer.scheduled — dry-run diff", () => {
  const TIMER_NAME = "vacuum"
  const SERVICE_PATH = `/etc/systemd/system/${TIMER_NAME}.service`
  const TIMER_PATH = `/etc/systemd/system/${TIMER_NAME}.timer`
  const baseOptions = {
    exec: "/usr/bin/vacuum --new",
    onCalendar: "*-*-* 04:00:00",
  } as const

  it("declares itself as a dry-run diff producer", () => {
    const mod = timer.scheduled(TIMER_NAME, baseOptions)
    expect(mod._dryRunDiffProducer).toBe(true)
  })

  it("renders a combined diff for service and timer unit content", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
      [`cat '${SERVICE_PATH}'`]: {
        code: 0,
        stdout:
          "[Unit]\nDescription=Old\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/vacuum --old\n",
      },
      [`cat '${TIMER_PATH}'`]: {
        code: 0,
        stdout: "[Unit]\nDescription=Old\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\n",
      },
    })
    const mod = timer.scheduled(TIMER_NAME, baseOptions)
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toContain("-ExecStart=/usr/bin/vacuum --old")
    expect(result.diff).toContain("+ExecStart=/usr/bin/vacuum --new")
    expect(result.diff).toContain("+OnCalendar=*-*-* 04:00:00")
  })

  it("renders an absent diff that lists unit files to remove", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 0 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 0 },
    })
    const mod = timer.scheduled(TIMER_NAME, { ...baseOptions, state: "absent" })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toContain(`-${SERVICE_PATH}`)
    expect(result.diff).toContain(`-${TIMER_PATH}`)
  })

  it("returns no diff when neither unit file exists in the absent path", async () => {
    const ssh = createMockSsh({
      [`[ -e '${SERVICE_PATH}' ]`]: { code: 1 },
      [`[ -e '${TIMER_PATH}' ]`]: { code: 1 },
    })
    const mod = timer.absent(TIMER_NAME)
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBeUndefined()
  })
})

describe("net.hosts — dry-run diff", () => {
  it("declares itself as a dry-run diff producer", () => {
    const mod = net.hosts("1.2.3.4", ["myhost"])
    expect(mod._dryRunDiffProducer).toBe(true)
  })

  it("renders a unified diff when /etc/hosts has a stale line for the same IP", async () => {
    // Apply preserves foreign hostnames already associated with the IP, so a
    // present mutation merges (rather than replaces) the same-IP line. The
    // diff must reflect that merge: the old line drops and a merged variant
    // including the desired hostname appears.
    const ssh = createMockSsh({
      "[ -e '/etc/hosts' ]": { code: 0 },
      "cat '/etc/hosts'": {
        code: 0,
        stdout: "127.0.0.1 localhost\n10.0.0.5 old.internal\n",
      },
    })
    const mod = net.hosts("10.0.0.5", ["db.internal"])
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toContain("-10.0.0.5 old.internal")
    expect(result.diff).toMatch(/^\+10\.0\.0\.5 .*db\.internal/mv)
  })

  it("renders a diff that removes a matching entry for state: absent", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/hosts' ]": { code: 0 },
      "cat '/etc/hosts'": {
        code: 0,
        stdout: "127.0.0.1 localhost\n10.0.0.5 db.internal\n",
      },
    })
    const mod = net.hosts("10.0.0.5", ["db.internal"], { state: "absent" })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toContain("-10.0.0.5 db.internal")
  })

  it("returns no diff when /etc/hosts already matches the desired entry", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/hosts' ]": { code: 0 },
      "cat '/etc/hosts'": {
        code: 0,
        stdout: "127.0.0.1 localhost\n10.0.0.5 db.internal\n",
      },
    })
    const mod = net.hosts("10.0.0.5", ["db.internal"])
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBeUndefined()
  })
})

describe("swap.file — dry-run diff", () => {
  it("declares itself as a dry-run diff producer", () => {
    const mod = swap.file({ path: "/swapfile", size: "2G" })
    expect(mod._dryRunDiffProducer).toBe(true)
  })

  it("emits a diff that previews a new /etc/fstab entry", async () => {
    const ssh = createMockSsh({
      "cat '/etc/fstab'": { code: 0, stdout: "proc /proc proc defaults 0 0\n" },
    })
    const mod = swap.file({ path: "/swapfile", size: "2G" })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toMatch(/\+\/swapfile\s+none\s+swap/v)
  })

  it("emits a removal diff when state: absent finds the swap entry in fstab", async () => {
    const ssh = createMockSsh({
      "cat '/etc/fstab'": {
        code: 0,
        stdout: "/swapfile none swap sw 0 0\n",
      },
    })
    const mod = swap.file({ path: "/swapfile", size: "2G", state: "absent" })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBe("-/swapfile none swap sw 0 0")
  })

  it("returns no diff when /etc/fstab is already converged", async () => {
    const ssh = createMockSsh({
      "cat '/etc/fstab'": {
        code: 0,
        stdout: "/swapfile none swap sw 0 0\n",
      },
    })
    const mod = swap.file({ path: "/swapfile", size: "2G" })
    const result = await mod._applyDryRun!(ssh, emptyEnv)
    expect(result.diff).toBeUndefined()
  })
})

describe("quadlet.container — dry-run diff", () => {
  const FILE_PATH = "/etc/containers/systemd/traefik.container"

  it("declares itself as a dry-run diff producer", () => {
    const mod = quadlet.container({ image: "docker.io/library/traefik:v3", name: "traefik" })
    expect(mod._dryRunDiffProducer).toBe(true)
  })

  it("renders a unified diff when the unit file already exists with different content", async () => {
    const ssh = createQuadletMockSsh({
      [`[ -e '${FILE_PATH}' ]`]: { code: 0 },
      [`cat '${FILE_PATH}'`]: {
        code: 0,
        stdout: "[Container]\nImage=docker.io/library/traefik:v2\n",
      },
    })
    const mod = quadlet.container({ image: "docker.io/library/traefik:v3", name: "traefik" })
    const result = await mod._applyDryRun!(ssh, emptyEnv, { diff: true })
    expect(result.status).toBe("changed")
    expect(result.diff).toContain("-Image=docker.io/library/traefik:v2")
    expect(result.diff).toContain("+Image=docker.io/library/traefik:v3")
  })

  it("marks the file as new when it does not exist on the remote host", async () => {
    const ssh = createQuadletMockSsh({
      [`[ -e '${FILE_PATH}' ]`]: { code: 1 },
    })
    const mod = quadlet.container({ image: "docker.io/library/traefik:v3", name: "traefik" })
    const result = await mod._applyDryRun!(ssh, emptyEnv, { diff: true })
    expect(result.diff).toContain("(new file)")
    expect(result.diff).toContain("+Image=docker.io/library/traefik:v3")
  })

  it("R-0001023: surfaces a pending daemon-reload when content matches but the reload flag is missing", async () => {
    // Build the expected unit content the module will compare against, so
    // the simulated `cat` output matches verbatim and the content-diff is
    // empty. The reload-flag probe (`[ -f .../<flag> ]`) returns non-zero
    // (= missing); the operator must still see the pending reload signal.
    const mod = quadlet.container({ image: "docker.io/library/traefik:v3", name: "traefik" })
    // Capture the expected content by letting the module write it via apply
    // would be intrusive — instead reuse the existing diff path: when `cat`
    // returns the same string the desired serialization produces, the diff
    // is empty.
    const desired = [
      "[Unit]",
      "Description=Podman container: traefik",
      "Wants=network-online.target",
      "After=network-online.target",
      "",
      "[Container]",
      "Image=docker.io/library/traefik:v3",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
    ].join("\n")
    const ssh = createQuadletMockSsh(
      {
        // File exists and content already converges.
        [`[ -e '${FILE_PATH}' ]`]: { code: 0 },
        [`cat '${FILE_PATH}'`]: { code: 0, stdout: desired },
        // The reload-flag probe — `hasFlag` runs `[ -f /var/lib/paratix/flags/'<flag>' ]`.
        // Stub via a permissive regex so we do not have to recompute the SHA here.
      },
      {
        responseStubs: [
          {
            command:
              /^\[ -f \/var\/lib\/paratix\/flags\/'quadlet-container-[0-9a-f]{16}-[0-9a-f]{16}' \]$/v,
            result: { code: 1 },
          },
        ],
      }
    )

    const result = await mod._applyDryRun!(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.diff).toBeUndefined()
    expect(result._dryRunDetail).toContain("daemon-reload pending")
  })

  it("R-0001023: omits the pending-reload detail when content matches and the reload flag is present", async () => {
    const mod = quadlet.container({ image: "docker.io/library/traefik:v3", name: "traefik" })
    const desired = [
      "[Unit]",
      "Description=Podman container: traefik",
      "Wants=network-online.target",
      "After=network-online.target",
      "",
      "[Container]",
      "Image=docker.io/library/traefik:v3",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
    ].join("\n")
    const ssh = createQuadletMockSsh(
      {
        [`[ -e '${FILE_PATH}' ]`]: { code: 0 },
        [`cat '${FILE_PATH}'`]: { code: 0, stdout: desired },
      },
      {
        responseStubs: [
          {
            command:
              /^\[ -f \/var\/lib\/paratix\/flags\/'quadlet-container-[0-9a-f]{16}-[0-9a-f]{16}' \]$/v,
            result: { code: 0 },
          },
        ],
      }
    )

    const result = await mod._applyDryRun!(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.diff).toBeUndefined()
    expect(result._dryRunDetail).toBeUndefined()
  })
})
