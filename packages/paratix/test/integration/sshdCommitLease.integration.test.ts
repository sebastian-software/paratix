import { spawnSync } from "node:child_process"
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import type { ModuleResult, SshConnection } from "../../src/types.js"

import { withSshdCommitLease } from "../../src/modules/sshdCommitLock.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import { createTrustFixture, type TrustFixture } from "./certificateTrustHarness.js"

const available = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!available && process.env.CI === "true")
  throw new Error("sshd lease proofs require Docker in CI")
const LEASE = "/var/lib/paratix/flags/etc-ssh-sshd-config-mutex"
const HOLDER = `${LEASE}/holder`
let fixture: TrustFixture
const connections: SshConnectionImpl[] = []

function checkpoint() {
  let release: () => void = missingCheckpoint
  const reached = new Promise<void>((resolveReached) => {
    release = resolveReached
  })
  return { reached, release }
}

async function bounded<T>(operation: Promise<T>, milliseconds = 5000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error("sshd lease proof checkpoint timed out"))
        }, milliseconds)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function connect(): Promise<SshConnectionImpl> {
  const info = fixture.ssh.getConnectionInfo()
  if (info.privateKeyPath === undefined || info.verifiedHostPublicKey === undefined)
    throw new Error("Missing isolated lease fixture identity")
  const ssh = new SshConnectionImpl("127.0.0.1", {
    expectedHostPublicKey: info.verifiedHostPublicKey,
    ports: [info.port],
    privateKey: info.privateKeyPath,
    strictHostKeyChecking: "yes",
    user: "root",
  })
  connections.push(ssh)
  await ssh.connect()
  return ssh
}

async function waitForStoppedTarget(): Promise<string> {
  await fixture.container([
    "timeout",
    "15",
    "sh",
    "-c",
    "until test -s /run/lease-paused-pid && grep -q '^State:.*T' /proc/$(cat /run/lease-paused-pid)/status 2>/dev/null; do sleep 0.02; done",
  ])
  return fixture.container(["cat", "/run/lease-paused-pid"])
}

async function guardedWrite(ssh: SshConnection, name: string): Promise<ModuleResult> {
  const result = await ssh.exec(`printf '%s' owner > /run/${name}`, { ignoreExitCode: true })
  return { detail: String(result.code), status: result.code === 0 ? "changed" : "failed" }
}

function missingCheckpoint(): never {
  throw new Error("Checkpoint not initialized")
}

function observeRefreshes(ssh: SshConnectionImpl, refreshes: string[]): void {
  const execute = ssh.exec.bind(ssh)
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (command.includes("touch -c") && !command.includes("# paratix-sshd-lease-acquire"))
      refreshes.push(command)
    return execute(command, options)
  })
}

function observeContention(ssh: SshConnectionImpl, contended: ReturnType<typeof checkpoint>): void {
  const execute = ssh.exec.bind(ssh)
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    const result = await execute(command, options)
    if (command.includes("# paratix-sshd-lease-acquire") && result.code === 77) contended.release()
    return result
  })
}

function pauseSuccessfulAcquisition(
  ssh: SshConnectionImpl,
  paused: ReturnType<typeof checkpoint>,
  resume: ReturnType<typeof checkpoint>
): void {
  const execute = ssh.exec.bind(ssh)
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    const result = await execute(command, options)
    if (command.includes("# paratix-sshd-lease-acquire") && result.code === 0) {
      paused.release()
      await resume.reached
    }
    return result
  })
}

function pauseInitialMarker(ssh: SshConnectionImpl, resumed: ReturnType<typeof checkpoint>): void {
  const execute = ssh.exec.bind(ssh)
  let injected = false
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (injected || !command.includes("# paratix-sshd-lease-acquire"))
      return execute(command, options)
    injected = true
    const boundary = `if mkdir -- '${LEASE}' 2>/dev/null; then`
    expect(command).toContain(boundary)
    const actual = command.replace(
      boundary,
      () => `${boundary}\nprintf '%s' "$$" > /run/lease-paused-pid; kill -STOP $$`
    )
    const result = await execute(actual, options).catch((error: unknown) => ({ error }))
    await resumed.reached
    if ("error" in result) throw result.error
    return result
  })
}

async function killPausedTarget(pid: string | undefined): Promise<void> {
  if (pid !== undefined) await fixture.container(["kill", "-KILL", pid])
}

type InitializationCrash =
  | "after-publication"
  | "before-publication"
  | "cleanup-directory"
  | "cleanup-file"
  | "prepared-empty"
  | "prepared-partial"

function boundaryMatch(pattern: RegExp, value: string): string {
  const boundary = pattern.exec(value)?.groups?.boundary
  if (boundary === undefined) throw new Error("Missing real holder preparation boundary")
  return boundary
}

function initializationParts(command: string): {
  prepared: string
  statement: string
  token: string
} {
  const statement = boundaryMatch(/(?<boundary>\(umask 077; set -C; printf[^\n]+\))/v, command)
  const prepared = boundaryMatch(/ > (?<boundary>'[^']+')\)$/v, statement)
  const token = boundaryMatch(/holder\.pending-(?<boundary>[0-9a-f\-]{36})/v, prepared)
  return { prepared, statement, token }
}

function injectInitializationCrash(command: string, boundary: InitializationCrash): string {
  const { prepared, statement, token } = initializationParts(command)
  const publication = `mv -T -n -- ${prepared} '${HOLDER}'`
  if (boundary === "prepared-empty")
    return command.replace(statement, () => `(umask 077; set -C; : > ${prepared}; kill -KILL $$)`)
  if (boundary === "prepared-partial")
    return command.replace(
      statement,
      () => `(umask 077; set -C; printf '%s' '${token.slice(0, 12)}' > ${prepared}; kill -KILL $$)`
    )
  if (boundary === "before-publication")
    return command.replace(publication, () => `kill -KILL $$\n${publication}`)
  if (boundary === "after-publication")
    return command.replace(publication, () => `${publication}\nkill -KILL $$`)
  const cleanup = boundary === "cleanup-file" ? 'rm -- "$paratix_entries"' : `rmdir -- '${LEASE}'`
  expect(command).toContain(cleanup)
  return command.replaceAll(cleanup, () => `${cleanup}\nkill -KILL $$`)
}

async function crashInitialization(boundary: InitializationCrash): Promise<void> {
  const ssh = await connect()
  const execute = ssh.exec.bind(ssh)
  let injected = false
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (injected || !command.includes("# paratix-sshd-lease-acquire"))
      return execute(command, options)
    injected = true
    return execute(injectInitializationCrash(command, boundary), options)
  })
  const section = vi.fn(async (connection: SshConnection) =>
    guardedWrite(connection, "stale-acquirer-wrote")
  )
  await expect(
    withSshdCommitLease(ssh, { name: "crashed initialization", section })
  ).rejects.toThrow("SIGKILL")
  expect(section).not.toHaveBeenCalled()
  expect(injected).toBe(true)
}

async function ageInitialization(): Promise<void> {
  await fixture.container([
    "sh",
    "-c",
    `if [ -d '${LEASE}' ]; then find '${LEASE}' -maxdepth 1 -exec touch -d '5 minutes ago' {} +; fi`,
  ])
}

async function seedInterruptedCleanup(boundary: InitializationCrash): Promise<void> {
  if (!boundary.startsWith("cleanup-")) return
  await crashInitialization("prepared-empty")
  await ageInitialization()
}

async function initializationState() {
  const directory = await fixture.ssh.exists(LEASE)
  const holder = await fixture.ssh.exists(HOLDER)
  const holderBytes = holder ? Number(await fixture.container(["stat", "-c", "%s", HOLDER])) : null
  const prepared = await fixture.container([
    "sh",
    "-c",
    `if [ -d '${LEASE}' ]; then find '${LEASE}' -mindepth 1 -maxdepth 1 -name 'holder.pending-*' -printf '%s\\n'; fi`,
  ])
  const sizes = prepared.length === 0 ? [] : prepared.split("\n").map(Number)
  return { directory, holderBytes, preparedBytes: sizes[0] ?? null, preparedCount: sizes.length }
}

function injectForeignHolder(ssh: SshConnectionImpl): void {
  const execute = ssh.exec.bind(ssh)
  let injected = false
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (injected || !command.includes("# paratix-sshd-lease-acquire"))
      return execute(command, options)
    injected = true
    const { prepared } = initializationParts(command)
    const publication = `mv -T -n -- ${prepared} '${HOLDER}'`
    const actual = command.replace(
      publication,
      () => `printf '%s\\n' foreign-current-controller > '${HOLDER}'\n${publication}`
    )
    return execute(actual, options)
  })
}

function alterGuardedStdin(
  ssh: SshConnectionImpl,
  intended: string,
  received: (content: string) => string
): { injected: boolean } {
  const execute = ssh.exec.bind(ssh)
  const state = { injected: false }
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (!command.includes(".paratix-sshd-write.")) return execute(command, options)
    expect(options?.input).toBe(intended)
    state.injected = true
    return execute(command, { ...options, input: received(intended) })
  })
  return state
}

describe.skipIf(!available)("sshd lease acquisition and contention", { concurrent: false }, () => {
  beforeAll(async () => {
    fixture = await createTrustFixture(resolve(import.meta.dirname, "../.."))
  })
  beforeEach(async () => {
    await fixture.container([
      "sh",
      "-c",
      `rm -rf '${LEASE}'; rm -f /run/lease-paused-pid /run/stale-acquirer-wrote /run/new-owner-wrote /run/healthy-owner-wrote`,
    ])
  })
  afterEach(() => {
    vi.restoreAllMocks()
    for (const ssh of connections.splice(0)) ssh.disconnect()
  })
  afterAll(async () => {
    await fixture.cleanup()
  })

  it.each([
    { name: "empty EOF", received: (_content: string) => "" },
    { name: "prefix EOF", received: (content: string) => content.slice(0, 40) },
    { name: "extra bytes", received: (content: string) => `${content}# extra\n` },
    {
      name: "same-length corruption",
      received: (content: string) => content.replace("Port", "port"),
    },
  ])(
    "rejects guarded stdin publication after $name without changing active config",
    async ({ received }) => {
      const target = "/etc/ssh/sshd_config"
      const original = await fixture.ssh.readFile(target)
      const originalMode = await fixture.container(["stat", "-c", "%a", target])
      const originalIdentity = await fixture.container(["stat", "-c", "%a %i", target])
      const intended = `${original}# complete UTF-8: β certificate\n`
      const ssh = await connect()
      const injection = alterGuardedStdin(ssh, intended, received)
      try {
        await expect(
          withSshdCommitLease(ssh, {
            name: "guarded stdin integrity",
            async section(connection) {
              await connection.writeFile(target, intended, { mode: "0600" })
              return { status: "changed" }
            },
          })
        ).rejects.toThrow("sshd guarded file integrity check failed")
        expect(injection.injected).toBe(true)
        expect(await fixture.ssh.readFile(target)).toBe(original)
        expect(await fixture.container(["stat", "-c", "%a %i", target])).toBe(originalIdentity)
        expect(
          await fixture.container([
            "find",
            "/etc/ssh",
            "-maxdepth",
            "1",
            "-name",
            ".paratix-sshd-write.*",
            "-print",
          ])
        ).toBe("")
        expect(await fixture.ssh.exists(LEASE)).toBe(false)
      } finally {
        await fixture.write(target, original, originalMode)
      }
    }
  )

  it("publishes complete guarded UTF-8 and empty payloads", async () => {
    const target = "/etc/ssh/sshd_config"
    const original = await fixture.ssh.readFile(target)
    const originalMode = await fixture.container(["stat", "-c", "%a", target])
    const intended = `${original}# complete UTF-8: β certificate\n`
    try {
      const result = await withSshdCommitLease(fixture.ssh, {
        name: "complete guarded stdin",
        async section(ssh) {
          await ssh.writeFile(target, intended, { mode: "0640" })
          await ssh.writeFile("/run/guarded-empty-file", "")
          return { status: "changed" }
        },
      })
      expect(result.status).toBe("changed")
      expect(await fixture.ssh.readFile(target)).toBe(intended)
      expect(await fixture.container(["stat", "-c", "%a", target])).toBe("640")
      expect(await fixture.ssh.readFile("/run/guarded-empty-file")).toBe("")
      expect(await fixture.container(["stat", "-c", "%a", "/run/guarded-empty-file"])).toBe("600")
    } finally {
      await fixture.write(target, original, originalMode)
      await fixture.container(["rm", "-f", "/run/guarded-empty-file"])
    }
  })

  it("a healthy contending waiter leaves owner work, automatic heartbeat, refresh and release unblocked", async () => {
    const owner = await connect()
    const waiter = await connect()
    const entered = checkpoint()
    const contended = checkpoint()
    const work = checkpoint()
    const worked = checkpoint()
    const release = checkpoint()
    const refreshes: string[] = []
    observeRefreshes(owner, refreshes)
    observeContention(waiter, contended)
    const holding = withSshdCommitLease(owner, {
      name: "healthy owner",
      async section(ssh, handle) {
        entered.release()
        await work.reached
        const result = await guardedWrite(ssh, "healthy-owner-wrote")
        worked.release()
        await release.reached
        expect(await handle.refresh()).toBe(true)
        expect(handle.isLost()).toBe(false)
        return result
      },
    })
    await bounded(entered.reached)
    const waiting = withSshdCommitLease(waiter, {
      name: "healthy waiter",
      section: async (ssh) => guardedWrite(ssh, "new-owner-wrote"),
    })
    try {
      await bounded(contended.reached)
      const started = performance.now()
      work.release()
      await bounded(worked.reached)
      expect(performance.now() - started).toBeLessThan(5000)
      const before = await fixture.container(["stat", "-c", "%Y", HOLDER])
      // Exercise the production ten-second automatic heartbeat while the waiter remains contended.
      await new Promise<void>((resolveWait) => {
        setTimeout(resolveWait, 11_000)
      })
      expect(Number(await fixture.container(["stat", "-c", "%Y", HOLDER]))).toBeGreaterThan(
        Number(before)
      )
      expect(refreshes.length).toBeGreaterThan(1) // guarded owner work plus automatic refresh
      release.release()
      expect(await bounded(holding)).toMatchObject({ detail: "0", status: "changed" })
      expect(await bounded(waiting)).toMatchObject({ detail: "0", status: "changed" })
      expect(await fixture.ssh.exists(LEASE)).toBe(false)
      expect(await fixture.container(["cat", "/run/healthy-owner-wrote"])).toBe("owner")
      expect(await fixture.container(["cat", "/run/new-owner-wrote"])).toBe("owner")
    } finally {
      work.release()
      release.release()
      await Promise.allSettled([holding, waiting])
    }
  })

  it("a paused successful acquisition cannot overwrite, refresh or release a newer controller lease", async () => {
    const old = await connect()
    const newer = await connect()
    const paused = checkpoint()
    const resume = checkpoint()
    const owned = checkpoint()
    const releaseNew = checkpoint()
    pauseSuccessfulAcquisition(old, paused, resume)
    const oldRun = withSshdCommitLease(old, {
      name: "paused old controller",
      async section(ssh, handle) {
        expect(await handle.refresh()).toBe(false)
        return guardedWrite(ssh, "stale-acquirer-wrote")
      },
    })
    await bounded(paused.reached)
    await fixture.container(["touch", "-d", "5 minutes ago", HOLDER])
    const newerRun = withSshdCommitLease(newer, {
      name: "new controller",
      async section(ssh, handle) {
        owned.release()
        await releaseNew.reached
        expect(await handle.refresh()).toBe(true)
        return guardedWrite(ssh, "new-owner-wrote")
      },
    })
    try {
      await bounded(owned.reached)
      const currentHolder = await fixture.ssh.readFile(HOLDER)
      resume.release()
      expect(await bounded(oldRun)).toMatchObject({ detail: "74", status: "failed" })
      expect(await fixture.ssh.readFile(HOLDER)).toBe(currentHolder)
      expect(await fixture.ssh.exists("/run/stale-acquirer-wrote")).toBe(false)
      releaseNew.release()
      expect(await bounded(newerRun)).toMatchObject({ detail: "0", status: "changed" })
      expect(await fixture.ssh.exists(LEASE)).toBe(false)
    } finally {
      resume.release()
      releaseNew.release()
      await Promise.allSettled([oldRun, newerRun])
    }
  })

  it("keeps mkdir and initial marker under the living target lock and permits takeover only after process death", async () => {
    const old = await connect()
    const newer = await connect()
    const resumed = checkpoint()
    const ownsNew = checkpoint()
    const releaseNew = checkpoint()
    pauseInitialMarker(old, resumed)
    const staleSection = vi.fn(async (ssh: SshConnection) =>
      guardedWrite(ssh, "stale-acquirer-wrote")
    )
    const oldRun = withSshdCommitLease(old, {
      name: "paused initialization",
      section: staleSection,
    }).then(
      (result) => ({ result }),
      (error: unknown) => ({ error })
    )
    let targetPid: string | undefined
    try {
      targetPid = await waitForStoppedTarget()
      await fixture.container(["touch", "-d", "5 minutes ago", LEASE])
      expect(await fixture.ssh.exists(HOLDER)).toBe(false)
      const start = performance.now()
      const blocked = await withSshdCommitLease(newer, {
        name: "blocked by living initializer",
        section: async (ssh) => guardedWrite(ssh, "new-owner-wrote"),
      })
      expect(blocked.status).toBe("failed")
      expect(blocked.error?.message).toContain("atomic lease acquisition failed")
      expect(performance.now() - start).toBeLessThan(40_000)
      expect(await fixture.ssh.exists(HOLDER)).toBe(false)
      expect(
        await fixture.container(["sh", "-c", `awk '/^State:/{print $2}' /proc/${targetPid}/status`])
      ).toBe("T")
      await fixture.container(["kill", "-KILL", targetPid])
      targetPid = undefined
      const newerRun = withSshdCommitLease(newer, {
        name: "takeover after process death",
        async section(ssh) {
          ownsNew.release()
          await releaseNew.reached
          return guardedWrite(ssh, "new-owner-wrote")
        },
      })
      try {
        await bounded(ownsNew.reached)
        const newHolder = await fixture.ssh.readFile(HOLDER)
        resumed.release()
        expect(await bounded(oldRun)).toMatchObject({
          error: { message: expect.stringContaining("SIGKILL") },
        })
        expect(staleSection).not.toHaveBeenCalled()
        expect(await fixture.ssh.readFile(HOLDER)).toBe(newHolder)
        expect(await fixture.ssh.exists("/run/stale-acquirer-wrote")).toBe(false)
        releaseNew.release()
        expect(await bounded(newerRun)).toMatchObject({ detail: "0", status: "changed" })
      } finally {
        releaseNew.release()
        await newerRun
      }
    } finally {
      await killPausedTarget(targetPid)
      resumed.release()
      await oldRun
      await fixture.container(["rm", "-f", "/run/lease-paused-pid"])
    }
  })

  it.each([
    {
      boundary: "prepared-empty",
      state: { directory: true, holderBytes: null, preparedBytes: 0, preparedCount: 1 },
    },
    {
      boundary: "prepared-partial",
      state: { directory: true, holderBytes: null, preparedBytes: 12, preparedCount: 1 },
    },
    {
      boundary: "before-publication",
      state: { directory: true, holderBytes: null, preparedBytes: 37, preparedCount: 1 },
    },
    {
      boundary: "after-publication",
      state: { directory: true, holderBytes: 37, preparedBytes: null, preparedCount: 0 },
    },
    {
      boundary: "cleanup-file",
      state: { directory: true, holderBytes: null, preparedBytes: null, preparedCount: 0 },
    },
    {
      boundary: "cleanup-directory",
      state: { directory: false, holderBytes: null, preparedBytes: null, preparedCount: 0 },
    },
  ] as const)(
    "automatically recovers real initialization SIGKILL at $boundary",
    async ({ boundary, state }) => {
      await seedInterruptedCleanup(boundary)
      await crashInitialization(boundary)
      expect(await initializationState()).toStrictEqual(state)
      expect(
        await fixture.container(["flock", "-n", "/var/lib/paratix/sshd-commit.lock", "true"])
      ).toBe("")
      await ageInitialization()
      const result = await withSshdCommitLease(fixture.ssh, {
        name: "automatic initialization recovery",
        section: async (ssh) => guardedWrite(ssh, "new-owner-wrote"),
      })
      expect(result).toMatchObject({ detail: "0", status: "changed" })
      expect(await fixture.container(["cat", "/run/new-owner-wrote"])).toBe("owner")
      expect(await fixture.ssh.exists(LEASE)).toBe(false)
      expect(await fixture.ssh.exists("/run/stale-acquirer-wrote")).toBe(false)
    }
  )

  it("never overwrites a foreign holder appearing immediately before atomic publication", async () => {
    const ssh = await connect()
    injectForeignHolder(ssh)
    const section = vi.fn(async (connection: SshConnection) =>
      guardedWrite(connection, "stale-acquirer-wrote")
    )
    const result = await withSshdCommitLease(ssh, { name: "foreign publication conflict", section })
    expect(result.status).toBe("failed")
    expect(section).not.toHaveBeenCalled()
    expect(await fixture.ssh.readFile(HOLDER)).toBe("foreign-current-controller\n")
    const before = await initializationState()
    await ageInitialization()
    const retried = await withSshdCommitLease(fixture.ssh, {
      name: "foreign evidence retained",
      section,
    })
    expect(retried.status).toBe("failed")
    expect(await initializationState()).toStrictEqual(before)
    expect(await fixture.ssh.readFile(HOLDER)).toBe("foreign-current-controller\n")
    expect(section).not.toHaveBeenCalled()
  })

  it.each([
    { name: "marker symlink", setup: `ln -s /run/unsafe-marker-target '${HOLDER}'` },
    { name: "foreign entry without marker", setup: `printf evidence > '${LEASE}/foreign'` },
    { name: "empty marker", setup: `touch '${HOLDER}'` },
    {
      name: "foreign prepared payload",
      setup: `chmod 0700 '${LEASE}'; printf foreign > '${LEASE}/holder.pending-00000000-0000-0000-0000-000000000000'; chmod 0600 '${LEASE}/holder.pending-00000000-0000-0000-0000-000000000000'`,
    },
    {
      name: "insecure prepared file",
      setup: `chmod 0700 '${LEASE}'; touch '${LEASE}/holder.pending-00000000-0000-0000-0000-000000000000'; chmod 0644 '${LEASE}/holder.pending-00000000-0000-0000-0000-000000000000'`,
    },
  ])("preserves unsafe aged lease evidence: $name", async ({ setup }) => {
    await fixture.container([
      "sh",
      "-c",
      `mkdir -p '${LEASE}'; ${setup}; touch -d '5 minutes ago' '${LEASE}'`,
    ])
    const before = await fixture.container([
      "sh",
      "-c",
      `find '${LEASE}' -printf '%P %y %l\\n' | sort`,
    ])
    const section = vi.fn(async (ssh: SshConnection) => guardedWrite(ssh, "stale-acquirer-wrote"))
    const result = await withSshdCommitLease(fixture.ssh, { name: "unsafe evidence", section })
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("atomic lease acquisition failed")
    expect(section).not.toHaveBeenCalled()
    expect(
      await fixture.container(["sh", "-c", `find '${LEASE}' -printf '%P %y %l\\n' | sort`])
    ).toBe(before)
    expect(await fixture.ssh.exists("/run/stale-acquirer-wrote")).toBe(false)
  })
})
