/* eslint-disable max-lines-per-function, max-statements, prefer-named-capture-group, regexp/prefer-quantifier, security/detect-unsafe-regex, @typescript-eslint/require-await -- the fake host mirrors the remote command surface with fixed fixture patterns and async interface methods */
/* oxlint-disable unicorn/consistent-function-scoping, unicorn/no-useless-spread, jsdoc/require-returns, jsdoc/require-param -- helpers stay next to the fake state they describe */
/**
 * Stateful in-memory sshd host for the `sshd.match` module flows.
 *
 * It models the files, the staging directories and the handful of commands the
 * module issues, so tests can prove publish, rollback and idempotence against
 * observable file state instead of command strings. `sshd -t` and `sshd -T`
 * outcomes are controlled through `behavior`.
 */
import { createHash } from "node:crypto"
import { posix } from "node:path"
import { vi } from "vitest"

import type { SshdConfigTransaction } from "../../../src/modules/sshd.js"
import type { ExecResult, SshConnection } from "../../../src/types.js"

import * as sshdModule from "../../../src/modules/sshd.js"
import { includeGlobMatches } from "../../../src/modules/sshdIncludeStaging.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

export const MAIN_CONFIG = "/etc/ssh/sshd_config"
export const DROP_IN_DIRECTORY = "/etc/ssh/sshd_config.d"
export const DEFAULT_MAIN_CONFIG = `Include ${DROP_IN_DIRECTORY}/*.conf\nPort 22\nPasswordAuthentication no\n`
const REGULAR_METADATA = "644 0 0"
const DIRECTORY_METADATA = "755 0 0"
const OK: ExecResult = { code: 0, stderr: "", stdout: "" }

type FileEntry = { content: string; metadata: string }

/** Switches a test flips to steer the fake sshd. */
export type FakeSshdBehavior = {
  /** Returns stderr to make one exec command fail; `undefined` runs it normally. */
  failCommand?: (command: string) => string | undefined
  /** Live `sshd -T [-C user=…]` output; defaults to `desired` while the drop-in exists. */
  liveEffective?: (user: string | undefined) => string
  /** `false` simulates a missing `/run/sshd` (dry-run only) . */
  privilegeSeparation: boolean
  /** Message of a failing `sshd -T` reload; `undefined` reloads successfully. */
  reloadError?: string
  /** Message of a failing pure-reload capability check (`systemctl show`/`is-active`). */
  reloadOnlyUnavailable?: string
  /** Message of a failing restore reload during rollback. */
  restoreError?: string
  /** Staged `sshd -T -f` output; defaults to `desired` while the staged tree holds the drop-in. */
  stagedEffective?: (user: string | undefined) => string
  /** stderr of a failing staged `sshd -t -f`; `undefined` validates successfully. */
  stagedTestFailure?: string
}

export type FakeSshdHost = {
  behavior: FakeSshdBehavior
  /** Every exec command in order. */
  commands: string[]
  connection: SshConnection
  files: Map<string, FileEntry>
  /** Replaces the transaction factory of the module under test; call `vi.restoreAllMocks()` afterwards. */
  install: () => void
  /** Live (non-staging) file content, or `undefined`. */
  live: (path: string) => string | undefined
  /** Number of pure-reload capability checks (`requireReloadOnly`). */
  reloadChecks: { value: number }
  /** `reload` and `restore` markers in call order. */
  reloads: string[]
  /** Concatenated staged tree content at each staged `sshd -t -f` call. */
  validatedTrees: string[]
}

export type FakeSshdHostOptions = {
  connectionUser?: string
  /** Effective directive lines printed while the drop-in is active. */
  desired: string
  /** Absolute path and marker of the module's drop-in. */
  dropInPath: string
  /** Account name to group names for `id -Gn --`; unknown accounts fail. */
  groups?: Record<string, string[]>
  /** Extra live directories (root:root 0755), e.g. a non-regular `*.conf` entry. */
  liveDirectories?: string[]
  /** Extra live files (root:root 0644). */
  liveFiles?: Record<string, string>
  mainConfig?: string
  marker: string
  /** Paths that `[ -L … ]` reports as symlinks (they also appear in glob results). */
  symlinks?: string[]
}

function hashOf(content: string): string {
  return createHash("sha256").update(content).digest("hex")
}

function byteOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
}

type Handler = (groups: string[]) => ExecResult
type Route = [RegExp, Handler]

export function createFakeSshdHost(options: FakeSshdHostOptions): FakeSshdHost {
  const files = new Map<string, FileEntry>()
  const directories = new Set<string>([
    "/",
    "/etc",
    "/etc/ssh",
    "/tmp",
    DROP_IN_DIRECTORY,
    ...(options.liveDirectories ?? []),
  ])
  const symlinks = new Set(options.symlinks ?? [])
  const commands: string[] = []
  const reloads: string[] = []
  const reloadChecks = { value: 0 }
  const validatedTrees: string[] = []
  const behavior: FakeSshdBehavior = { privilegeSeparation: true }
  const counter = { value: 0 }
  const put = (path: string, content: string, metadata = REGULAR_METADATA): void => {
    files.set(path, { content, metadata })
  }
  put(MAIN_CONFIG, options.mainConfig ?? DEFAULT_MAIN_CONFIG)
  for (const [path, content] of Object.entries(options.liveFiles ?? {})) put(path, content)

  const stagedTree = (): string =>
    [...files]
      .filter(([path]) => path.startsWith("/tmp/"))
      .map(([, entry]) => entry.content)
      .join("\n")
  const user = (spec: string | undefined): string | undefined =>
    /user=([^,]+)/v.exec(spec ?? "")?.[1]
  const fail = (stderr: string): ExecResult => ({ code: 1, stderr, stdout: "" })
  const out = (stdout: string): ExecResult => ({ code: 0, stderr: "", stdout })
  const liveEffective = (account: string | undefined): string => {
    if (behavior.liveEffective !== undefined) return behavior.liveEffective(account)
    return files.has(options.dropInPath) ? options.desired : ""
  }
  const stagedEffective = (account: string | undefined): string => {
    if (behavior.stagedEffective !== undefined) return behavior.stagedEffective(account)
    return stagedTree().includes(options.marker) ? options.desired : ""
  }

  const routes: Route[] = [
    [
      /^stat -c '%a %u %g' -- '(.*)'$/v,
      ([path]) => {
        if (directories.has(path)) return out(DIRECTORY_METADATA)
        const entry = files.get(path)
        return entry === undefined ? fail(`stat: ${path}: no such file`) : out(entry.metadata)
      },
    ],
    [
      /^mktemp -d -p '?([^' ]+)'? -- '(.+)\.XXXXXX'$/v,
      ([parent, prefix]) => {
        counter.value += 1
        const directory = `${parent}/${prefix}.T${String(counter.value)}`
        directories.add(directory)
        return out(directory)
      },
    ],
    [
      /^rm -rf -- '(.*)'$/v,
      ([directory]) => {
        directories.delete(directory)
        for (const path of [...files.keys()])
          if (path.startsWith(`${directory}/`)) files.delete(path)
        return OK
      },
    ],
    [
      /^rm (?:-f )?-- '(.*)'$/v,
      ([path]) => {
        files.delete(path)
        return OK
      },
    ],
    [
      /^chown 0:0 -- '(.*)' && chmod 0644 -- '(.*)'$/v,
      ([path]) => {
        const entry = files.get(path)
        if (entry === undefined) return fail(`chown: ${path}: no such file`)
        entry.metadata = REGULAR_METADATA
        return OK
      },
    ],
    [
      /^mv -T -- '(.*)' '(.*)'$/v,
      ([from, to]) => {
        const entry = files.get(from)
        if (entry === undefined) return fail(`mv: ${from}: no such file`)
        files.delete(from)
        files.set(to, entry)
        return OK
      },
    ],
    [
      /^cp -p --no-dereference -- '(.*)' '(.*)'$/v,
      ([from, to]) => {
        const entry = files.get(from)
        if (entry === undefined) return fail(`cp: ${from}: no such file`)
        files.set(to, { ...entry })
        return OK
      },
    ],
    [/^if \[ -e '.*' \]; then rmdir -- '.*'; fi$/v, () => OK],
    [
      /^for paratix_include in (\S+); do /v,
      ([pattern]) =>
        out(
          [...files.keys(), ...directories, ...symlinks]
            .filter((path) => !path.startsWith("/tmp/") && includeGlobMatches(pattern, path))
            .toSorted(byteOrder)
            // The shell keeps the pattern's spelling, e.g. a doubled slash.
            .map((path) => `${posix.dirname(pattern)}/${posix.basename(path)}\n`)
            .join("")
        ),
    ],
    [
      /^sshd -t -f '(.*)'$/v,
      () => {
        validatedTrees.push(stagedTree())
        return behavior.stagedTestFailure === undefined ? OK : fail(behavior.stagedTestFailure)
      },
    ],
    [/^sshd -T -f '(.*)'(?: -C '(.*)')?$/v, ([, spec]) => out(stagedEffective(user(spec)))],
    [
      /^id -Gn -- '(.*)'$/v,
      ([account]) => {
        const memberships = options.groups?.[account]
        return memberships === undefined
          ? fail(`id: '${account}': no such user`)
          : out(`${memberships.join(" ")}\n`)
      },
    ],
  ]

  const exec: SshConnection["exec"] = async (command) => {
    commands.push(command)
    const injected = behavior.failCommand?.(command)
    if (injected !== undefined) return fail(injected)
    for (const [pattern, handler] of routes) {
      const match = pattern.exec(command)
      if (match !== null) return handler(match.slice(1))
    }
    throw new Error(`fake sshd host: unexpected command ${command}`)
  }
  const base = createMockSsh({}, { strict: false })
  const connection: SshConnection = {
    ...base,
    exec,
    async exists(path) {
      return files.has(path) || directories.has(path)
    },
    getConnectionInfo: () => ({
      ...base.getConnectionInfo(),
      user: options.connectionUser ?? "root",
    }),
    async readFile(path) {
      const entry = files.get(path)
      if (entry === undefined) throw new Error(`fake sshd host: no such file ${path}`)
      return entry.content
    },
    async sha256(path) {
      const entry = files.get(path)
      return entry === undefined ? null : hashOf(entry.content)
    },
    async test(command) {
      commands.push(command)
      const match = /^\[ -([Lefd]) '(.*)' \]$/v.exec(command)
      if (match === null) throw new Error(`fake sshd host: unexpected test ${command}`)
      const [, flag, path] = match
      if (flag === "L") return symlinks.has(path)
      if (flag === "d") return directories.has(path)
      if (flag === "f") return files.has(path)
      return files.has(path) || directories.has(path)
    },
    async writeFile(path, content, writeOptions) {
      if (!directories.has(posix.dirname(path)))
        throw new Error(`fake sshd host: no such directory for ${path}`)
      put(path, content, `${(writeOptions?.mode ?? "0644").replace(/^0/v, "")} 0 0`)
    },
  }
  const transaction: SshdConfigTransaction = {
    connection,
    async preparePrivilegeSeparation() {
      return behavior.privilegeSeparation
    },
    readEffective: vi.fn(),
    async readEffectiveOutput(account) {
      return liveEffective(account)
    },
    reload: vi.fn(),
    async reloadOnly() {
      reloads.push("reload")
      if (behavior.reloadError !== undefined) throw new Error(behavior.reloadError)
    },
    async requireReloadOnly() {
      reloadChecks.value += 1
      if (behavior.reloadOnlyUnavailable !== undefined)
        throw new Error(behavior.reloadOnlyUnavailable)
    },
    async restoreReload() {
      reloads.push("restore")
      if (behavior.restoreError !== undefined) throw new Error(behavior.restoreError)
    },
    validate: vi.fn(),
  }
  return {
    behavior,
    commands,
    connection,
    files,
    install() {
      vi.spyOn(sshdModule, "withSshdConfigTransaction").mockImplementation(
        async (_connection, input) => input.section(transaction)
      )
    },
    live: (path) => files.get(path)?.content,
    reloadChecks,
    reloads,
    validatedTrees,
  }
}
