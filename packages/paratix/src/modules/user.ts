/* eslint-disable max-lines -- user module keeps account validation, mutation and home-mode enforcement together for cohesion */
import { failed, failedCommand } from "../moduleFailure.js"
import { registerSecret, unregisterSecret } from "../secretSink.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { assertValidGroupName, assertValidUserName } from "./posixNames.js"

type UserOptions = {
  groups?: string[]
  home?: string
  // R-0000656: dot-files inside a freshly created home directory inherit the
  // mode determined by `useradd`'s `HOME_MODE` setting in /etc/login.defs,
  // which defaults to `0755` on Debian/Ubuntu. That leaves user secrets like
  // `~/.ssh/authorized_keys` readable by other local accounts on the same
  // host. Accept an explicit per-user mode and enforce it after useradd /
  // usermod so the result does not depend on the runner host's login.defs.
  homeMode?: string
  password?: string
  shell?: string
  uid?: number
}

// R-0000656: chmod accepts octal permissions in 3- or 4-digit form
// (e.g. `0700`, `750`). Reject anything else so a typo cannot reach
// `chmod` and silently apply a wrong mode (or no mode at all because
// chmod parses the leading characters and ignores trailing garbage).
const HOME_MODE_PATTERN = /^0?[0-7]{3}$/v

// R-0000656: when the caller does not specify a mode we still want
// to enforce a safe default so an unrelated /etc/login.defs change on
// the runner host cannot widen permissions of all managed homes.
const DEFAULT_HOME_MODE = "0700"

const ID_CMD = "id"

// R-0000120: validate the `uid` and `groups` options at construction time so
// numeric drift (NaN, negative, fractional, > 2^32) and group-name injection
// (commas, newlines, flag-shaped values) cannot reach the `useradd` /
// `usermod` argument vector. uid_t is a 32-bit unsigned integer on Linux, so
// any value outside [0, 2^32) would be silently truncated by `useradd --uid`.
const UID_BIT_WIDTH = 32
const UID_MAX_EXCLUSIVE = 2 ** UID_BIT_WIDTH

function assertValidUid(uid: number): void {
  if (!Number.isInteger(uid) || uid < 0 || uid >= UID_MAX_EXCLUSIVE) {
    throw new Error(`uid ${JSON.stringify(uid)} is invalid`)
  }
}

function assertValidPasswordHash(password: string): void {
  if (password.length === 0 || /[:\r\n]/v.test(password)) {
    throw new Error("password hash is invalid")
  }
}

// R-0000652: both `--shell` and `--home` end up as fields in `/etc/passwd`, a
// colon-separated record terminated by a newline. A newline in either value
// would split the passwd entry and corrupt the file format; a colon would
// shift subsequent fields (uid, gid, gecos, ...) by one column. useradd does
// not perform this validation itself, so reject control characters and
// relative paths at construction time before the strings reach the argument
// vector.
function assertValidShellPath(shell: string): void {
  if (!shell.startsWith("/") || /[:\r\n]/v.test(shell)) {
    throw new Error(`shell path ${JSON.stringify(shell)} is invalid`)
  }
}

function assertValidHomePath(home: string): void {
  if (!home.startsWith("/") || /[:\r\n]/v.test(home)) {
    throw new Error(`home path ${JSON.stringify(home)} is invalid`)
  }
}

// R-0000656: limit `homeMode` to the octal triplets chmod accepts so a
// typo cannot reach the remote shell. `0` prefix is optional.
function assertValidHomeMode(mode: string): void {
  if (!HOME_MODE_PATTERN.test(mode)) {
    throw new Error(`home mode ${JSON.stringify(mode)} is invalid`)
  }
}

function assertValidUserOptions(options: UserOptions): void {
  if (options.uid != null) assertValidUid(options.uid)
  if (options.shell != null) assertValidShellPath(options.shell)
  if (options.home != null) assertValidHomePath(options.home)
  if (options.homeMode != null) {
    assertValidHomeMode(options.homeMode)
    // R-0000656: `homeMode` is only meaningful when we know the home path
    // (so we can `chmod` it). Reject the orphan combination at construction
    // time instead of silently ignoring the mode at apply time.
    if (options.home == null) {
      throw new Error("homeMode requires home to be set")
    }
  }
  if (options.groups != null) {
    for (const group of options.groups) assertValidGroupName(group)
  }
  if (options.password != null) assertValidPasswordHash(options.password)
}

// R-0000656: strip a single leading `0` so values like `"0700"` and `"700"`
// compare equal. Mirrors the `normalizeMode` helper used in the timer and
// systemd modules.
function normalizeHomeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

// R-0000546: `--groups ''` is rejected by useradd/usermod with
// "invalid argument", which would surface as a generic failedCommand
// even though the corresponding `check` reports the empty list as
// already satisfied. Skip the flag entirely when no groups are
// requested so empty arrays behave idempotently across check/apply.
function buildGroupsFlags(mode: "useradd" | "usermod", groups: string[] | undefined): string[] {
  if (groups == null || groups.length === 0) return []
  const flags: string[] = []
  // For `usermod`, emit `--append --groups` so unrelated supplementary group
  // memberships (sudo, docker, manually added groups) are preserved across
  // re-applies. `useradd` does not accept `--append` and the new account has
  // no preexisting supplementary memberships to preserve.
  if (mode === "usermod") flags.push("--append")
  flags.push(`--groups ${shellQuote(groups.join(","))}`)
  return flags
}

function buildUserArguments(mode: "useradd" | "usermod", options?: UserOptions): string[] {
  const flags: string[] = []
  if (options?.uid != null) flags.push(`--uid ${String(options.uid)}`)
  if (options?.shell != null) flags.push(`--shell ${shellQuote(options.shell)}`)
  if (options?.home != null) {
    flags.push(`--home ${shellQuote(options.home)}`)
    // R-0000656: `usermod --home /new/path` rewrites only the passwd entry
    // and leaves the previous home directory and its contents in place,
    // so the user ends up pointing at an empty directory. Combine with
    // `--move-home` so the existing contents (dot-files, mail spool,
    // installed user data) follow the account to the new location.
    // `useradd --create-home` already populates the new home, so the
    // flag is only emitted for usermod.
    if (mode === "usermod") flags.push("--move-home")
  }
  flags.push(...buildGroupsFlags(mode, options?.groups))
  return flags
}

/**
 * Apply a pre-hashed password via `chpasswd -e`. The hash is written to the
 * SSH stream's stdin instead of being inlined into the command argument so it
 * never appears in `/var/log/auth.log`, `ps -ef`, or `/proc/<pid>/cmdline`.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param name - The username whose password should be set.
 * @param password - The pre-hashed password value (e.g. SHA-512 `$6$...`).
 * @returns `null` on success, or a failure result when `chpasswd` rejects the
 *   hash. The hash is registered as a secret so any failure path masks it.
 */
async function setPassword(
  ssh: SshConnection,
  name: string,
  password: string
): Promise<ModuleResult | null> {
  // R-0000041: register the hash with the process-scoped secret sink so any
  // subsequent generic stderr output (printCommandFailure /
  // printVerboseGenericError) masks it, even when the surfacing error is not
  // a CommandError emitted by ssh.exec.
  registerSecret(password)
  try {
    const credential = [name, password].join(":")
    const pwResult = await ssh.exec(`chpasswd -e`, {
      ignoreExitCode: true,
      input: `${credential}\n`,
      secrets: [password],
      silent: true,
    })
    if (pwResult.code !== 0) {
      return failedCommand(`[user.present: ${name}] chpasswd -e failed`, pwResult, [password])
    }
    return null
  } finally {
    unregisterSecret(password)
  }
}

function parsePasswdEntry(entry: string): { home: string; shell: string; uid: string } {
  const fields = entry.split(":")
  return { home: fields[5] ?? "", shell: fields[6] ?? "", uid: fields[2] ?? "" }
}

function groupsContain(actual: Set<string>, desired: string[]): boolean {
  // Additive (subset) semantics: the user must be a member of every desired
  // group, but extra unrelated memberships (sudo, docker, manually added
  // groups) are tolerated. Mirrors the `usermod --append --groups` apply path.
  return desired.every((g) => actual.has(g))
}

// R-0000776 / R-0000777: the structured comparison helpers share the
// `AttributesMatchOutcome` discriminator with `shadowHashMatches` /
// `attributesMatch`. `mismatch` keeps the old "needs-apply" verdict, `match`
// keeps the old "ok" verdict, and `toolchain-error` surfaces a getent/id
// failure as a structured ModuleResult instead of falsely returning a
// mismatch (which would loop the apply on a host where the lookup itself is
// broken).

async function supplementaryGroupsMatch(
  ssh: SshConnection,
  name: string,
  desiredGroups: string[]
): Promise<boolean> {
  const groupOutput = await ssh.output(`${ID_CMD} -Gn ${shellQuote(name)}`)
  const primaryGroup = await ssh.output(`${ID_CMD} -gn ${shellQuote(name)}`)
  const actualSupplementaryGroups = new Set(
    groupOutput
      .split(/\s+/v)
      .filter(Boolean)
      .filter((group) => group !== primaryGroup)
  )
  return groupsContain(actualSupplementaryGroups, desiredGroups)
}

async function passwdAttributesMatch(
  ssh: SshConnection,
  name: string,
  options: UserOptions
): Promise<AttributesMatchOutcome> {
  // R-0000776: route the passwd lookup through `ssh.exec` with
  // `ignoreExitCode` so a non-zero `getent passwd` (NSS misconfiguration,
  // missing user mid-comparison, sudoers restriction) does not surface as an
  // unstructured SSH error. Inspect the field count too: a truncated entry
  // with fewer than 7 fields means the line is malformed and the comparison
  // can no longer trust the parsed values.
  const passwdResult = await ssh.exec(`getent passwd ${shellQuote(name)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (passwdResult.code !== 0) {
    return {
      failure: failedCommand(
        `[user.present: ${name}] getent passwd failed during attribute comparison`,
        passwdResult
      ),
      kind: TOOLCHAIN_ERROR,
    }
  }
  const entry = passwdResult.stdout.trim()
  if (entry.split(":").length < 7) {
    return {
      failure: failed(
        `[user.present: ${name}] getent passwd returned a malformed entry with fewer than 7 fields`
      ),
      kind: TOOLCHAIN_ERROR,
    }
  }
  const parsed = parsePasswdEntry(entry)
  if (options.uid != null && parsed.uid !== String(options.uid)) return { kind: "mismatch" }
  if (options.home != null && parsed.home !== options.home) return { kind: "mismatch" }
  if (options.shell != null && parsed.shell !== options.shell) return { kind: "mismatch" }
  return { kind: "match" }
}

// R-0000657: result of the server-side shadow-hash comparison. `cmp` reports
// exit 0 when the hashes match byte-for-byte, exit 1 when they differ, and
// exit ≥ 2 for hard errors (missing input file, unreadable shadow line, etc.).
// A failed `bash -c` invocation — missing `bash`, broken process substitution,
// or a permission error reading `/etc/shadow` — manifests as an exit code
// outside the 0/1 set or as an exception from `ssh.exec`. Treating any
// non-zero exit as "mismatch" caused the module to re-set the password on
// every run when the toolchain was broken; differentiate the three outcomes
// so the caller can react accordingly.
// R-0000657: shared discriminator for the toolchain-error variant so the
// literal lives in one place and the sonarjs duplicate-string rule does
// not flag every occurrence.
const TOOLCHAIN_ERROR = "toolchain-error" as const

type ShadowHashCompareResult =
  | { failure: ModuleResult; kind: typeof TOOLCHAIN_ERROR }
  | { kind: "match" }
  | { kind: "mismatch" }

async function shadowHashMatches(
  ssh: SshConnection,
  name: string,
  password: string
): Promise<ShadowHashCompareResult> {
  // R-0000544: compare the shadow hash server-side so the raw hash never
  // travels back as stdout (where it could land in failure snippets or
  // verbose-error output). The new hash is streamed in via stdin (masked as
  // a secret) and the comparison is performed in a tiny bash script: extract
  // the stored hash with `getent shadow | cut -d: -f2`, then `cmp -s` it
  // against the stdin payload via process substitution. Only the exit code
  // flows back over SSH; the raw hashes never appear in stdout or stderr.
  //
  // R-0000657: distinguish three exit-code classes — 0 (match), 1 (mismatch),
  // ≥ 2 or spawn error (toolchain problem). For the toolchain class, surface
  // a structured failure instead of silently falling back to "mismatch" so
  // idempotency is preserved when bash, getent, cmp, or process substitution
  // is unavailable.
  registerSecret(password)
  try {
    // Run the comparison through `bash -c` so process substitution `<()` is
    // available regardless of the login shell of the remote user. `getent
    // shadow` terminates its line with a newline that `cut` preserves, so
    // the caller-provided hash is forwarded with a trailing newline to keep
    // both inputs byte-for-byte comparable.
    const compareScript = `set -o pipefail
cmp -s <(getent shadow ${shellQuote(name)} | cut -d: -f2) -`
    let result: Awaited<ReturnType<typeof ssh.exec>>
    try {
      result = await ssh.exec(`bash -c ${shellQuote(compareScript)}`, {
        ignoreExitCode: true,
        input: `${password}\n`,
        secrets: [password],
        silent: true,
      })
    } catch (error) {
      // A thrown exception here means the SSH transport rejected the command
      // outright (network drop, spawn failure) — treat as a toolchain error
      // so the caller can fail fast instead of looping over a doomed apply.
      const detail = error instanceof Error ? error.message : String(error)
      return {
        failure: failed(`[user.present: ${name}] shadow hash comparison failed: ${detail}`),
        kind: TOOLCHAIN_ERROR,
      }
    }
    if (result.code === 0) return { kind: "match" }
    if (result.code === 1) return { kind: "mismatch" }
    return {
      failure: failedCommand(
        `[user.present: ${name}] shadow hash comparison toolchain error`,
        result,
        [password]
      ),
      kind: TOOLCHAIN_ERROR,
    }
  } finally {
    unregisterSecret(password)
  }
}

type UserMutationContext = {
  exists: boolean
  flags: string[]
  name: string
  ssh: SshConnection
}

type UserMutationOutcome =
  | { kind: "changed" }
  | { kind: "failed"; result: ModuleResult }
  | { kind: "noop" }

/**
 * Run `useradd` or `usermod` to bring the user account into the desired state.
 *
 * When the user already exists and `flags` is empty (e.g. only a password
 * change has been requested), the call is skipped entirely. `usermod ${name}`
 * without any flags would otherwise fail with `usermod: no flags given`.
 *
 * @param context - The mutation context (ssh handle, username, existence flag, rendered flags).
 * @returns A discriminated outcome: `noop` when no command was executed,
 *   `changed` when `useradd` / `usermod` ran successfully, or `failed` with the
 *   failure result when the command exited non-zero.
 */
async function applyUserMutation(context: UserMutationContext): Promise<UserMutationOutcome> {
  const { exists, flags, name, ssh } = context
  if (exists && flags.length === 0) return { kind: "noop" }

  const cmd = exists
    ? `usermod ${flags.join(" ")} ${shellQuote(name)}`
    : `useradd ${flags.join(" ")} --create-home ${shellQuote(name)}`

  const result = await ssh.exec(cmd, { ignoreExitCode: true, silent: true })
  if (result.code !== 0) {
    return {
      kind: "failed",
      result: failedCommand(
        `[user.present: ${name}] ${exists ? "usermod" : "useradd"} failed`,
        result
      ),
    }
  }
  return { kind: "changed" }
}

// R-0000657: discriminated outcome of `attributesMatch`. The toolchain-error
// variant lets the caller distinguish "the shadow hash compare blew up" from
// the regular match/mismatch verdict so check phase can surface a structured
// failure instead of falsely returning `needs-apply`.
type AttributesMatchOutcome =
  | { failure: ModuleResult; kind: typeof TOOLCHAIN_ERROR }
  | { kind: "match" }
  | { kind: "mismatch" }

async function attributesMatch(
  ssh: SshConnection,
  name: string,
  options: UserOptions
): Promise<AttributesMatchOutcome> {
  const passwordOutcome = await passwordHashOutcome(ssh, name, options)
  if (passwordOutcome != null) return passwordOutcome
  const passwdGroupsOutcome = await passwdAndGroupsMatch(ssh, name, options)
  if (passwdGroupsOutcome.kind !== "match") return passwdGroupsOutcome
  // R-0000656: when a home directory is being managed, the mode on disk
  // must also match the (default or explicit) homeMode; otherwise an
  // earlier apply that ran on a host with HOME_MODE=0755 in
  // /etc/login.defs would leave dot-files world-readable until the next
  // mismatch on another attribute forces a reapply.
  if (!(await managedHomeModeMatches(ssh, options))) return { kind: "mismatch" }
  return { kind: "match" }
}

async function passwordHashOutcome(
  ssh: SshConnection,
  name: string,
  options: UserOptions
): Promise<AttributesMatchOutcome | null> {
  if (options.password == null) return null
  const shadow = await shadowHashMatches(ssh, name, options.password)
  if (shadow.kind === TOOLCHAIN_ERROR) {
    return { failure: shadow.failure, kind: TOOLCHAIN_ERROR }
  }
  if (shadow.kind === "mismatch") return { kind: "mismatch" }
  return null
}

async function passwdAndGroupsMatch(
  ssh: SshConnection,
  name: string,
  options: UserOptions
): Promise<AttributesMatchOutcome> {
  const needsPasswdCheck = options.uid != null || options.shell != null || options.home != null
  if (needsPasswdCheck) {
    const passwdOutcome = await passwdAttributesMatch(ssh, name, options)
    if (passwdOutcome.kind !== "match") return passwdOutcome
  }
  if (options.groups != null && !(await supplementaryGroupsMatch(ssh, name, options.groups))) {
    return { kind: "mismatch" }
  }
  return { kind: "match" }
}

async function managedHomeModeMatches(ssh: SshConnection, options: UserOptions): Promise<boolean> {
  if (options.home == null) return true
  const desiredMode = options.homeMode ?? DEFAULT_HOME_MODE
  return homeModeMatches(ssh, options.home, desiredMode)
}

// R-0000656: `stat -c '%a' <path>` reports octal permission bits without
// leading zeros. A failure to read the mode (missing directory, stat error,
// empty output) counts as mismatch so apply can recreate or fix the home.
async function homeModeMatches(
  ssh: SshConnection,
  home: string,
  desiredMode: string
): Promise<boolean> {
  const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(home)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (modeResult.code !== 0) return false
  const currentMode = modeResult.stdout.trim()
  if (currentMode === "") return false
  return normalizeHomeMode(currentMode) === normalizeHomeMode(desiredMode)
}

// R-0000656: enforce the desired home mode after useradd/usermod so the
// permission bits do not depend on the runner host's HOME_MODE setting in
// /etc/login.defs. `chmod` is idempotent; running it on a home that
// already matches is harmless.
async function applyHomeMode(
  ssh: SshConnection,
  parameters: { home: string; mode: string; name: string }
): Promise<ModuleResult | null> {
  const { home, mode, name } = parameters
  const result = await ssh.exec(`chmod ${shellQuote(mode)} ${shellQuote(home)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  return failedCommand(`[user.present: ${name}] chmod home failed`, result)
}

// R-0000656: pre-check the home mode and chmod only when it differs so
// steady-state applies do not flip status from "ok" to "changed".
async function ensureHomeMode(
  ssh: SshConnection,
  parameters: { home: string; mode: string; name: string }
): Promise<{ kind: "changed" } | { kind: "failed"; result: ModuleResult } | { kind: "noop" }> {
  if (await homeModeMatches(ssh, parameters.home, parameters.mode)) {
    return { kind: "noop" }
  }
  const failure = await applyHomeMode(ssh, parameters)
  if (failure != null) return { kind: "failed", result: failure }
  return { kind: "changed" }
}

type PresentMutationStep =
  | { failure: ModuleResult; kind: "failed" }
  | { kind: "changed" }
  | { kind: "noop" }

async function runUserMutationStep(
  ssh: SshConnection,
  parameters: { name: string; options: undefined | UserOptions }
): Promise<PresentMutationStep> {
  const { name, options } = parameters
  const exists = await ssh.test(`${ID_CMD} ${shellQuote(name)}`)
  const flags = buildUserArguments(exists ? "usermod" : "useradd", options)
  const outcome = await applyUserMutation({ exists, flags, name, ssh })
  if (outcome.kind === "failed") return { failure: outcome.result, kind: "failed" }
  return outcome.kind === "changed" ? { kind: "changed" } : { kind: "noop" }
}

// R-0000656: enforce homeMode after useradd/usermod has settled the home
// path so the result is independent of the runner host's HOME_MODE in
// /etc/login.defs.
async function runHomeModeStep(
  ssh: SshConnection,
  parameters: { name: string; options: undefined | UserOptions }
): Promise<PresentMutationStep> {
  const { name, options } = parameters
  if (options?.home == null) return { kind: "noop" }
  const outcome = await ensureHomeMode(ssh, {
    home: options.home,
    mode: options.homeMode ?? DEFAULT_HOME_MODE,
    name,
  })
  if (outcome.kind === "failed") return { failure: outcome.result, kind: "failed" }
  return outcome.kind === "changed" ? { kind: "changed" } : { kind: "noop" }
}

async function runPasswordStep(
  ssh: SshConnection,
  parameters: { name: string; options: undefined | UserOptions }
): Promise<PresentMutationStep> {
  const { name, options } = parameters
  if (options?.password == null) return { kind: "noop" }
  // setPassword has no pre-check, so any invocation is treated as a
  // mutation even when the resulting hash matches the existing one.
  const failure = await setPassword(ssh, name, options.password)
  if (failure != null) return { failure, kind: "failed" }
  return { kind: "changed" }
}

async function applyPresentMutations(
  ssh: SshConnection,
  parameters: { name: string; options: undefined | UserOptions }
): Promise<ModuleResult> {
  // R-0000088: track whether a mutating command actually ran so the no-op
  // path (user exists, no flags differ, no password set) returns status
  // "ok" instead of falsely reporting "changed".
  let mutationOccurred = false
  const steps = [runUserMutationStep, runHomeModeStep, runPasswordStep] as const
  for (const step of steps) {
    // eslint-disable-next-line no-await-in-loop -- steps mutate remote state and must run sequentially
    const outcome = await step(ssh, parameters)
    if (outcome.kind === "failed") return outcome.failure
    if (outcome.kind === "changed") mutationOccurred = true
  }
  return mutationOccurred ? { status: "changed" } : { status: "ok" }
}

/**
 * Modules for managing Linux user accounts.
 */
export const user = {
  /**
   * Ensure a user account does not exist. Removes the account via `userdel`.
   *
   * @param name - The username to remove.
   * @param options - Optional removal configuration.
   * @param options.removeHome - When `true`, also delete the user's home directory.
   * @returns A Module that ensures the user account is absent.
   */
  absent(name: string, options?: { removeHome?: boolean }): Module {
    // R-0000119: validate the username synchronously at construction time so
    // flag-shaped names cannot slip past `userdel` argument parsing.
    assertValidUserName(name)
    // R-0000077: userdel returns exit code 6 ("specified user doesn't
    // exist") when the account has already been removed. Treat this case
    // as idempotent success — both by probing `id` first to mirror
    // cron.absent's early-return pattern, and by mapping exit code 6 to
    // status ok as a defensive fallback when the user is removed between
    // the probe and the userdel call.
    const USERDEL_NOT_FOUND_EXIT_CODE = 6
    // R-0000545: userdel exits with 8 ("user currently logged in" /
    // "user has active processes") when the kernel still has running
    // processes owned by the target uid. The raw shadow/utmp message is
    // not actionable, so the runner surfaces an explicit hint instead.
    const USERDEL_USER_BUSY_EXIT_CODE = 8
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[user.absent: ${name}] SSH connection is required`)
        if (!(await ssh.test(`${ID_CMD} ${shellQuote(name)}`))) return { status: "ok" }
        const removeFlag = options?.removeHome ? "--remove" : ""
        const result = await ssh.exec(`userdel ${removeFlag} ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code === 0) return { status: "changed" }
        if (result.code === USERDEL_NOT_FOUND_EXIT_CODE) return { status: "ok" }
        if (result.code === USERDEL_USER_BUSY_EXIT_CODE) {
          return failed(
            `[user.absent: ${name}] userdel reported user has active processes; ` +
              `stop them (e.g. via 'pkill -KILL -u ${name}') before removing the account`
          )
        }
        return failedCommand(`[user.absent: ${name}] userdel failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${ID_CMD} ${shellQuote(name)}`)) ? NEEDS_APPLY : "ok"
      },
      name: `user.absent: ${name}`,
    }
  },

  /**
   * Ensure a user account exists. Creates the account if absent, or runs
   * `usermod` to update attributes if the user already exists.
   *
   * Supplementary group membership is additive: when `options.groups` is set
   * and the user already exists, `usermod --append --groups <list>` is used so
   * preexisting memberships not managed by Paratix (e.g. `sudo`, `docker`,
   * manually added groups) are preserved across re-applies. The `groups`
   * option therefore expresses "ensure the user is a member of these groups",
   * not "the user must be a member of exactly these supplementary groups".
   *
   * When `home` is provided, `usermod --move-home` migrates the existing
   * contents to the new path (instead of leaving the user pointing at an
   * empty directory with the old contents stranded on disk). The home
   * directory's permission bits are then enforced via `chmod`; the default
   * mode is `0700` so dot-files in a freshly created home cannot be read
   * by other local accounts even on hosts where `/etc/login.defs` sets
   * `HOME_MODE=0755`.
   *
   * @param name - The username.
   * @param options - Optional user account configuration.
   * @param options.uid - Desired numeric UID.
   * @param options.shell - Login shell path (e.g. `"/bin/bash"`).
   * @param options.home - Home directory path.
   * @param options.homeMode - Octal permission bits for the home directory
   *   (e.g. `"0700"`, `"750"`). Requires `home`. Defaults to `"0700"`.
   * @param options.groups - Supplementary groups to add the user to (additive).
   * @param options.password - Pre-hashed password (e.g. SHA-512 `$6$...`) set via `chpasswd -e`.
   * @returns A Module that ensures the user account is present.
   */
  present(name: string, options?: UserOptions): Module {
    // R-0000119: validate the username synchronously at construction time so
    // flag-shaped names cannot slip past `useradd` / `usermod` argument
    // parsing.
    assertValidUserName(name)
    // R-0000120: validate uid and group names synchronously at construction
    // time so out-of-range / non-integer uids and injection-shaped group
    // names (commas, newlines, leading flags) cannot reach
    // `useradd`/`usermod --groups`.
    if (options != null) assertValidUserOptions(options)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[user.present: ${name}] SSH connection is required`)
        return applyPresentMutations(ssh, { name, options })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        if (!(await ssh.test(`${ID_CMD} ${shellQuote(name)}`))) return NEEDS_APPLY
        if (options != null) {
          const outcome = await attributesMatch(ssh, name, options)
          // R-0000657: surface a shadow-hash comparison toolchain failure
          // (missing cmp, broken bash process substitution, permission
          // error) as a structured runner error instead of looping the
          // module through `needs-apply` -> apply -> setPassword on every
          // run when the compare cannot be executed.
          if (outcome.kind === TOOLCHAIN_ERROR) {
            throw (
              outcome.failure.error ??
              new Error(`[user.present: ${name}] shadow hash comparison failed`)
            )
          }
          if (outcome.kind === "mismatch") return NEEDS_APPLY
        }
        return "ok"
      },
      name: `user.present: ${name}`,
    }
  },
}
