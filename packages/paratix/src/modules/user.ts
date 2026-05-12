import { failed, failedCommand } from "../moduleFailure.js"
import { registerSecret, unregisterSecret } from "../secretSink.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { assertValidGroupName, assertValidUserName } from "./posixNames.js"

type UserOptions = {
  groups?: string[]
  home?: string
  password?: string
  shell?: string
  uid?: number
}

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

function assertValidUserOptions(options: UserOptions): void {
  if (options.uid != null) assertValidUid(options.uid)
  if (options.groups != null) {
    for (const group of options.groups) assertValidGroupName(group)
  }
  if (options.password != null) assertValidPasswordHash(options.password)
}

function buildUserArguments(mode: "useradd" | "usermod", options?: UserOptions): string[] {
  const flags: string[] = []
  if (options?.uid != null) flags.push(`--uid ${String(options.uid)}`)
  if (options?.shell != null) flags.push(`--shell ${shellQuote(options.shell)}`)
  if (options?.home != null) flags.push(`--home ${shellQuote(options.home)}`)
  if (options?.groups != null) {
    // For `usermod`, emit `--append --groups` so unrelated supplementary group
    // memberships (sudo, docker, manually added groups) are preserved across
    // re-applies. `useradd` does not accept `--append` and the new account has
    // no preexisting supplementary memberships to preserve.
    if (mode === "usermod") flags.push("--append")
    flags.push(`--groups ${shellQuote(options.groups.join(","))}`)
  }
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
): Promise<boolean> {
  const parsed = parsePasswdEntry(await ssh.output(`getent passwd ${shellQuote(name)}`))
  if (options.uid != null && parsed.uid !== String(options.uid)) return false
  if (options.home != null && parsed.home !== options.home) return false
  if (options.shell != null && parsed.shell !== options.shell) return false
  return true
}

async function shadowHashMatches(
  ssh: SshConnection,
  name: string,
  password: string
): Promise<boolean> {
  const shadowEntry = await ssh.output(`getent shadow ${shellQuote(name)}`)
  const currentHash = shadowEntry.split(":")[1] ?? ""
  return currentHash === password
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

async function attributesMatch(
  ssh: SshConnection,
  name: string,
  options: UserOptions
): Promise<boolean> {
  if (options.password != null && !(await shadowHashMatches(ssh, name, options.password))) {
    return false
  }

  const needsPasswdCheck = options.uid != null || options.shell != null || options.home != null
  if (needsPasswdCheck && !(await passwdAttributesMatch(ssh, name, options))) return false

  if (options.groups != null && !(await supplementaryGroupsMatch(ssh, name, options.groups))) {
    return false
  }

  return true
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
   * @param name - The username.
   * @param options - Optional user account configuration.
   * @param options.uid - Desired numeric UID.
   * @param options.shell - Login shell path (e.g. `"/bin/bash"`).
   * @param options.home - Home directory path.
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

        const exists = await ssh.test(`${ID_CMD} ${shellQuote(name)}`)
        const flags = buildUserArguments(exists ? "usermod" : "useradd", options)

        // R-0000088: track whether a mutating command actually ran so the
        // no-op path (user exists, no flags differ, no password set) returns
        // status "ok" instead of falsely reporting "changed".
        let mutationOccurred = false

        const mutationOutcome = await applyUserMutation({ exists, flags, name, ssh })
        if (mutationOutcome.kind === "failed") return mutationOutcome.result
        if (mutationOutcome.kind === "changed") mutationOccurred = true

        if (options?.password != null) {
          // setPassword has no pre-check, so any invocation is treated as a
          // mutation even when the resulting hash matches the existing one.
          const failure = await setPassword(ssh, name, options.password)
          if (failure != null) return failure
          mutationOccurred = true
        }

        return mutationOccurred ? { status: "changed" } : { status: "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        if (!(await ssh.test(`${ID_CMD} ${shellQuote(name)}`))) return NEEDS_APPLY
        if (options != null && !(await attributesMatch(ssh, name, options))) return NEEDS_APPLY
        return "ok"
      },
      name: `user.present: ${name}`,
    }
  },
}
