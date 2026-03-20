import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

type UserOptions = {
  groups?: string[]
  home?: string
  password?: string
  shell?: string
  uid?: number
}

const ID_CMD = "id"

function buildUserArguments(options?: UserOptions): string[] {
  const flags: string[] = []
  if (options?.uid != null) flags.push(`--uid ${String(options.uid)}`)
  if (options?.shell != null) flags.push(`--shell ${shellQuote(options.shell)}`)
  if (options?.home != null) flags.push(`--home ${shellQuote(options.home)}`)
  if (options?.groups != null) flags.push(`--groups ${shellQuote(options.groups.join(","))}`)
  return flags
}

async function setPassword(
  ssh: SshConnection,
  name: string,
  password: string
): Promise<ModuleResult | null> {
  const credential = [name, password].join(":")
  const pwResult = await ssh.exec(`printf '%s\\n' ${shellQuote(credential)} | chpasswd -e`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (pwResult.code !== 0) {
    return failedCommand(`[user.present: ${name}] chpasswd -e failed`, pwResult)
  }
  return null
}

function parsePasswdEntry(entry: string): { home: string; shell: string; uid: string } {
  const fields = entry.split(":")
  return { home: fields[5] ?? "", shell: fields[6] ?? "", uid: fields[2] ?? "" }
}

function groupsEqual(actual: Set<string>, desired: string[]): boolean {
  const expected = new Set(desired)
  return actual.size === expected.size && [...expected].every((g) => actual.has(g))
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

  if (options.groups != null) {
    const groupOutput = await ssh.output(`${ID_CMD} -Gn ${shellQuote(name)}`)
    const actual = new Set(groupOutput.split(/\s+/v).filter(Boolean))
    if (!groupsEqual(actual, options.groups)) return false
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[user.absent: ${name}] SSH connection is required`)
        const removeFlag = options?.removeHome ? "--remove" : ""
        const result = await ssh.exec(`userdel ${removeFlag} ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[user.absent: ${name}] userdel failed`, result)
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
   * @param name - The username.
   * @param options - Optional user account configuration.
   * @param options.uid - Desired numeric UID.
   * @param options.shell - Login shell path (e.g. `"/bin/bash"`).
   * @param options.home - Home directory path.
   * @param options.groups - Supplementary groups to add the user to.
   * @param options.password - Pre-hashed password (e.g. SHA-512 `$6$...`) set via `chpasswd -e`.
   * @returns A Module that ensures the user account is present.
   */
  present(name: string, options?: UserOptions): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[user.present: ${name}] SSH connection is required`)

        const flags = buildUserArguments(options)
        const exists = await ssh.test(`${ID_CMD} ${shellQuote(name)}`)
        const cmd = exists
          ? `usermod ${flags.join(" ")} ${shellQuote(name)}`
          : `useradd ${flags.join(" ")} --create-home ${shellQuote(name)}`

        const result = await ssh.exec(cmd, { ignoreExitCode: true, silent: true })
        if (result.code !== 0) {
          return failedCommand(
            `[user.present: ${name}] ${exists ? "usermod" : "useradd"} failed`,
            result
          )
        }

        if (options?.password != null) {
          const failure = await setPassword(ssh, name, options.password)
          if (failure != null) return failure
        }

        return { status: "changed" }
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
