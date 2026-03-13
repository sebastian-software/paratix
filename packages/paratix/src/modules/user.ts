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
  const pwResult = await ssh.exec(`printf '%s\\n' ${shellQuote(credential)} | chpasswd`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (pwResult.code !== 0) return { status: "failed" }
  return null
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
        if (!ssh) return { status: "failed" }
        const removeFlag = options?.removeHome ? "--remove" : ""
        const result = await ssh.exec(`userdel ${removeFlag} ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
   * @param options.password - Plain-text password set via `chpasswd`.
   * @returns A Module that ensures the user account is present.
   */
  present(name: string, options?: UserOptions): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const flags = buildUserArguments(options)
        const exists = await ssh.test(`${ID_CMD} ${shellQuote(name)}`)
        const cmd = exists
          ? `usermod ${flags.join(" ")} ${shellQuote(name)}`
          : `useradd ${flags.join(" ")} --create-home ${shellQuote(name)}`

        const result = await ssh.exec(cmd, { ignoreExitCode: true, silent: true })
        if (result.code !== 0) return { status: "failed" }

        if (options?.password != null) {
          const failure = await setPassword(ssh, name, options.password)
          if (failure != null) return failure
        }

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${ID_CMD} ${shellQuote(name)}`)) ? "ok" : NEEDS_APPLY
      },
      name: `user.present: ${name}`,
    }
  },
}
