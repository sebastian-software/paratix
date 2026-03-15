import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

/**
 * Resolve a user's home directory by executing `getent passwd` on the remote host.
 *
 * @param conn - The SSH connection to use for the lookup.
 * @param user - The username to look up.
 * @returns The absolute path to the user's home directory.
 */
async function resolveHome(conn: SshConnection, user: string): Promise<string> {
  return conn.output(`getent passwd ${shellQuote(user)} | cut -d: -f6`)
}

/**
 * Modules for managing SSH client-side resources such as known hosts
 * and authorized keys.
 */
export const ssh = {
  /**
   * Ensure a public key is present in (or absent from) a user's `authorized_keys` file.
   *
   * When `state` is `"present"` (the default), the key is appended if missing and the
   * `.ssh` directory and `authorized_keys` file are created with correct ownership
   * and permissions. When `state` is `"absent"`, the matching line is removed.
   *
   * @param user - The target user whose `authorized_keys` file is managed.
   * @param key - The full public key string (e.g. `"ssh-ed25519 AAAA... comment"`).
   * @param options - Optional settings.
   * @param options.state - Whether the key should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @returns A Module that manages the authorized key entry.
   */
  authorizedKeys(user: string, key: string, options?: { state?: "absent" | "present" }): Module {
    const state = options?.state ?? "present"

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return { status: "failed" }

        const home = await resolveHome(conn, user)
        const directory = shellQuote(`${home}/.ssh`)
        const authKeysPath = shellQuote(`${home}/.ssh/authorized_keys`)
        const temporaryPath = shellQuote(`${home}/.ssh/authorized_keys.tmp`)

        if (state === "present") {
          await conn.exec(
            `mkdir -p ${directory} && chmod 700 ${directory} && chown ${shellQuote(user)}:${shellQuote(user)} ${directory}`,
            { silent: true }
          )
          await conn.exec(`printf '%s\\n' ${shellQuote(key)} >> ${authKeysPath}`, {
            silent: true,
          })
          await conn.exec(
            `chmod 600 ${authKeysPath} && chown ${shellQuote(user)}:${shellQuote(user)} ${authKeysPath}`,
            { silent: true }
          )
        } else {
          await conn.exec(
            `{ grep -vF -- ${shellQuote(key)} ${authKeysPath} || true; } > ${temporaryPath} && mv ${temporaryPath} ${authKeysPath}`,
            { silent: true }
          )
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const home = await resolveHome(conn, user)
        const authKeysPath = shellQuote(`${home}/.ssh/authorized_keys`)

        const keyExists = await conn.test(`grep -qF -- ${shellQuote(key)} ${authKeysPath}`)

        if (state === "present") {
          return keyExists ? "ok" : NEEDS_APPLY
        }
        return keyExists ? NEEDS_APPLY : "ok"
      },
      name: `ssh.authorizedKeys: ${user} (${state})`,
    }
  },

  /**
   * Ensure a host is present in (or absent from) the connecting user's `~/.ssh/known_hosts`.
   *
   * When `state` is `"present"` (the default), the host's public keys are fetched
   * via `ssh-keyscan` and appended to `~/.ssh/known_hosts`. When `state` is
   * `"absent"`, the host entry is removed via `ssh-keygen -R`.
   *
   * @param host - The hostname or IP address to manage.
   * @param options - Optional settings.
   * @param options.state - Whether the host should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @returns A Module that manages the known hosts entry.
   */
  knownHosts(host: string, options?: { state?: "absent" | "present" }): Module {
    const state = options?.state ?? "present"

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return { status: "failed" }

        if (state === "present") {
          await conn.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh", { silent: true })
          await conn.exec(`ssh-keyscan -H ${shellQuote(host)} >> ~/.ssh/known_hosts 2>/dev/null`, {
            silent: true,
          })
        } else {
          await conn.exec(`ssh-keygen -R ${shellQuote(host)}`, { silent: true })
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        const hostKnown = await conn.test(`ssh-keygen -F ${shellQuote(host)}`)

        if (state === "present") {
          return hostKnown ? "ok" : NEEDS_APPLY
        }
        return hostKnown ? NEEDS_APPLY : "ok"
      },
      name: `ssh.knownHosts: ${host} (${state})`,
    }
  },
}
