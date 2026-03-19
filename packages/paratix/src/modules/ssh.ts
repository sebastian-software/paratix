import { computeFingerprint } from "../knownHosts.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

type KnownHostsOptions = {
  expectedFingerprint?: string
  publicKey?: string
  state?: "absent" | "present"
}

const SSH_KEYSCAN_MIN_FIELDS = 3

function normalizePublicKey(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/v)
  if (parts.length < 2) {
    throw new Error(
      "ssh.knownHosts requires a full public key in the format '<algorithm> <base64>'"
    )
  }
  const [algorithm, key] = parts
  return `${algorithm} ${key}`
}

function parseHostKeyLines(output: string): string[] {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
}

function scannedLinePublicKey(line: string): string {
  const parts = line.split(/\s+/v)
  if (parts.length < SSH_KEYSCAN_MIN_FIELDS) {
    throw new Error(`ssh.knownHosts received invalid ssh-keyscan output: ${line}`)
  }
  const [, algorithm, key] = parts
  return `${algorithm} ${key}`
}

function scannedLineFingerprint(line: string): string {
  const publicKey = scannedLinePublicKey(line)
  const [, key] = publicKey.split(" ")
  return computeFingerprint(Buffer.from(key, "base64"))
}

function verifyScannedHostKeys(
  host: string,
  scannedLines: string[],
  options: KnownHostsOptions
): void {
  const normalizedExpectedKey =
    options.publicKey == null ? null : normalizePublicKey(options.publicKey)
  const expectedFingerprint = options.expectedFingerprint

  if (normalizedExpectedKey == null && expectedFingerprint == null) {
    throw new Error(
      `ssh.knownHosts(${host}) requires expectedFingerprint or publicKey before accepting ssh-keyscan output`
    )
  }

  const matched = scannedLines.some((line) => {
    const publicKeyMatches =
      normalizedExpectedKey != null && scannedLinePublicKey(line) === normalizedExpectedKey
    const fingerprintMatches =
      expectedFingerprint != null && scannedLineFingerprint(line) === expectedFingerprint
    return publicKeyMatches || fingerprintMatches
  })

  if (!matched) {
    throw new Error(
      `ssh.knownHosts(${host}) could not verify the scanned host key against the provided trust anchor`
    )
  }
}

function hasKnownHostsTrustAnchor(options?: KnownHostsOptions): boolean {
  return options?.expectedFingerprint != null || options?.publicKey != null
}

async function hasMatchingKnownHostTrustAnchor(
  conn: SshConnection,
  host: string,
  options: KnownHostsOptions
): Promise<boolean> {
  const knownHostOutput = await conn.output(`ssh-keygen -F ${shellQuote(host)}`)
  const knownHostLines = parseHostKeyLines(knownHostOutput)

  if (knownHostLines.length === 0) return false

  try {
    verifyScannedHostKeys(host, knownHostLines, options)
    return true
  } catch {
    return false
  }
}

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

async function createAuthorizedKeysTemporaryPath(conn: SshConnection): Promise<string> {
  await conn.exec("install -d -m 700 /run/paratix", { silent: true })
  return conn.output("mktemp /run/paratix/authorized-keys.XXXXXX")
}

async function ensureAuthorizedKeysIsNotSymlink(
  conn: SshConnection,
  authorizedKeysPath: string
): Promise<void> {
  await conn.exec(
    `[ ! -L ${shellQuote(authorizedKeysPath)} ] || { echo 'authorized_keys must not be a symlink' >&2; exit 1; }`,
    { silent: true }
  )
}

async function rewriteAuthorizedKeys(
  conn: SshConnection,
  parameters: {
    authorizedKeysPath: string
    key: string
    state: "absent" | "present"
    user: string
  }
): Promise<void> {
  const { authorizedKeysPath, key, state, user } = parameters
  const temporaryPath = await createAuthorizedKeysTemporaryPath(conn)

  try {
    if (state === "present") {
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then cat ${shellQuote(authorizedKeysPath)}; fi; printf '%s\\n' ${shellQuote(key)}; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    } else {
      await conn.exec(
        `{ if [ -f ${shellQuote(authorizedKeysPath)} ]; then grep -vF -- ${shellQuote(key)} ${shellQuote(authorizedKeysPath)} || true; fi; } > ${shellQuote(temporaryPath)}`,
        { silent: true }
      )
    }

    await conn.exec(
      `chmod 600 ${shellQuote(temporaryPath)} && chown ${shellQuote(user)}:${shellQuote(user)} ${shellQuote(temporaryPath)} && mv ${shellQuote(temporaryPath)} ${shellQuote(authorizedKeysPath)} && chmod 600 ${shellQuote(authorizedKeysPath)} && chown ${shellQuote(user)}:${shellQuote(user)} ${shellQuote(authorizedKeysPath)}`,
      { silent: true }
    )
  } finally {
    await conn.exec(`rm -f ${shellQuote(temporaryPath)}`, { silent: true })
  }
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
        const authorizedKeysPath = `${home}/.ssh/authorized_keys`

        await conn.exec(
          `mkdir -p ${directory} && chmod 700 ${directory} && chown ${shellQuote(user)}:${shellQuote(user)} ${directory}`,
          { silent: true }
        )
        await ensureAuthorizedKeysIsNotSymlink(conn, authorizedKeysPath)
        await rewriteAuthorizedKeys(conn, { authorizedKeysPath, key, state, user })

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
  knownHosts(host: string, options?: KnownHostsOptions): Module {
    const state = options?.state ?? "present"

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return { status: "failed" }

        if (state === "present") {
          const scannedOutput = await conn.output(`ssh-keyscan -H ${shellQuote(host)} 2>/dev/null`)
          const scannedLines = parseHostKeyLines(scannedOutput)
          verifyScannedHostKeys(host, scannedLines, options ?? {})
          await conn.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh", { silent: true })
          await conn.exec(
            `printf '%s\\n' ${scannedLines.map((line) => shellQuote(line)).join(" ")} >> ~/.ssh/known_hosts`,
            { silent: true }
          )
        } else {
          await conn.exec(`ssh-keygen -R ${shellQuote(host)}`, { silent: true })
        }

        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        if (state === "present" && hasKnownHostsTrustAnchor(options)) {
          return (await hasMatchingKnownHostTrustAnchor(conn, host, options ?? {}))
            ? "ok"
            : NEEDS_APPLY
        }

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
