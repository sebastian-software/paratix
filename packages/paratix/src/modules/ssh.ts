import { computeFingerprint } from "../knownHosts.js"
import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { applyAuthorizedKeys, checkAuthorizedKeys } from "./sshAuthorizedKeysHelpers.js"

type KnownHostsOptions = {
  expectedFingerprint?: string
  port?: number
  publicKey?: string
  state?: "absent" | "present"
}

const SSH_KEYSCAN_MIN_FIELDS = 3
const DEFAULT_SSH_PORT = 22

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

function lineMatchesTrustAnchor(line: string, options: KnownHostsOptions): boolean {
  const normalizedExpectedKey =
    options.publicKey == null ? null : normalizePublicKey(options.publicKey)
  const expectedFingerprint = options.expectedFingerprint

  const publicKeyMatches =
    normalizedExpectedKey != null && scannedLinePublicKey(line) === normalizedExpectedKey
  const fingerprintMatches =
    expectedFingerprint != null && scannedLineFingerprint(line) === expectedFingerprint
  return publicKeyMatches || fingerprintMatches
}

function getVerifiedScannedHostKeyLines(
  host: string,
  scannedLines: string[],
  options: KnownHostsOptions
): string[] {
  const normalizedExpectedKey =
    options.publicKey == null ? null : normalizePublicKey(options.publicKey)
  const expectedFingerprint = options.expectedFingerprint

  if (normalizedExpectedKey == null && expectedFingerprint == null) {
    throw new Error(
      `ssh.knownHosts(${host}) requires expectedFingerprint or publicKey before accepting ssh-keyscan output`
    )
  }

  const verifiedLines = scannedLines.filter((line) => lineMatchesTrustAnchor(line, options))

  if (verifiedLines.length === 0) {
    throw new Error(
      `ssh.knownHosts(${host}) could not verify the scanned host key against the provided trust anchor`
    )
  }

  return verifiedLines
}

function hasKnownHostsTrustAnchor(options?: KnownHostsOptions): boolean {
  return options?.expectedFingerprint != null || options?.publicKey != null
}

function knownHostsLookupTarget(host: string, options?: KnownHostsOptions): string {
  const port = options?.port
  if (port == null || port === DEFAULT_SSH_PORT) return host
  return `[${host}]:${port}`
}

function sshKeyscanCommand(host: string, options?: KnownHostsOptions): string {
  const port = options?.port
  if (port == null || port === DEFAULT_SSH_PORT) {
    return `ssh-keyscan -H ${shellQuote(host)} 2>/dev/null`
  }
  return `ssh-keyscan -p ${port} -H ${shellQuote(host)} 2>/dev/null`
}

async function hasMatchingKnownHostTrustAnchor(
  conn: SshConnection,
  host: string,
  options: KnownHostsOptions
): Promise<boolean> {
  const knownHostOutput = await conn.output(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}`
  )
  const knownHostLines = parseHostKeyLines(knownHostOutput)

  if (knownHostLines.length === 0) return false

  return knownHostLines.some((line) => lineMatchesTrustAnchor(line, options))
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
        return applyAuthorizedKeys(conn, { key, state, user })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        return checkAuthorizedKeys(conn, { key, state, user })
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
    const lookupTarget = knownHostsLookupTarget(host, options)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[ssh.knownHosts: ${host} (${state})] SSH connection is required`)

        if (state === "present") {
          const scannedOutput = await conn.output(sshKeyscanCommand(host, options))
          const scannedLines = parseHostKeyLines(scannedOutput)
          const verifiedLines = getVerifiedScannedHostKeyLines(host, scannedLines, options ?? {})
          await conn.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh", { silent: true })
          await conn.exec(
            `printf '%s\\n' ${verifiedLines.map((line) => shellQuote(line)).join(" ")} >> ~/.ssh/known_hosts`,
            { silent: true }
          )
        } else {
          await conn.exec(`ssh-keygen -R ${shellQuote(lookupTarget)}`, { silent: true })
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

        const hostKnown = await conn.test(`ssh-keygen -F ${shellQuote(lookupTarget)}`)

        if (state === "present") {
          return hostKnown ? "ok" : NEEDS_APPLY
        }
        return hostKnown ? NEEDS_APPLY : "ok"
      },
      name: `ssh.knownHosts: ${host} (${state})`,
    }
  },
}
