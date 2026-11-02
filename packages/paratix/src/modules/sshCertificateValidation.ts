import { posix } from "node:path"

import { assertValidUserName } from "./posixNames.js"
import { assertAuthorizedKeyValue } from "./sshPublicKeyValidation.js"

export const TRUSTED_USER_CA_PATH = "/etc/ssh/trusted_user_ca_keys"
export const DEFAULT_PRINCIPALS_FILE = "/etc/ssh/auth_principals/%u"
export const CERTIFICATE_SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

const USER_TOKEN = "%u"

type CertificatePaths = { principalsFile?: string; revokedKeys?: string }

/**
 * Options for `ssh.trustedUserCa`. `present` is the default and requires a
 * non-empty `publicKey`; `absent` may omit it. The CA path is fixed, while the
 * optional principals template defaults to `/etc/ssh/auth_principals/%u` and
 * must be shared with {@link AuthorizedPrincipalsOptions}.
 */
export type TrustedUserCaOptions = (
  { publicKey: string; state?: "present" } | { publicKey?: string; state: "absent" }
) &
  CertificatePaths

/**
 * Options for `ssh.authorizedPrincipals`. State defaults to `present`; an
 * `absent` value removes the expanded per-user file. `principalsFile`, when
 * supplied, must be the same template used by the CA module.
 */
export type AuthorizedPrincipalsOptions =
  { principalsFile?: string; state: "absent" } | { principalsFile?: string; state?: "present" }

export type CertificateState = "absent" | "present"

export function certificateState(state: unknown): CertificateState {
  if (state === undefined || state === "present") return "present"
  if (state === "absent") return state
  throw new Error('SSH certificate module state must be "present" or "absent"')
}

export function assertCertificatePath(path: string): void {
  if (
    !path.startsWith("/etc/ssh/") ||
    posix.normalize(path) !== path ||
    !/^\/etc\/ssh\/[\w.\/\-]+$/v.test(path) ||
    path.endsWith("/") ||
    path.split("/").some((part) => part === "." || part === "..")
  ) {
    throw new Error(`SSH certificate file requires a normalized safe path under /etc/ssh/: ${path}`)
  }
}

export function principalsTemplate(value = DEFAULT_PRINCIPALS_FILE): string {
  if (!value.endsWith("/%u") || value.slice(0, -USER_TOKEN.length).includes("%")) {
    throw new Error("principalsFile must have exactly one %u token as its final path segment")
  }
  assertCertificatePath(`${value.slice(0, -USER_TOKEN.length)}paratix-user`)
  assertDistinctCertificatePaths([value, TRUSTED_USER_CA_PATH, CERTIFICATE_SSHD_CONFIG_PATH])
  return value
}

function pathsOverlap(left: string, right: string): boolean {
  if (left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`)) return true
  if (left.endsWith("/%u") && right.startsWith(`${posix.dirname(left)}/`)) return true
  return right.endsWith("/%u") && left.startsWith(`${posix.dirname(right)}/`)
}

export function assertDistinctCertificatePaths(paths: readonly string[]): void {
  for (let index = 0; index < paths.length; index++) {
    const left = paths[index]
    for (const right of paths.slice(index + 1)) {
      if (pathsOverlap(left, right)) {
        throw new Error(`SSH certificate file/directory path collision: ${left} and ${right}`)
      }
    }
  }
}

export function certificatePaths(options: CertificatePaths): {
  principalsFile: string
  revokedKeys?: string
} {
  const principalsFile = principalsTemplate(options.principalsFile)
  if (options.revokedKeys !== undefined) assertCertificatePath(options.revokedKeys)
  assertDistinctCertificatePaths([
    TRUSTED_USER_CA_PATH,
    principalsFile,
    CERTIFICATE_SSHD_CONFIG_PATH,
    ...(options.revokedKeys === undefined ? [] : [options.revokedKeys]),
  ])
  return { principalsFile, revokedKeys: options.revokedKeys }
}

export function normalizeCaKeys(value: string): string {
  const keys = new Map<string, string>()
  for (const rawLine of value.split(/\r\n|\n|\r/v)) {
    const line = rawLine.trim()
    if (line.length === 0) continue
    // Reuse the single-key algorithm and binary-blob validation, including its
    // rejection of certificate keys, private keys and authorized_keys options.
    assertAuthorizedKeyValue(line)
    const [algorithm, blob] = line.split(/\s+/v)
    const identity = `${algorithm} ${blob}`
    if (!keys.has(identity)) keys.set(identity, line)
  }
  if (keys.size === 0) throw new Error("ssh.trustedUserCa requires at least one public CA key")
  return `${[...keys.values()].sort().join("\n")}\n`
}

export function normalizePrincipals(user: string, principals: readonly string[]): string {
  assertValidUserName(user)
  for (const principal of principals) {
    if (principal.length === 0 || /[\s,#\p{Cc}\p{Cf}]/v.test(principal)) {
      throw new Error(`ssh.authorizedPrincipals: invalid principal ${JSON.stringify(principal)}`)
    }
  }
  const lines = [...new Set(principals)].sort()
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`
}
