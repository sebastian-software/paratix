import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  type CertificateFile,
  CertificateFileError,
  certificateFileMatches,
  inspectCertificateFile,
} from "./sshCertificateFiles.js"
import { CertificateFilesTransaction } from "./sshCertificateFileTransaction.js"
import { activeCertificateConfig, type CertificateRunMode } from "./sshCertificateModules.js"
import {
  assertDistinctCertificatePaths,
  type AuthorizedPrincipalsOptions,
  CERTIFICATE_SSHD_CONFIG_PATH,
  certificateState,
  type CertificateState,
  normalizePrincipals,
  principalsTemplate,
  TRUSTED_USER_CA_PATH,
} from "./sshCertificateValidation.js"
import { withSshdConfigTransaction } from "./sshd.js"

type PrincipalParameters = {
  content: string
  path: string
  state: CertificateState
  user: string
}

async function principalFile(
  ssh: SshConnection,
  parameters: PrincipalParameters
): Promise<CertificateFile> {
  const active = await activeCertificateConfig(ssh, [TRUSTED_USER_CA_PATH, parameters.path], false)
  assertDistinctCertificatePaths([
    parameters.path,
    ...new Set([...active.caFiles, ...active.revocations]),
  ])
  if (parameters.state === "present" && !(await ssh.test(`id -u ${shellQuote(parameters.user)}`))) {
    throw new CertificateFileError(`Unix user does not exist: ${parameters.user}`)
  }
  return {
    content: parameters.state === "present" ? parameters.content : undefined,
    original: await inspectCertificateFile(ssh, parameters.path, {
      user: parameters.state === "present" ? parameters.user : undefined,
    }),
    path: parameters.path,
  }
}

async function principalReadable(
  ssh: SshConnection,
  parameters: PrincipalParameters
): Promise<boolean> {
  const readTest = `test -r ${shellQuote(parameters.path)}`
  return ssh.test(`su -s /bin/sh -c ${shellQuote(readTest)} ${shellQuote(parameters.user)}`)
}

async function applyPrincipal(
  ssh: SshConnection,
  parameters: PrincipalParameters,
  file: CertificateFile
): Promise<ModuleResult> {
  const transaction = new CertificateFilesTransaction(ssh)
  try {
    if (parameters.state === "absent") await transaction.remove(file)
    else {
      await transaction.write(file)
      if (!(await principalReadable(ssh, parameters)))
        throw new CertificateFileError(
          `Principal file is not readable under login user ${parameters.user}: ${parameters.path}`
        )
    }
  } catch (error) {
    const failures = await transaction.rollback()
    const suffix =
      failures.length === 0
        ? "; previous file and metadata restored"
        : `; rollback also failed: ${failures.join("; ")}`
    return failed(`[ssh.authorizedPrincipals: ${parameters.user}] ${String(error)}${suffix}`)
  }
  const cleanup = await transaction.cleanup()
  return cleanup.length === 0
    ? { status: "changed" }
    : failed(`[ssh.authorizedPrincipals] temporary-file cleanup failed: ${cleanup.join("; ")}`)
}

async function runPrincipal(
  ssh: null | SshConnection,
  parameters: PrincipalParameters,
  mode: CertificateRunMode
): Promise<ModuleResult> {
  if (ssh === null)
    return failed(`[ssh.authorizedPrincipals: ${parameters.user}] SSH connection is required`)
  try {
    const file = await principalFile(ssh, parameters)
    const converged =
      certificateFileMatches(file) &&
      (parameters.state === "absent" || (await principalReadable(ssh, parameters)))
    if (converged) return { status: "ok" }
    if (mode !== "apply") return { status: "changed" }
    // Serialize with CA activation/removal, so its snapshots cannot race an
    // independent principal update. The inner API never reacquires the lock.
    return await withSshdConfigTransaction(ssh, {
      dryRun: false,
      name: "ssh.authorizedPrincipals",
      async section(transaction) {
        const scoped = transaction.connection
        return applyPrincipal(scoped, parameters, await principalFile(scoped, parameters))
      },
    })
  } catch (error) {
    return failed(`[ssh.authorizedPrincipals: ${parameters.user}] ${String(error)}`)
  }
}

/**
 * Manage one Unix user's SSH certificate principals file.
 *
 * State defaults to `"present"`; `"absent"` removes only the expanded file.
 * The default template is `/etc/ssh/auth_principals/%u`; a custom template
 * must be an absolute safe `/etc/ssh/` path ending in exactly `%u` and must be
 * repeated identically in `trustedUserCa`. Principal names are normalized to
 * one sorted name per line and reject whitespace, `#`, commas, and control
 * characters. The file is checked for readability by the login user. Parent
 * directories that the login user cannot traverse are rejected even with safe permissions.
 *
 * @param user - The existing Unix login user for the expanded file.
 * @param principals - The complete desired principal set; an empty array leaves an empty file.
 * @param options - Optional template and state settings.
 * @returns A module managing only this user's principals file.
 */
export function authorizedPrincipals(
  user: string,
  principals: string[],
  options: AuthorizedPrincipalsOptions = {}
): Module {
  const state = certificateState(options.state)
  const content = normalizePrincipals(user, principals)
  const template = principalsTemplate(options.principalsFile)
  const path = template.replace("%u", user)
  assertDistinctCertificatePaths([path, TRUSTED_USER_CA_PATH, CERTIFICATE_SSHD_CONFIG_PATH])
  const parameters: PrincipalParameters = { content, path, state, user }
  return {
    async _applyDryRun(ssh) {
      return runPrincipal(ssh, parameters, "dry-run")
    },
    async apply(ssh) {
      return runPrincipal(ssh, parameters, "apply")
    },
    async check(ssh) {
      const result = await runPrincipal(ssh, parameters, "check")
      return result.status === "ok" ? "ok" : NEEDS_APPLY
    },
    name: `ssh.authorizedPrincipals: ${user} (${state})`,
  }
}
