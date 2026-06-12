import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { buildDryRunDetail, buildKeyValueDiff } from "./diffHelpers.js"

const HOSTNAME_MAX_LENGTH = 253
const HOSTNAME_LABEL_MAX_LENGTH = 63

function isHostnameLabelCharacter(character: string): boolean {
  if (character >= "a" && character <= "z") return true
  if (character >= "A" && character <= "Z") return true
  if (character >= "0" && character <= "9") return true
  return character === "-"
}

function isValidHostnameLabel(label: string): boolean {
  if (label.startsWith("-") || label.endsWith("-")) return false
  for (const character of label) {
    if (!isHostnameLabelCharacter(character)) return false
  }
  return true
}

function validateHostname(name: string): void {
  if (name.length === 0) {
    throw new Error("hostname.set: hostname must not be empty")
  }
  if (name.length > HOSTNAME_MAX_LENGTH) {
    throw new Error(
      `hostname.set: hostname must be at most ${String(HOSTNAME_MAX_LENGTH)} characters`
    )
  }
  if (name.startsWith("-")) {
    throw new Error("hostname.set: hostname must not start with '-'")
  }
  for (const label of name.split(".")) {
    if (label.length === 0) {
      throw new Error(
        `hostname.set: hostname must not contain empty labels: ${JSON.stringify(name)}`
      )
    }
    if (label.length > HOSTNAME_LABEL_MAX_LENGTH) {
      throw new Error(
        `hostname.set: hostname labels must be at most ${String(HOSTNAME_LABEL_MAX_LENGTH)} characters`
      )
    }
    if (!isValidHostnameLabel(label)) {
      throw new Error(`hostname.set: invalid hostname label: ${JSON.stringify(label)}`)
    }
  }
}

/**
 * Modules for managing the system hostname.
 */
export const hostname = {
  /**
   * Set the system hostname via `hostnamectl set-hostname`.
   * Checks the current hostname first and skips the command when it already matches.
   *
   * @param name - The desired hostname.
   * @returns A Module that sets the hostname.
   */
  set(name: string): Module {
    validateHostname(name)
    return {
      async _applyDryRun(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "changed" }
        try {
          const result = await ssh.exec("hostnamectl --static", {
            ignoreExitCode: true,
            silent: true,
          })
          const currentValue = result.code === 0 ? result.stdout.trim() : null
          const diff = buildKeyValueDiff("hostname", currentValue, name)
          return diff === "" ? { status: "changed" } : { diff, status: "changed" }
        } catch (error) {
          // R-0001018: surface the underlying error code so an SSH hiccup
          // during the dry-run probe shows up in the runner log instead of a
          // silent "(dry-run)" marker.
          return { _dryRunDetail: buildDryRunDetail(error), status: "changed" }
        }
      },
      _dryRunDiffProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[hostname.set: ${name}] SSH connection is required`)
        const result = await ssh.exec(`hostnamectl set-hostname ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[hostname.set: ${name}] hostnamectl set-hostname failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // Use `hostnamectl --static` to read the persisted hostname from /etc/hostname
        // rather than the kernel-resolved hostname returned by `hostname`, which can
        // differ (e.g. FQDN vs. short name) depending on /etc/hosts and nsswitch.conf
        // and would otherwise cause check to report drift even after a successful apply.
        // R-0000558: route through ssh.exec with ignoreExitCode so non-zero
        // hostnamectl exits (systemd containers without DBus access, missing
        // privileges, etc.) do not propagate a raw CommandError out of check.
        // Treat any non-zero exit as drift so apply re-runs and surfaces the
        // actionable hostnamectl failure via failedCommand.
        const result = await ssh.exec("hostnamectl --static", {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) return NEEDS_APPLY
        return result.stdout.trim() === name ? "ok" : NEEDS_APPLY
      },
      name: `hostname.set: ${name}`,
    }
  },
}
