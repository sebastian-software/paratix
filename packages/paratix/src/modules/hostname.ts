import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const HOSTNAME_MAX_LENGTH = 253
const HOSTNAME_LABEL_MAX_LENGTH = 63
const HOSTNAME_LABEL_PATTERN = /^[a-zA-Z0-9](?:[a-zA-Z0-9\x2d]*[a-zA-Z0-9])?$/v

function validateHostname(name: string): void {
  if (name.length === 0) {
    throw new Error("hostname.set: hostname must not be empty")
  }
  if (name.length > HOSTNAME_MAX_LENGTH) {
    throw new Error(`hostname.set: hostname must be at most ${String(HOSTNAME_MAX_LENGTH)} characters`)
  }
  if (name.startsWith("-")) {
    throw new Error("hostname.set: hostname must not start with '-'")
  }
  for (const label of name.split(".")) {
    if (label.length === 0) {
      throw new Error(`hostname.set: hostname must not contain empty labels: ${JSON.stringify(name)}`)
    }
    if (label.length > HOSTNAME_LABEL_MAX_LENGTH) {
      throw new Error(
        `hostname.set: hostname labels must be at most ${String(HOSTNAME_LABEL_MAX_LENGTH)} characters`
      )
    }
    if (!HOSTNAME_LABEL_PATTERN.test(label)) {
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
        const current = await ssh.output("hostnamectl --static")
        return current === name ? "ok" : NEEDS_APPLY
      },
      name: `hostname.set: ${name}`,
    }
  },
}
