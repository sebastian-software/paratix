import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const SYSTEMCTL = "systemctl"
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const SYSTEMD_UNIT_MODE = "0644"

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

function buildSystemdUnitReloadFlag(
  name: string,
  content: string
): {
  flagName: string
  flagPrefix: string
} {
  const flagPrefix = `systemd-unit-${sha256String(name).slice(0, 16)}-`
  return {
    flagName: `${flagPrefix}${sha256String(content).slice(0, 16)}`,
    flagPrefix,
  }
}

/**
 * Modules for managing systemd unit files and unit masking.
 *
 * The `unit` method writes unit files with idempotent checks and triggers a daemon-reload
 * on change. `masked` and `unmasked` control unit masking state.
 * `daemonReload` is a signal-style method that always applies.
 */
export const systemd = {
  /**
   * Reload the systemd manager configuration. Intended as a recipe signal --
   * always applies.
   * @returns A Module that runs `systemctl daemon-reload`.
   */
  daemonReload(): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[systemd.daemonReload] SSH connection is required")
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand("[systemd.daemonReload] systemctl daemon-reload failed", result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        // Signal: always needs apply
        return NEEDS_APPLY
      },
      name: "systemd.daemonReload",
    }
  },

  /**
   * Ensure a systemd unit is masked and cannot be started.
   * @param name - The systemd unit name (e.g. `"apt-daily.timer"`).
   * @returns A Module that ensures the unit is masked.
   */
  masked(name: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.masked: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} mask ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.masked: ${name}] systemctl mask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const result = await ssh.exec(`${SYSTEMCTL} is-enabled ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.stdout.trim().includes("masked") ? "ok" : NEEDS_APPLY
      },
      name: `systemd.masked: ${name}`,
    }
  },

  /**
   * Write a systemd unit file to `/etc/systemd/system/` and reload the
   * daemon configuration when the content changes.
   *
   * The check phase compares the remote file content with the desired
   * content string. Apply writes the file and runs `systemctl daemon-reload`.
   *
   * @param name - Unit file name (e.g. `"my-app.service"` or `"backup.timer"`).
   * @param content - The full unit file content.
   * @returns A Module that ensures the unit file is present with the given content.
   */
  unit(name: string, content: string): Module {
    if (!UNIT_NAME_PATTERN.test(name)) {
      throw new Error(`systemd.unit: name must match ${String(UNIT_NAME_PATTERN)}, got: ${name}`)
    }
    const filePath = `/etc/systemd/system/${name}`
    const reloadFlag = buildSystemdUnitReloadFlag(name, content)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.unit: ${name}] SSH connection is required`)
        await ssh.writeFile(filePath, content, { mode: SYSTEMD_UNIT_MODE })
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return failedCommand(`[systemd.unit: ${name}] systemctl daemon-reload failed`, result)
        }
        await setVersionedFlag(ssh, reloadFlag.flagName, reloadFlag.flagPrefix)
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(filePath)
        if (!exists) return NEEDS_APPLY
        const remoteContent = await ssh.readFile(filePath)
        if (remoteContent.trim() !== content.trim()) return NEEDS_APPLY
        const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(filePath)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (modeResult.code !== 0) return NEEDS_APPLY
        const currentMode = modeResult.stdout.trim()
        if (currentMode === "") return NEEDS_APPLY
        if (normalizeMode(currentMode) !== normalizeMode(SYSTEMD_UNIT_MODE)) return NEEDS_APPLY
        return (await hasFlag(ssh, reloadFlag.flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `systemd.unit: ${name}`,
    }
  },

  /**
   * Ensure a systemd unit is unmasked and can be started normally.
   * @param name - The systemd unit name (e.g. `"apt-daily.timer"`).
   * @returns A Module that ensures the unit is unmasked.
   */
  unmasked(name: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.unmasked: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} unmask ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.unmasked: ${name}] systemctl unmask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const result = await ssh.exec(`${SYSTEMCTL} is-enabled ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.stdout.trim().includes("masked") ? NEEDS_APPLY : "ok"
      },
      name: `systemd.unmasked: ${name}`,
    }
  },
}
