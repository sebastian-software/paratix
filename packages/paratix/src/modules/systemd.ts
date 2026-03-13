import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const SYSTEMCTL = "systemctl"

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
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} mask ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
    const filePath = `/etc/systemd/system/${name}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        await ssh.writeFile(filePath, content)
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(filePath)
        if (!exists) return NEEDS_APPLY
        const remoteContent = await ssh.readFile(filePath)
        return remoteContent.trim() === content.trim() ? "ok" : NEEDS_APPLY
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
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} unmask ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
