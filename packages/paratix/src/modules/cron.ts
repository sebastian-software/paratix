import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

/**
 * Read the current crontab lines for a user.
 *
 * @param ssh - The active SSH connection.
 * @param user - The target user whose crontab is read.
 * @returns The crontab split into lines, or an empty array if no crontab exists.
 */
async function readCrontab(ssh: SshConnection, user: string): Promise<string[]> {
  const result = await ssh.exec(`crontab -u ${shellQuote(user)} -l`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0 ? result.stdout.trimEnd().split("\n") : []
}

/**
 * Write a new crontab for a user, or remove it entirely when the content is empty.
 *
 * @param ssh - The active SSH connection.
 * @param user - The target user whose crontab is written.
 * @param lines - The crontab lines to write. An empty array removes the crontab.
 */
async function writeCrontab(ssh: SshConnection, user: string, lines: string[]): Promise<void> {
  if (lines.length === 0) {
    await ssh.exec(`crontab -u ${shellQuote(user)} -r`, { ignoreExitCode: true, silent: true })
    return
  }
  const content = `${lines.join("\n")}\n`
  await ssh.exec(`printf '%s' ${shellQuote(content)} | crontab -u ${shellQuote(user)} -`, {
    silent: true,
  })
}

/**
 * Check whether a marker-job pair is correctly present in crontab lines.
 *
 * @param lines - The crontab lines to inspect.
 * @param marker - The marker comment to search for.
 * @param cronJob - The expected job line after the marker.
 * @returns `true` if the marker exists and is followed by the expected job line.
 */
function hasMarkedJob(lines: string[], marker: string, cronJob: string): boolean {
  const index = lines.indexOf(marker)
  return index !== -1 && index + 1 < lines.length && lines[index + 1] === cronJob
}

/** Options for `cron.job`. */
type CronJobOptions = {
  /** The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`). */
  job: string
  /** Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`. */
  state?: "absent" | "present"
}

/**
 * Modules for managing cron jobs in user crontabs.
 *
 * Each managed entry is identified by a `# paratix: <name>` marker comment
 * written on the line directly above the job line, making all changes
 * idempotent and safely repeatable.
 */
export const cron = {
  /**
   * Ensure a cron job is present in (or absent from) a user's crontab.
   *
   * Each managed entry is tracked via a `# paratix: <name>` marker comment
   * placed on the line directly above the job line. When the marker already
   * exists, the job line is updated in place. When `state` is `"absent"`,
   * both the marker and the job line are removed.
   *
   * @param user - The target user whose crontab is managed.
   * @param name - Unique identifier for this cron job, used in the marker line.
   * @param options - Job content and desired state.
   * @param options.job - The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`).
   * @param options.state - Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @returns A Module that manages the cron job entry.
   */
  job(user: string, name: string, options: CronJobOptions): Module {
    if (/[\n\r]/v.test(name)) {
      throw new Error(`cron.job: name must not contain newlines: ${JSON.stringify(name)}`)
    }
    if (/[\n\r]/v.test(options.job)) {
      throw new Error(`cron.job: job must not contain newlines: ${JSON.stringify(options.job)}`)
    }

    const state = options.state ?? "present"
    const cronJob = options.job
    const marker = `# paratix: ${name}`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const lines = await readCrontab(ssh, user)
        const markerIndex = lines.indexOf(marker)

        if (state === "present") {
          if (markerIndex === -1) {
            lines.push(marker, cronJob)
          } else {
            lines[markerIndex + 1] = cronJob
          }
        } else if (markerIndex === -1) {
          return { status: "ok" }
        } else {
          lines.splice(markerIndex, 2)
        }

        await writeCrontab(ssh, user, lines)
        return { status: "changed" }
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const lines = await readCrontab(ssh, user)
        const found = hasMarkedJob(lines, marker, cronJob)

        if (state === "present") {
          return found ? "ok" : NEEDS_APPLY
        }

        // state === "absent": ok when marker is not found
        return lines.includes(marker) ? NEEDS_APPLY : "ok"
      },

      name: `cron.job: ${name} (${user})`,
    }
  },
}
