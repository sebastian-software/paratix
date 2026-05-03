import { failed } from "../moduleFailure.js"
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

/**
 * Decide whether the line at `index` looks like a previously managed cron
 * job that may safely be overwritten.
 *
 * "Safely overwritable" means: the line is not a comment (starts with `#`),
 * not empty, and not another paratix marker. This protects user-authored
 * lines that ended up between the marker and the original job from being
 * silently overwritten by `present` apply.
 *
 * @param lines - The full crontab line array.
 * @param index - The index of the line to inspect.
 * @returns `true` when the line at `index` is a real cron job line.
 */
function looksLikeCronJobLine(lines: string[], index: number): boolean {
  if (index < 0 || index >= lines.length) return false
  const line = lines[index] ?? ""
  const trimmed = line.trim()
  if (trimmed.length === 0) return false
  if (trimmed.startsWith("#")) return false
  return true
}

/** Arguments for {@link computePresentMutation}. */
type PresentMutationArguments = {
  /** The desired cron job line. */
  cronJob: string
  /** The current crontab lines (not mutated). */
  lines: string[]
  /** The paratix marker comment. */
  marker: string
  /** The current index of the marker, or `-1`. */
  markerIndex: number
}

/**
 * Compute the new crontab lines required to make the `present` state hold.
 *
 * Returns `null` when no mutation is required (the marker already exists
 * and is followed by the desired job line), allowing the caller to
 * short-circuit without writing the crontab.
 *
 * @param mutation - The mutation inputs (see {@link PresentMutationArguments}).
 * @returns The new crontab lines, or `null` when no write is needed.
 */
function computePresentMutation(mutation: PresentMutationArguments): null | string[] {
  const { cronJob, lines, marker, markerIndex } = mutation

  // R-0000081: short-circuit when the marker already exists and the
  // following line already matches the desired cron job. Without this,
  // apply would overwrite the line with the same value and re-write the
  // crontab, reporting "changed" on every run when invoked directly
  // (e.g. as a signal target). Mirrors the no-op returns that R-0000075
  // added to file.replace.apply and R-0000077 added to user.absent.apply.
  if (markerIndex !== -1 && lines[markerIndex + 1] === cronJob) return null

  const next = [...lines]

  if (markerIndex === -1) {
    // No marker yet — append at the end.
    next.push(marker, cronJob)
  } else if (looksLikeCronJobLine(next, markerIndex + 1)) {
    // R-0000047: only overwrite the next line when it actually looks
    // like a managed cron job. This prevents user-authored comments /
    // blanks that ended up between marker and previous job from being
    // silently destroyed by a re-apply.
    next[markerIndex + 1] = cronJob
  } else {
    // Marker is the last line, or the next line is a comment / blank
    // that the user inserted — splice the new job in instead of
    // overwriting unrelated content.
    next.splice(markerIndex + 1, 0, cronJob)
  }

  return next
}

/** Options for `cron.job`. */
type CronJobOptions = {
  /** The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`). */
  job: string
  /** Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`. */
  state?: "absent" | "present"
}

function assertCronName(name: string): void {
  if (/[\n\r]/v.test(name)) {
    throw new Error(`cron: name must not contain newlines: ${JSON.stringify(name)}`)
  }
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
   * Ensure a cron job is absent from a user's crontab.
   *
   * Removes the `# paratix: <name>` marker comment and the crontab line
   * directly below it. If the marker is not found, the module reports `ok`
   * without writing the crontab. When the crontab becomes empty after the
   * removal, it is deleted entirely via `crontab -r`.
   *
   * Equivalent to `cron.job(user, name, { job: "<unused>", state: "absent" })`,
   * but does not require a placeholder `job` argument.
   *
   * @param user - The target user whose crontab is managed.
   * @param name - Unique identifier of the cron job marker to remove.
   * @returns A Module that ensures the cron job entry is absent.
   */
  absent(user: string, name: string): Module {
    assertCronName(name)
    const marker = `# paratix: ${name}`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.absent: ${name} (${user})] SSH connection is required`)

        const lines = await readCrontab(ssh, user)
        const markerIndex = lines.indexOf(marker)
        if (markerIndex === -1) return { status: "ok" }

        // R-0000047: only splice the next line as well when it actually
        // looks like a cron job. If the marker is the last line, or the
        // next line is a user comment / blank, only the marker itself is
        // removed so we cannot accidentally delete unrelated content.
        const removeCount = looksLikeCronJobLine(lines, markerIndex + 1) ? 2 : 1
        lines.splice(markerIndex, removeCount)
        await writeCrontab(ssh, user, lines)
        return { status: "changed" }
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const lines = await readCrontab(ssh, user)
        return lines.includes(marker) ? NEEDS_APPLY : "ok"
      },

      name: `cron.absent: ${name} (${user})`,
    }
  },

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
    assertCronName(name)
    if (/[\n\r]/v.test(options.job)) {
      throw new Error(`cron.job: job must not contain newlines: ${JSON.stringify(options.job)}`)
    }

    const state = options.state ?? "present"
    const cronJob = options.job
    const marker = `# paratix: ${name}`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.job: ${name} (${user})] SSH connection is required`)

        const lines = await readCrontab(ssh, user)
        const markerIndex = lines.indexOf(marker)

        let nextLines: string[]
        if (state === "present") {
          const computed = computePresentMutation({ cronJob, lines, marker, markerIndex })
          if (computed === null) return { status: "ok" }
          nextLines = computed
        } else if (markerIndex === -1) {
          return { status: "ok" }
        } else {
          // R-0000047: only remove the line after the marker when it
          // exactly matches the expected job. If the user has already
          // deleted the job line, or replaced it with something
          // different, drop only the marker and keep the surrounding
          // content untouched.
          const removeCount = lines[markerIndex + 1] === cronJob ? 2 : 1
          nextLines = [...lines]
          nextLines.splice(markerIndex, removeCount)
        }

        await writeCrontab(ssh, user, nextLines)
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
