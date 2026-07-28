import type { ExecResult, SshConnection } from "../types.js"

// R-0000541: parse the `users:(("PROC",...))` entries from `ss -ltnp` instead
// of running a bare substring match against the entire row. Without the
// structural parse a user-level process called `sshd-fake` or a comment
// containing the literal text `sshd` would satisfy the regex even though no
// real sshd is bound. Only `sshd` (direct service) and `systemd` (socket
// activation hands the listening socket to systemd-pid-1) are accepted as
// owners.
const SS_USERS_PROCESS_PATTERN = /users:\(\("(?<name>[^"]+)"[^\)]*\)/gv
const SSHD_OWNER_NAMES = new Set(["sshd", "systemd"])

function extractSsListenerProcessNames(output: string): string[] {
  const names: string[] = []
  for (const match of output.matchAll(SS_USERS_PROCESS_PATTERN)) {
    const name = match.groups?.name
    if (name != null) names.push(name)
  }
  return names
}

// R-0000609: `ss` may fail for two very different reasons. A non-zero exit
// with empty stdout normally just means the port has no listener yet (e.g.
// during a slow systemd transition) — callers may want to keep polling. But
// a missing `ss` binary (`command not found`) or a permission denial
// (`Operation not permitted`, `Permission denied`) is a hard environmental
// failure: every probe will return the same non-zero code, retry loops would
// time out without ever seeing a listener, and the apply path would then
// roll back even on a successful restart. Detect those families up front so
// callers can surface them as a structured module error instead of pretending
// the port silently lacks a listener.
const SS_HARD_ERROR_PATTERNS: RegExp[] = [
  /command not found/iv,
  /no such file or directory/iv,
  /permission denied/iv,
  /operation not permitted/iv,
  /must be run as root/iv,
]

export type LiveSshdPortProbe =
  { kind: "hard-error"; stderr: string; stdout: string } | { kind: "match"; matches: boolean }

export const LIVE_PORT_PROBE_MATCH_KIND = "match" as const
export const LIVE_PORT_PROBE_HARD_ERROR_KIND = "hard-error" as const

export function classifyLiveSshdPortProbe(result: ExecResult): LiveSshdPortProbe {
  if (result.code !== 0) {
    const haystack = `${result.stderr}\n${result.stdout}`
    if (SS_HARD_ERROR_PATTERNS.some((pattern) => pattern.test(haystack))) {
      return {
        kind: LIVE_PORT_PROBE_HARD_ERROR_KIND,
        stderr: result.stderr,
        stdout: result.stdout,
      }
    }
    return { kind: LIVE_PORT_PROBE_MATCH_KIND, matches: false }
  }
  const output = result.stdout.trim()
  if (output === "") return { kind: LIVE_PORT_PROBE_MATCH_KIND, matches: false }
  const processNames = extractSsListenerProcessNames(output)
  if (processNames.length === 0) return { kind: LIVE_PORT_PROBE_MATCH_KIND, matches: false }
  return {
    kind: LIVE_PORT_PROBE_MATCH_KIND,
    matches: processNames.some((name) => SSHD_OWNER_NAMES.has(name)),
  }
}

// R-0000609: callers carry their own log tag (e.g. `sshd.port: 22`,
// `ufw.rule: deny 22`) so this error class only owns the generic detail
// message. The tag is supplied by the caller so a single helper can serve
// both `sshd.port` and `ufw.rule` without leaking the wrong module name
// into surfaced errors.
export class LiveSshdPortProbeError extends Error {
  public constructor(tag: string, detail: string) {
    super(
      `[${tag}] live-port probe via \`ss\` failed (likely missing ` +
        `\`ss\` binary or insufficient privileges): ${detail}`
    )
    this.name = "LiveSshdPortProbeError"
  }
}

export async function probeLiveSshdPort(
  ssh: SshConnection,
  targetPort: number
): Promise<LiveSshdPortProbe> {
  const result = await ssh.exec(`ss -H -ltnp 'sport = :${String(targetPort)}'`, {
    ignoreExitCode: true,
    silent: true,
  })
  return classifyLiveSshdPortProbe(result)
}

// R-0000609: run the probe and throw a structured `LiveSshdPortProbeError`
// for hard environmental failures so callers can surface them as proper
// module failures instead of swallowing them as "no listener yet". The
// `tag` parameter mirrors the caller's log prefix (`sshd.port: 22`,
// `ufw.rule: deny 22`).
export async function liveSshdPortMatches(
  ssh: SshConnection,
  parameters: { tag: string; targetPort: number }
): Promise<boolean> {
  const { tag, targetPort } = parameters
  const probe = await probeLiveSshdPort(ssh, targetPort)
  if (probe.kind === LIVE_PORT_PROBE_HARD_ERROR_KIND) {
    const stderrTrimmed = probe.stderr.trim()
    const detail = stderrTrimmed === "" ? probe.stdout.trim() : stderrTrimmed
    throw new LiveSshdPortProbeError(tag, detail === "" ? "no stderr captured" : detail)
  }
  return probe.matches
}
