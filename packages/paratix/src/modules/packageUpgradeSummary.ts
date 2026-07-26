import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"

/**
 * Summary line emitted by apt at the end of an upgrade run, e.g.
 * `12 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.`
 *
 * Only the leading upgrade count is consumed: it is the number that tells an
 * operator whether the step actually changed the system or merely wrote its
 * dated marker. The remaining fields vary between apt versions and are not
 * relied upon.
 */
const APT_UPGRADE_SUMMARY_PATTERN = /^(?<upgraded>\d+) upgraded, /mv

/**
 * Detail used when the upgrade succeeded but no trustworthy count could be
 * derived — a non-apt package manager, an apt output shape this parser does
 * not know, or a capture that was truncated before the summary line.
 */
export const UNKNOWN_UPGRADE_OUTCOME_DETAIL = "upgrade completed, package count unavailable"

/**
 * Describe the outcome of an apt upgrade for the module status line.
 *
 * apt prints its summary as the *last* line of the run, so a capture that hit
 * `maxOutputBytes` loses exactly the line this parser needs. A truncated
 * capture is therefore rejected up front rather than parsed: a match found in
 * such output could only come from unrelated earlier text, and reporting a
 * wrong count is worse than reporting none.
 *
 * @param stdout - Captured standard output of the apt upgrade command.
 * @returns A short single-line detail describing how many packages were upgraded.
 */
export function describeAptUpgradeOutcome(stdout: string): string {
  if (stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) return UNKNOWN_UPGRADE_OUTCOME_DETAIL

  const captured = APT_UPGRADE_SUMMARY_PATTERN.exec(stdout)?.groups?.upgraded
  if (captured == null || captured === "") return UNKNOWN_UPGRADE_OUTCOME_DETAIL

  const upgraded = Number(captured)
  if (!Number.isSafeInteger(upgraded)) return UNKNOWN_UPGRADE_OUTCOME_DETAIL
  if (upgraded === 0) return "no packages upgraded"
  return upgraded === 1 ? "1 package upgraded" : `${upgraded} packages upgraded`
}
