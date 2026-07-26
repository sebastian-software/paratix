import { describe, expect, it } from "vitest"

import {
  describeAptUpgradeOutcome,
  UNKNOWN_UPGRADE_OUTCOME_DETAIL,
} from "../../src/modules/packageUpgradeSummary.js"
import { CAPTURE_TRUNCATION_MARKER } from "../../src/sshHelpers.js"

const APT_TAIL = "0 newly installed, 0 to remove and 3 not upgraded."

describe("describeAptUpgradeOutcome", () => {
  it("reports the upgraded package count", () => {
    expect(describeAptUpgradeOutcome(`Reading package lists...\n12 upgraded, ${APT_TAIL}\n`)).toBe(
      "12 packages upgraded"
    )
  })

  it("uses the singular form for exactly one package", () => {
    expect(describeAptUpgradeOutcome(`1 upgraded, ${APT_TAIL}\n`)).toBe("1 package upgraded")
  })

  // The case that motivates the whole change: the dated marker was missing, so
  // the step reports `changed`, but the system was already current.
  it("distinguishes an upgrade that changed nothing", () => {
    expect(describeAptUpgradeOutcome(`0 upgraded, ${APT_TAIL}\n`)).toBe("no packages upgraded")
  })

  it("matches the summary anywhere in multi-line output", () => {
    const stdout = [
      "Reading package lists...",
      "Building dependency tree...",
      `7 upgraded, ${APT_TAIL}`,
    ].join("\n")
    expect(describeAptUpgradeOutcome(stdout)).toBe("7 packages upgraded")
  })

  it("falls back when the output has no summary line", () => {
    expect(describeAptUpgradeOutcome("Reading package lists...\nDone\n")).toBe(
      UNKNOWN_UPGRADE_OUTCOME_DETAIL
    )
  })

  it("falls back for empty output", () => {
    expect(describeAptUpgradeOutcome("")).toBe(UNKNOWN_UPGRADE_OUTCOME_DETAIL)
  })

  // apt prints its summary last, so a capture that hit `maxOutputBytes` lost
  // exactly that line. Reporting no count is correct; reporting a stale one
  // picked from earlier output would not be.
  it("falls back when the capture was truncated", () => {
    const stdout = `4 upgraded, ${APT_TAIL}\n${"noise\n".repeat(3)}${CAPTURE_TRUNCATION_MARKER}`
    expect(describeAptUpgradeOutcome(stdout)).toBe(UNKNOWN_UPGRADE_OUTCOME_DETAIL)
  })

  it("ignores a count that is not at the start of a line", () => {
    expect(describeAptUpgradeOutcome(`note: 5 upgraded, ${APT_TAIL}\n`)).toBe(
      UNKNOWN_UPGRADE_OUTCOME_DETAIL
    )
  })
})
