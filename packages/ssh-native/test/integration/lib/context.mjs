// Test-side view of a run: the descriptor written by run.mjs, the
// `hardProof()`/`check()` wrappers that enforce the skip rule, and the
// requirements a test can declare.
import assert from "node:assert/strict"
import { appendFileSync, readFileSync } from "node:fs"
import { it } from "node:test"

import { DESCRIPTOR_ENV, HARD_PROOFS, isCi, RESULTS_ENV } from "./proofs.mjs"
import { missingTools } from "./tools.mjs"

/**
 * @typedef {object} Target
 * @property {"docker" | "local"} kind which target
 * @property {string} host sshd host
 * @property {string} user login user
 * @property {string | null} password the user's password (Docker only)
 * @property {{ main: number, userCa: number, password: number | null, keyboardInteractive: number | null }} ports profile ports
 * @property {{ pam: boolean, tmpfs: boolean }} features what the target offers
 * @property {string} [container] Docker container name
 */

/**
 * @typedef {object} Descriptor
 * @property {"docker" | "local"} kind the selected target
 * @property {string} marker run marker for remote sleep commands
 * @property {string} runDir private run directory
 * @property {string | null} unavailable why the target is not running
 * @property {Target} [target] the running target
 * @property {import("./keys.mjs").Fixtures} [fixtures] generated keys
 */

/** @returns the run descriptor, or a stand-in when not started by run.mjs */
function loadDescriptor() {
  const path = process.env[DESCRIPTOR_ENV]
  if (!path) {
    return /** @type {Descriptor} */ ({
      kind: "local",
      marker: "000000",
      runDir: "",
      unavailable: "not started by test/integration/run.mjs (use the test:integration scripts)",
    })
  }
  return /** @type {Descriptor} */ (JSON.parse(readFileSync(path, "utf8")))
}

export const descriptor = loadDescriptor()

/**
 * @typedef {"sshd" | "agent" | "pam" | "tmpfs" | "dev-full" | "non-root"} Requirement
 */

/** @type {Record<Requirement, () => string | null>} */
const REQUIREMENTS = {
  agent: () => missingTools(["ssh-agent", "ssh-add"]),
  "dev-full": () =>
    descriptor.kind === "docker" || process.platform === "linux"
      ? null
      : "needs /dev/full on the sshd host (Linux)",
  "non-root": () =>
    descriptor.kind === "local" && process.getuid?.() === 0
      ? "the local sshd runs as root, which ignores file permissions"
      : null,
  pam: () =>
    descriptor.target?.features.pam
      ? null
      : "needs PAM (password and keyboard-interactive): Docker target only",
  sshd: () => descriptor.unavailable,
  tmpfs: () => (descriptor.target?.features.tmpfs ? null : "needs the Docker tmpfs mount"),
}

/**
 * @param needs requirements of a test
 * @returns the first unmet requirement's reason, or `null`
 */
function unmet(needs) {
  for (const need of needs) {
    const reason = REQUIREMENTS[need]()
    if (reason) return reason
  }
  return null
}

/**
 * @typedef {object} CheckOptions
 * @property {Requirement[]} [needs] default `["sshd"]`
 */

/**
 * A test that is skipped with a reason when a requirement is unmet.
 *
 * @param name test name
 * @param fn the test
 * @param [options] requirements
 */
export function check(name, fn, options = {}) {
  const { needs = ["sshd"] } = options
  it(name, async (context) => {
    const reason = unmet(needs)
    if (reason) {
      context.skip(reason)
      return
    }
    await fn(context)
  })
}

/**
 * @typedef {object} ProofInfo
 * @property {string} id one of HARD_PROOFS
 * @property {string} name what the proof shows
 * @property {Requirement[]} [needs] requirements, default `["sshd"]`
 */

/**
 * A hard proof of ADR 0008. A skip is a failure with CI=true; a pass is
 * recorded for the runner's gate.
 *
 * @param proof id, name and requirements
 * @param fn the test
 */
export function hardProof(proof, fn) {
  const { id, name, needs = ["sshd"] } = proof
  assert.ok(HARD_PROOFS.includes(id), `unknown hard proof ${id}`)
  it(`${id}: ${name}`, async (context) => {
    const reason = unmet(needs)
    if (reason && isCi()) assert.fail(`hard proof ${id} cannot be skipped with CI=true: ${reason}`)
    if (reason) {
      context.skip(reason)
      return
    }
    await fn(context)
    const results = process.env[RESULTS_ENV]
    if (results) appendFileSync(results, `pass ${id}\n`)
  })
}

/** @returns the running target; only call inside a test whose `sshd` need is met */
export function target() {
  return /** @type {Target} */ (descriptor.target)
}

/** @returns the generated fixtures; only call inside a test whose `sshd` need is met */
export function fixtures() {
  return /** @type {import("./keys.mjs").Fixtures} */ (descriptor.fixtures)
}

/**
 * A remote `sleep` that the runner can find and kill afterwards (local
 * target: exec runs without a PTY, so a dropped connection does not stop it).
 *
 * @param seconds whole number of seconds to sleep
 * @returns `sleep <seconds>.<run marker>`
 */
export function sleepCommand(seconds) {
  return `sleep ${seconds}.${descriptor.marker}`
}
