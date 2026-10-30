// Child process of panic.test.mjs: runs every panic probe one after another,
// prints one JSON line per probe and a final marker, and must exit 0 with
// empty stderr.
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
/** @type {typeof import("../../index.js")} */
const binding = require("../../index.js")

const KINDS = /** @type {const} */ (["sync", "convert", "async", "event", "execReader", "handler"])

/**
 * @param kind one of KINDS
 * @returns whether it threw or rejected, with code and message
 */
async function probe(kind) {
  /** @type {Record<string, unknown>} */
  const outcome = { kind }
  let pending
  try {
    pending = binding.__internalPanicProbe(kind)
  } catch (error) {
    return { ...outcome, code: error.code, message: error.message, returned: "throw" }
  }
  try {
    await pending
    return { ...outcome, returned: "promise", settled: "resolved" }
  } catch (error) {
    return {
      ...outcome,
      code: error.code,
      message: error.message,
      returned: "promise",
      settled: "rejected",
    }
  }
}

/**
 * Runs the probes one after another, from `index` on.
 *
 * @param index first probe to run
 */
async function runFrom(index) {
  if (index >= KINDS.length) return
  const outcome = await probe(KINDS[index])
  process.stdout.write(`${JSON.stringify(outcome)}\n`)
  await runFrom(index + 1)
}

await runFrom(0)
process.stdout.write("PROBES-DONE\n")
