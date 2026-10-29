// THROWAWAY SPIKE (issue #254): machine-readable proof results (JSON lines).
import { appendFileSync, mkdirSync } from "node:fs"
import { dirname, join } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

import { TARGET } from "./env.mjs"

const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..")
export const RESULTS_PATH =
  process.env.SPIKE_RESULTS ?? join(packageDir, "spike-results", `results-${TARGET}.jsonl`)

export class SkipProof extends Error {}

export function record({ id, level, status, detail }) {
  mkdirSync(dirname(RESULTS_PATH), { recursive: true })
  const line = {
    id,
    level,
    status,
    detail,
    target: TARGET,
    platform: `${process.platform}-${process.arch}`,
    node: process.version,
    at: new Date().toISOString(),
  }
  appendFileSync(RESULTS_PATH, `${JSON.stringify(line)}\n`)
}

/**
 * Registers one proof as a node:test test and records its outcome.
 * `fn` returns a detail object; throwing SkipProof records a skip.
 * Hard and other proofs fail the suite on failure; soft proofs only record.
 * A skipped hard proof is recorded as `skip` AND fails the suite.
 * @param {string} id
 * @param {"hard"|"other"|"soft"} level
 * @param {string} title
 * @param {(t: import("node:test").TestContext) => Promise<unknown>} fn
 */
export function proof(id, level, title, fn) {
  test(`[${level}] ${id}: ${title}`, async (t) => {
    try {
      const detail = await fn(t)
      record({ id, level, status: "pass", detail: detail ?? null })
    } catch (error) {
      if (error instanceof SkipProof) {
        record({ id, level, status: "skip", detail: { reason: error.message } })
        // A hard proof may never be skipped: a skip counts as a failure.
        if (level === "hard") throw new Error(`hard proof skipped: ${error.message}`)
        t.skip(error.message)
        return
      }
      const detail = { error: error?.message ?? String(error), code: error?.code ?? null }
      record({ id, level, status: "fail", detail })
      if (level === "soft") {
        t.diagnostic(`soft proof failed (recorded as limitation): ${detail.error}`)
        return
      }
      throw error
    }
  })
}
