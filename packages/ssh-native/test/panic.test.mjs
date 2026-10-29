import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { describe, it } from "node:test"
import { fileURLToPath } from "node:url"

import { INDEX_PATH } from "./helpers/binding.mjs"

const CHILD = fileURLToPath(new URL("children/panic-child.mjs", import.meta.url))
const FIXED_MESSAGE = "internal error in the native SSH binding"
const SYNC_KINDS = new Set(["convert", "sync"])

describe("panic probe", () => {
  it("maps a panic at every entry point to INTERNAL, silently, without aborting", () => {
    const child = spawnSync(process.execPath, [CHILD], {
      encoding: "utf8",
      env: { ...process.env, SSH_NATIVE_INDEX: INDEX_PATH },
      timeout: 30_000,
    })
    assert.equal(child.stderr, "", "a panic must print nothing")
    assert.equal(child.signal, null)
    assert.equal(child.status, 0)
    const lines = child.stdout.trim().split("\n")
    assert.equal(lines.at(-1), "PROBES-DONE", "the process keeps running after the probes")
    const outcomes = lines.slice(0, -1).map((line) => JSON.parse(line))
    assert.deepEqual(
      outcomes.map((outcome) => outcome.kind),
      ["sync", "convert", "async", "event", "execReader", "handler"]
    )
    for (const outcome of outcomes) {
      assert.equal(outcome.code, "INTERNAL", outcome.kind)
      assert.equal(outcome.message, FIXED_MESSAGE, outcome.kind)
      assert.doesNotMatch(outcome.message, /probe/v, "no panic text leaks")
      if (SYNC_KINDS.has(outcome.kind)) assert.equal(outcome.returned, "throw", outcome.kind)
      else
        assert.deepEqual([outcome.returned, outcome.settled], ["promise", "rejected"], outcome.kind)
    }
  })
})
