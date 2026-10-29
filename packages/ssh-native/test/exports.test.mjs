import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, it } from "node:test"

import { binding, PACKAGE_DIR } from "./helpers/binding.mjs"

const DECLARED_VALUE = /^export declare (?:function|const) (?<name>\w+)/gmv

describe("index.d.ts", () => {
  it("declares exactly the runtime exports of index.js", () => {
    const dts = readFileSync(join(PACKAGE_DIR, "index.d.ts"), "utf8")
    const declared = new Set([...dts.matchAll(DECLARED_VALUE)].map((match) => match.groups?.name))
    assert.deepEqual([...declared].sort(), Object.keys(binding).sort())
    assert.doesNotMatch(dts, /export declare class/v, "no raw native class leaks into the types")
  })
})
