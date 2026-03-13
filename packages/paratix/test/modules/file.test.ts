import { describe, expect, it } from "vitest"

import { file } from "../../src/modules/file.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("file.directory", () => {
  it("check returns ok when the directory exists", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
    })
    const mod = file.directory("/var/app")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the directory does not exist", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 1 },
    })
    const mod = file.directory("/var/app")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.directory("/var/app")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.absent", () => {
  it("check returns ok when the path does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ]": { code: 1 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the path exists", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ]": { code: 0 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
