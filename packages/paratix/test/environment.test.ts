import { unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import type { Environment } from "../src/types.js"

import { loadDotEnvironment, mergeEnvironment, resolveEnvironment } from "../src/environment.js"

describe("resolveEnvironment", () => {
  it("returns a string value directly", async () => {
    const env: Environment = { HOST: "example.com" }
    const result = await resolveEnvironment(env, "HOST")
    expect(result).toBe("example.com")
  })

  it("returns a number value directly", async () => {
    const env: Environment = { PORT: 8080 }
    const result = await resolveEnvironment(env, "PORT")
    expect(result).toBe(8080)
  })

  it("calls a synchronous lazy function and returns its result", async () => {
    const env: Environment = { SECRET: () => "lazy-value" }
    const result = await resolveEnvironment(env, "SECRET")
    expect(result).toBe("lazy-value")
  })

  it("calls an async lazy function and returns its resolved value", async () => {
    // eslint-disable-next-line @typescript-eslint/require-await -- Testing async lazy env value
    const env: Environment = { TOKEN: async () => "async-token" }
    const result = await resolveEnvironment(env, "TOKEN")
    expect(result).toBe("async-token")
  })

  it("throws an error when the key is not defined", async () => {
    const env: Environment = {}
    await expect(resolveEnvironment(env, "MISSING_KEY")).rejects.toThrow(
      'Env key "MISSING_KEY" is not defined'
    )
  })
})

describe("loadDotEnvironment", () => {
  let tmpFile: string

  beforeEach(() => {
    tmpFile = join(tmpdir(), `paratix-test-${Date.now()}.env`)
  })

  afterEach(() => {
    try {
      unlinkSync(tmpFile)
    } catch {
      // noop
    }
  })

  it("parses KEY=value lines into an Environment object", async () => {
    writeFileSync(tmpFile, "HOST=example.com\nPORT=3000\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.HOST).toBe("example.com")
    expect(env.PORT).toBe("3000")
  })

  it("ignores comment lines starting with #", async () => {
    writeFileSync(tmpFile, "# This is a comment\nHOST=example.com\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(Object.keys(env)).toHaveLength(1)
    expect(env.HOST).toBe("example.com")
  })

  it("ignores empty lines", async () => {
    writeFileSync(tmpFile, "\n\nHOST=example.com\n\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(Object.keys(env)).toHaveLength(1)
    expect(env.HOST).toBe("example.com")
  })

  it("strips surrounding double quotes from values", async () => {
    writeFileSync(tmpFile, 'TOKEN="my-secret-token"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.TOKEN).toBe("my-secret-token")
  })

  it("strips surrounding single quotes from values", async () => {
    writeFileSync(tmpFile, "TOKEN='my-secret-token'\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.TOKEN).toBe("my-secret-token")
  })

  // Escape sequences in double-quoted values
  it("expands \\n escape to a real newline in double-quoted value", async () => {
    writeFileSync(tmpFile, 'KEY="hello\\nworld"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("hello\nworld")
  })

  it('expands \\" escape to a double quote in double-quoted value', async () => {
    writeFileSync(tmpFile, 'KEY="escaped\\"quote"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe('escaped"quote')
  })

  it("expands \\\\ escape to a single backslash in double-quoted value", async () => {
    writeFileSync(tmpFile, 'KEY="back\\\\slash"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("back\\slash")
  })

  it('handles mixed escape sequences \\n, \\" and \\\\ in double-quoted value', async () => {
    writeFileSync(tmpFile, 'KEY="mixed\\n\\"\\\\"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe('mixed\n"\\')
  })

  it("treats \\\\ followed by n as literal backslash+n, not a newline", async () => {
    writeFileSync(tmpFile, 'KEY="literal\\\\n"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("literal\\n")
  })

  // Inline comments in unquoted values
  it("strips inline comment (space + #) from unquoted value", async () => {
    writeFileSync(tmpFile, "KEY=value # this is a comment\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("value")
  })

  it("keeps # without preceding space as part of an unquoted value", async () => {
    writeFileSync(tmpFile, "KEY=value#no-space\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("value#no-space")
  })

  it("strips inline comment with multiple spaces before # from unquoted value", async () => {
    writeFileSync(tmpFile, "KEY=value  # comment with extra space\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("value")
  })

  it("strips inline comment with tab whitespace before # from unquoted secret value", async () => {
    writeFileSync(tmpFile, "SECRET=tabbed-secret\t# inline comment\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.SECRET).toBe("tabbed-secret")
  })

  // No comment stripping or escape processing in quoted values
  it("keeps # and surrounding text as literal content in double-quoted value", async () => {
    writeFileSync(tmpFile, 'KEY="value # not a comment"\n')
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("value # not a comment")
  })

  it("keeps # and surrounding text as literal content in single-quoted value", async () => {
    writeFileSync(tmpFile, "KEY='value # not a comment'\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("value # not a comment")
  })

  it("treats backslash sequences literally in single-quoted value", async () => {
    writeFileSync(tmpFile, "KEY='no\\\\nescapes'\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.KEY).toBe("no\\\\nescapes")
  })
})

describe("mergeEnvironment", () => {
  it("merges multiple env objects into one", () => {
    const base: Environment = { HOST: "localhost", PORT: 80 }
    const override: Environment = { PORT: 443 }
    const merged = mergeEnvironment(base, override)
    expect(merged.HOST).toBe("localhost")
    expect(merged.PORT).toBe(443)
  })

  it("later values overwrite earlier values for the same key", () => {
    const first: Environment = { KEY: "first" }
    const second: Environment = { KEY: "second" }
    const third: Environment = { KEY: "third" }
    const merged = mergeEnvironment(first, second, third)
    expect(merged.KEY).toBe("third")
  })

  it("skips undefined env arguments", () => {
    const base: Environment = { HOST: "example.com" }
    const undef: Environment | undefined = undefined
    const merged = mergeEnvironment(base, undef)
    expect(merged.HOST).toBe("example.com")
  })

  it("returns an empty object when called with no arguments", () => {
    const merged = mergeEnvironment()
    expect(merged).toStrictEqual({})
  })
})
