import type * as FsPromises from "node:fs/promises"

import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { readFile, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment } from "../src/types.js"

vi.mock("node:fs/promises", async () => {
  const actual = await vi.importActual<typeof FsPromises>("node:fs/promises")
  return {
    ...actual,
    readFile: vi.fn(actual.readFile),
    stat: vi.fn(actual.stat),
  }
})

const actualFsPromises = await vi.importActual<typeof FsPromises>("node:fs/promises")
const mockedReadFile = vi.mocked(readFile)
const mockedStat = vi.mocked(stat)

const { ENVIRONMENT_FILE_BYTE_LIMIT, loadDotEnvironment, mergeEnvironment, resolveEnvironment } =
  await import("../src/environment.js")

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

  it("throws an error when the key exists only on the prototype", async () => {
    const env: Environment = {}
    Object.setPrototypeOf(env, { INHERITED_KEY: "prototype-value" })

    await expect(resolveEnvironment(env, "INHERITED_KEY")).rejects.toThrow(
      'Env key "INHERITED_KEY" is not defined'
    )
  })

  it("returns an own key even when the environment has inherited keys", async () => {
    const env: Environment = { OWN_KEY: "own-value" }
    Object.setPrototypeOf(env, { INHERITED_KEY: "prototype-value" })

    await expect(resolveEnvironment(env, "OWN_KEY")).resolves.toBe("own-value")
  })
})

describe("loadDotEnvironment", () => {
  let tmpFile: string

  beforeEach(() => {
    tmpFile = join(tmpdir(), `paratix-test-${randomUUID()}.env`)
    mockedReadFile.mockImplementation(actualFsPromises.readFile)
    mockedStat.mockImplementation(actualFsPromises.stat)
  })

  afterEach(() => {
    mockedReadFile.mockReset()
    mockedStat.mockReset()
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

  // R-0000069 regression: loadDotEnvironment must apply the same
  // ENVIRONMENT_KEY_PATTERN allow-list that cli.ts collectEnvironment uses
  // and explicitly reject reserved JavaScript identifiers, so malformed or
  // dangerous keys cannot leak into meta.env.
  it("rejects keys that start with a digit", async () => {
    writeFileSync(tmpFile, "1KEY=value\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/Invalid env key/v)
  })

  it("rejects keys that contain a space", async () => {
    writeFileSync(tmpFile, "KEY WITH SPACE=value\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/Invalid env key/v)
  })

  it("rejects the reserved __proto__ key", async () => {
    writeFileSync(tmpFile, "__proto__=evil\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/Forbidden env key/v)
  })

  it("includes the file name and line number in the rejection error", async () => {
    writeFileSync(tmpFile, "VALID=ok\nBAD KEY=oops\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/line 2/v)
  })

  it("loads valid keys without rejecting them", async () => {
    writeFileSync(tmpFile, "HOST=example.com\n_LEADING_UNDERSCORE=ok\nPORT_8080=8080\n")
    const env = await loadDotEnvironment(tmpFile)
    expect(env.HOST).toBe("example.com")
    expect(env._LEADING_UNDERSCORE).toBe("ok")
    expect(env.PORT_8080).toBe("8080")
  })

  it("rejects oversized env files before reading their contents", async () => {
    const size = ENVIRONMENT_FILE_BYTE_LIMIT + 1
    mockedStat.mockResolvedValueOnce({ size } as Awaited<ReturnType<typeof stat>>)

    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(
      `size ${size} bytes exceeds the ${ENVIRONMENT_FILE_BYTE_LIMIT}-byte cap`
    )
    expect(mockedReadFile).not.toHaveBeenCalled()
  })

  // R-0000747: NUL is used internally as a sentinel for escaped backslashes
  // in double-quoted values, so a literal NUL in the raw input would survive
  // the swap and corrupt the decoded value. NUL also terminates strings in
  // shells and many syscalls, so any branch must refuse the file outright.
  it("rejects unquoted values that contain a literal NUL byte", async () => {
    writeFileSync(tmpFile, "TOKEN=before\0after\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/NUL byte/v)
  })

  it("rejects double-quoted values that contain a literal NUL byte", async () => {
    writeFileSync(tmpFile, 'TOKEN="before\0after"\n')
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/NUL byte/v)
  })

  it("rejects single-quoted values that contain a literal NUL byte", async () => {
    writeFileSync(tmpFile, "TOKEN='before\0after'\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/NUL byte/v)
  })

  it("names the offending file and line number when refusing a NUL byte value", async () => {
    writeFileSync(tmpFile, "OK=fine\nLEAK=before\0after\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/line 2/v)
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(tmpFile)
  })

  // R-0000791: a literal CR (0x0D) byte inside a dotenv value emerges
  // unprintable downstream, hides line-ending mismatches inside values, and
  // can re-introduce mixed CRLF state into shell command lines. The
  // double-quoted decoder interprets only `\n` / `\\` / `\"` escapes, so
  // a literal CR is never the intended way to smuggle a newline in. Refuse
  // it the same way NUL is refused.
  it("rejects unquoted values that contain a literal carriage return (R-0000791)", async () => {
    writeFileSync(tmpFile, "TOKEN=before\rafter\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/carriage return/v)
  })

  it("rejects double-quoted values that contain a literal carriage return (R-0000791)", async () => {
    writeFileSync(tmpFile, 'TOKEN="before\rafter"\n')
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/carriage return/v)
  })

  it("rejects single-quoted values that contain a literal carriage return (R-0000791)", async () => {
    writeFileSync(tmpFile, "TOKEN='before\rafter'\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/carriage return/v)
  })

  it("names the offending file and line number when refusing a CR-byte value (R-0000791)", async () => {
    writeFileSync(tmpFile, "OK=fine\nLEAK=before\rafter\n")
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(/line 2/v)
    await expect(loadDotEnvironment(tmpFile)).rejects.toThrow(tmpFile)
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
    expect(Object.keys(merged)).toHaveLength(0)
  })

  // R-0000070 regression: mergeEnvironment must seed its result with a
  // null-prototype object so reserved property names like `constructor`
  // and `__proto__` cannot inherit prototype semantics. Setting
  // `constructor` to a string must produce that string at lookup time,
  // never the global Object constructor.
  it("uses a null-prototype result so the reserved key constructor stores the assigned string", () => {
    const base: Environment = { HOST: "example.com" }
    const override: Environment = { constructor: "evil" }
    const merged = mergeEnvironment(base, override)
    expect(merged.constructor).toBe("evil")
    expect(Object.getPrototypeOf(merged)).toBeNull()
  })

  it("uses a null-prototype result on an empty merge so the prototype chain cannot pollute lookups", () => {
    const merged = mergeEnvironment()
    expect(Object.getPrototypeOf(merged)).toBeNull()
  })
})
