import { describe, expect, it } from "vitest"

import {
  FLAGS_DIRECTORY,
  hasFlag,
  setFlag,
  setVersionedFlag,
} from "../../src/modules/moduleHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, { strict: false, ...options })

describe("hasFlag – empty string validation", () => {
  it("throws when flagName is an empty string", async () => {
    // An empty flagName produces shellQuote("") === "''" which expands the
    // glob pattern to match all flags, causing silent data-loss or wrong results.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "")).rejects.toThrow(/flagName must match/v)
  })

  it("does not throw for a valid flagName", async () => {
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "valid-flag")).resolves.not.toThrow()
  })
})

describe("setVersionedFlag – empty string validation", () => {
  it("throws when flagName is an empty string", async () => {
    // shellQuote("") === "''" – touch would create a file literally named "''"
    // instead of the intended versioned flag.
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, "", "valid-prefix-")).rejects.toThrow(/flagName must match/v)
  })

  it("throws when flagPrefix is an empty string", async () => {
    // shellQuote("") === "''" – the find -name glob becomes "''"* which in bash
    // expands to * and would delete ALL flags on the target system.
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, "valid-flag-1.0", "")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("does not throw for valid flagName and flagPrefix", async () => {
    const flagPrefix = "valid-prefix-"
    const flagName = "valid-prefix-1.0"
    const ssh = createMockSsh({
      [`find ${FLAGS_DIRECTORY} -maxdepth 1 -name '${flagPrefix}*' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`]:
        {
          code: 0,
        },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, flagName, flagPrefix)).resolves.not.toThrow()
  })

  it("calls find with the correct prefix glob to replace old versioned flags", async () => {
    const flagPrefix = "myapp-"
    const flagName = "myapp-2.0"
    const expectedCommand = `find ${FLAGS_DIRECTORY} -maxdepth 1 -name '${flagPrefix}*' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`
    const ssh = createMockSsh({
      [expectedCommand]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await setVersionedFlag(ssh, flagName, flagPrefix)
    expect(ssh.calls).toContain(expectedCommand)
  })
})

describe("hasFlag – rejects path-traversal-like names", () => {
  it("rejects flagName equal to '..' (would resolve to parent directory)", async () => {
    // [ -f /var/lib/paratix/flags/.. ] would always be true, masking missing flags.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "..")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName with a leading dot", async () => {
    // Hidden-style names like ".foo" are not permitted; they collide with the
    // directory-traversal exclusion and complicate reasoning about flag files.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, ".foo")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing a path separator", async () => {
    // A `/` would let a flag name escape the flags directory entirely.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "foo/bar")).rejects.toThrow(/flagName must match/v)
  })
})

describe("setFlag – rejects path-traversal-like names", () => {
  it("rejects flagName equal to '..'", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, "..")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName with a leading dot", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, ".foo")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing a path separator", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, "foo/bar")).rejects.toThrow(/flagName must match/v)
  })

  it("does not throw for a valid flagName", async () => {
    const flagName = "valid-flag"
    const ssh = createMockSsh({
      [`touch ${FLAGS_DIRECTORY}/'${flagName}'`]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await expect(setFlag(ssh, flagName)).resolves.not.toThrow()
  })
})

describe("setVersionedFlag – rejects path-traversal-like names", () => {
  it("rejects flagPrefix equal to '..'", async () => {
    // A `..` prefix would let `find -name '..*' -delete` target paths outside
    // the flags directory hierarchy on some find implementations.
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "..")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagPrefix with a leading dot", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", ".hidden-")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagPrefix containing a path separator", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "foo/bar")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagName equal to '..'", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "..", "valid-prefix-")).rejects.toThrow(
      /flagName must match/v
    )
  })
})

describe("setVersionedFlag – rejects shell-special characters", () => {
  it("rejects flagPrefix containing spaces and parentheses", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "my prefix (v2)")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagName containing semicolons (command injection attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "safe; rm -rf /; #1.0", "safe-")).rejects.toThrow(
      /flagName must match/v
    )
  })

  it("rejects flagName containing backticks (command substitution attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "`id`1.0", "valid-")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing $() (command substitution attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "$(id)1.0", "valid-")).rejects.toThrow(
      /flagName must match/v
    )
  })
})
