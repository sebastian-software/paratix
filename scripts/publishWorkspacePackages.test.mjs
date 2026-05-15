import assert from "node:assert/strict"
import { describe, it } from "node:test"

import { publishWorkspacePackages } from "./publishWorkspacePackages.mjs"

const CREATE_PARATIX_SPECIFIER = "create-paratix@1.2.3"
const PARATIX_SPECIFIER = "paratix@1.2.3"
const BOTH_PACKAGE_SPECIFIERS = [CREATE_PARATIX_SPECIFIER, PARATIX_SPECIFIER]

function createFs({ createParatixVersion = "1.2.3", paratixVersion = "1.2.3" } = {}) {
  return {
    async readFile(path) {
      if (path === "packages/paratix/package.json") {
        return JSON.stringify({ name: "paratix", version: paratixVersion })
      }

      if (path === "packages/create-paratix/package.json") {
        return JSON.stringify({ name: "create-paratix", version: createParatixVersion })
      }

      throw new Error(`Unexpected path: ${path}`)
    },
  }
}

function createMissingPackageError() {
  const error = new Error("missing")
  error.stderr = "npm ERR! code E404"
  return error
}

function createCommandRunner(initiallyPublished = new Set()) {
  const published = new Set(initiallyPublished)
  const calls = []

  return {
    calls,
    async execFile(command, commandArguments) {
      calls.push([command, ...commandArguments])

      const packageSpecifier = commandArguments[1]
      if (published.has(packageSpecifier)) {
        const version = packageSpecifier.slice(packageSpecifier.lastIndexOf("@") + 1)
        return { stdout: JSON.stringify(version) }
      }

      throw createMissingPackageError()
    },
    async spawn(command, commandArguments) {
      calls.push([command, ...commandArguments])
      const directory = commandArguments[1]
      const packageSpecifier = directory.endsWith("create-paratix")
        ? CREATE_PARATIX_SPECIFIER
        : PARATIX_SPECIFIER
      published.add(packageSpecifier)
    },
  }
}

function hasCommandCall(calls, command) {
  for (const call of calls) {
    if (call[0] === command) return true
  }

  return false
}

async function assertRejectsWithMessage(promise, expectedMessage) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.message.includes(expectedMessage), true)
    return
  }

  assert.fail("Expected promise to reject.")
}

describe("publishWorkspacePackages", () => {
  it("publishes paratix, waits for registry availability, then publishes create-paratix", async () => {
    const commandRunner = createCommandRunner()

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      availabilityRetries: 2,
      commandRunner,
      fs: createFs(),
    })

    assert.deepEqual(commandRunner.calls, [
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["pnpm", "--dir", "packages/paratix", "publish", "--no-git-checks", "--provenance"],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      ["pnpm", "--dir", "packages/create-paratix", "publish", "--no-git-checks", "--provenance"],
    ])
  })

  it("skips already published packages after verifying paratix is available", async () => {
    const commandRunner = createCommandRunner(new Set(BOTH_PACKAGE_SPECIFIERS))

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      commandRunner,
      fs: createFs(),
    })

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("fails clearly when create-paratix is published without a matching paratix runtime", async () => {
    const commandRunner = createCommandRunner(new Set([CREATE_PARATIX_SPECIFIER]))

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
      }),
      "create-paratix@1.2.3 is already published, but paratix@1.2.3 is not available"
    )
  })

  it("rejects mismatched workspace package versions before publishing", async () => {
    const commandRunner = createCommandRunner()

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        commandRunner,
        fs: createFs({ createParatixVersion: "1.2.4" }),
      }),
      "versions must match"
    )

    assert.equal(commandRunner.calls.length, 0)
  })
})
