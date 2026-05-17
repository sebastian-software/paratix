import assert from "node:assert/strict"
import { describe, it } from "node:test"

import { publishWorkspacePackages } from "./publishWorkspacePackages.mjs"

const DEFAULT_STABLE_VERSION = "1.2.3"
const CREATE_PARATIX_NAME = "create-paratix"
const PARATIX_NAME = "paratix"
const CREATE_PARATIX_SPECIFIER = `${CREATE_PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const PARATIX_SPECIFIER = `${PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const BOTH_PACKAGE_SPECIFIERS = [CREATE_PARATIX_SPECIFIER, PARATIX_SPECIFIER]
const BETA_PRERELEASE_VERSION = `${DEFAULT_STABLE_VERSION}-beta.1`
const STABLE_BUILD_METADATA_VERSION = `${DEFAULT_STABLE_VERSION}+build.5`

function createFs({
  createParatixVersion = DEFAULT_STABLE_VERSION,
  paratixVersion = DEFAULT_STABLE_VERSION,
} = {}) {
  return {
    async readFile(path) {
      if (path === "packages/paratix/package.json") {
        return JSON.stringify({ name: "paratix", version: paratixVersion })
      }

      if (path === "packages/create-paratix/package.json") {
        return JSON.stringify({ name: CREATE_PARATIX_NAME, version: createParatixVersion })
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

function createCommandRunner(initiallyPublished = new Set(), publishedVersions = {}) {
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
      // Use the explicit per-directory version override when provided so
      // tests can simulate publishing arbitrary prerelease/build-metadata
      // versions, falling back to the legacy 1.2.3 specifier so existing
      // tests keep working without touching the helper.
      const isCreateParatix = directory.endsWith(CREATE_PARATIX_NAME)
      const defaultSpecifier = isCreateParatix ? CREATE_PARATIX_SPECIFIER : PARATIX_SPECIFIER
      const versionOverride = isCreateParatix
        ? publishedVersions.createParatix
        : publishedVersions.paratix
      const packageSpecifier =
        versionOverride === undefined
          ? defaultSpecifier
          : `${isCreateParatix ? CREATE_PARATIX_NAME : PARATIX_NAME}@${versionOverride}`
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
      [
        "pnpm",
        "--dir",
        "packages/paratix",
        "publish",
        "--no-git-checks",
        "--provenance",
        "--tag",
        "latest",
      ],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      [
        "pnpm",
        "--dir",
        "packages/create-paratix",
        "publish",
        "--no-git-checks",
        "--provenance",
        "--tag",
        "latest",
      ],
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

  // R-0000660: `pnpm publish` defaults to `--tag latest`, which would silently
  // overwrite the `latest` dist-tag with a prerelease build. Versions
  // containing a SemVer prerelease segment must publish under `next`
  // instead, while stable versions must continue to set `--tag latest`
  // explicitly so the dist-tag intent never depends on pnpm's default.
  it("R-0000660: publishes prerelease versions under --tag next", async () => {
    assertPublishCallsUseDistributionTag({
      expectedTag: "next",
      version: BETA_PRERELEASE_VERSION,
    })
  })

  it("R-0000660: keeps stable versions with build metadata on --tag latest", async () => {
    assertPublishCallsUseDistributionTag({
      expectedTag: "latest",
      version: STABLE_BUILD_METADATA_VERSION,
    })
  })
})

async function assertPublishCallsUseDistributionTag({ expectedTag, version }) {
  const commandRunner = createCommandRunner(new Set(), {
    createParatix: version,
    paratix: version,
  })

  await publishWorkspacePackages({
    availabilityDelayMilliseconds: 0,
    availabilityRetries: 2,
    commandRunner,
    fs: createFs({ createParatixVersion: version, paratixVersion: version }),
  })

  const publishCalls = commandRunner.calls.filter((call) => call[0] === "pnpm")
  assert.equal(publishCalls.length, 2)
  const everyCallHasExpectedTag = publishCalls.every(
    (call) => call.includes("--tag") && call[call.indexOf("--tag") + 1] === expectedTag
  )
  assert.equal(everyCallHasExpectedTag, true)
}
