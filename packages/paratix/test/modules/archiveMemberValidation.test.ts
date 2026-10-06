import { afterEach, describe, expect, it, vi } from "vitest"

import type * as ArchiveMemberValidationModule from "../../src/modules/archiveMemberValidation.js"
import type * as SshHelpersModule from "../../src/sshHelpers.js"
import type { ExecResult, SshConnection } from "../../src/types.js"

const src = "/tmp/app.tar.gz"

/**
 * #193: the published package bundles `sshHelpers.ts` twice — once into
 * `dist/cli.js` (which creates the SSH connection whose strict UTF-8 decode
 * rejects) and once into the library chunk behind `dist/index.js` (where
 * `archive.extract` lists the members). Loading the error class and the
 * listing across `vi.resetModules()` simulates that bundle split without a
 * build.
 *
 * @returns The error classes of copy A and the member listing of copy B.
 */
async function loadErrorsAndListingFromDifferentCopies(): Promise<{
  memberValidation: typeof ArchiveMemberValidationModule
  sshHelpers: typeof SshHelpersModule
}> {
  vi.resetModules()
  const sshHelpers = await import("../../src/sshHelpers.js")
  vi.resetModules()
  const memberValidation = await import("../../src/modules/archiveMemberValidation.js")
  return { memberValidation, sshHelpers }
}

describe("listArchiveMembers across module copies (#193)", () => {
  afterEach(() => {
    vi.resetModules()
  })

  it("refuses a listing that another copy rejected as invalid UTF-8 instead of rethrowing it", async () => {
    const { memberValidation, sshHelpers } = await loadErrorsAndListingFromDifferentCopies()
    const conn = {
      async exec(): Promise<ExecResult> {
        await Promise.resolve()
        throw new sshHelpers.InvalidUtf8OutputError(
          `Command stdout is not valid UTF-8 (exit code 0): tar -tvzf '${src}'`
        )
      },
    } as unknown as SshConnection

    const result = await memberValidation.listArchiveMembers(conn, {
      archivePath: src,
      source: src,
    })

    expect(result).toStrictEqual({
      failureReason: `archive listing for ${src} is not valid UTF-8; refusing to validate member names that cannot be mapped to the extracted names reliably (a member name whose bytes are not valid UTF-8 cannot be mapped)`,
    })
  })
})
