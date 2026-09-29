/**
 * Issue #219: shell-level smoke tests for the locale-independent tar listing.
 *
 * The production listing script runs on the local `/bin/sh` against the local
 * `tar` (GNU tar in Linux CI, bsdtar on macOS) with `LC_ALL=C` in the session
 * environment, the locale minimal images and `sudo` often leave an SSH exec
 * with. The fixtures are ustar archives written byte by byte, so member names
 * need not be valid on the local filesystem.
 */
import { spawnSync } from "node:child_process"
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
} from "../../src/modules/archiveMemberValidation.js"
import { tarListingScript } from "../../src/modules/archiveTarListing.js"
import { localShellConnection } from "../helpers/localShell.js"

const SKIP_PLATFORM = process.platform === "win32"
const USTAR_BLOCK = 512
const GO_MEMBER = "go/test/fixedbugs/issue27836.dir/Þfoo.go"

/** A ustar member: a regular file (`0`), a directory (`5`) or a symlink (`2`). */
type UstarMember = { linkName?: Buffer; name: Buffer; type: "0" | "2" | "5" }

/**
 * Write an ASCII field into a ustar header.
 *
 * @param header - The 512-byte header to write into.
 * @param offset - Where the field starts in the header.
 * @param value - The ASCII text, including any NUL terminator.
 */
function writeField(header: Buffer, offset: number, value: string): void {
  header.write(value, offset, "latin1")
}

/**
 * Build one ustar header block with raw name bytes.
 *
 * @param member - The member to describe.
 * @returns The 512-byte header.
 */
function ustarHeader(member: UstarMember): Buffer {
  const header = Buffer.alloc(USTAR_BLOCK)
  member.name.copy(header, 0)
  writeField(header, 100, member.type === "5" ? "0000755\0" : "0000644\0")
  writeField(header, 108, "0000000\0")
  writeField(header, 116, "0000000\0")
  writeField(header, 124, "00000000000\0")
  writeField(header, 136, "00000000000\0")
  writeField(header, 148, "        ")
  writeField(header, 156, member.type)
  member.linkName?.copy(header, 157)
  writeField(header, 257, "ustar\u000000")
  writeField(header, 265, "root\0")
  writeField(header, 297, "root\0")
  let checksum = 0
  for (const byte of header) checksum += byte
  writeField(header, 148, `${checksum.toString(8).padStart(6, "0")}\0 `)
  return header
}

/**
 * Write a ustar archive with empty members.
 *
 * @param path - The archive path.
 * @param members - The members in archive order.
 */
function writeUstar(path: string, members: readonly UstarMember[]): void {
  writeFileSync(
    path,
    Buffer.concat([...members.map((member) => ustarHeader(member)), Buffer.alloc(USTAR_BLOCK * 2)])
  )
}

/**
 * A file member with a UTF-8 or raw byte name.
 *
 * @param name - The member name.
 * @returns The member.
 */
function file(name: Buffer | string): UstarMember {
  return { name: typeof name === "string" ? Buffer.from(name, "utf8") : name, type: "0" }
}

/**
 * Run `body` with a scratch directory that holds the fixtures and, in `bin`,
 * a `locale` stub that fails, to force the `LC_ALL=C` fallback.
 *
 * @param body - The test body.
 * @returns The body's result.
 */
async function withScratch<T>(body: (root: string) => Promise<T>): Promise<T> {
  const root = mkdtempSync(join(tmpdir(), "paratix-tar-listing-"))
  try {
    mkdirSync(join(root, "bin"))
    writeFileSync(join(root, "bin", "locale"), "#!/bin/sh\nexit 1\n")
    chmodSync(join(root, "bin", "locale"), 0o755)
    return await body(root)
  } finally {
    rmSync(root, { force: true, recursive: true })
  }
}

/**
 * The session environment of a host that leaves the exec in the C locale.
 *
 * @param root - The scratch directory.
 * @param forceCLocale - Whether the `locale` stub hides the UTF-8 C locales.
 * @returns The environment for {@link localShellConnection}.
 */
function cLocaleEnvironment(root: string, forceCLocale: boolean): NodeJS.ProcessEnv {
  const path = process.env.PATH ?? "/usr/bin:/bin"
  return {
    ...process.env,
    LANG: "C",
    LC_ALL: "C",
    PATH: forceCLocale ? `${join(root, "bin")}:${path}` : path,
  }
}

/**
 * The `tar` implementation the listing script will detect locally.
 *
 * @returns The flavor word of the mode line.
 */
function localTarFlavor(): string {
  const version = spawnSync("/bin/sh", ["-c", "LC_ALL=C tar --version 2>/dev/null"], {
    encoding: "utf8",
    timeout: 5000,
  }).stdout
  if (version.startsWith("tar (GNU tar) ")) return "gnu"
  if (version.startsWith("bsdtar ")) return "bsd"
  return "other"
}

const LOCAL_TAR_FLAVOR = SKIP_PLATFORM ? "other" : localTarFlavor()
// Issue #219: names are only decoded for GNU tar and bsdtar; BusyBox and
// other tar implementations list them raw and keep the older rules.
const SKIP_UNDECODED_TAR = SKIP_PLATFORM || LOCAL_TAR_FLAVOR === "other"
// Issue #219: the locale the listing script picks when the host has a UTF-8
// C locale; bsdtar always runs under `LC_ALL=C`.
const DEFAULT_LISTING_LOCALE = LOCAL_TAR_FLAVOR === "bsd" ? /^C$/v : /^C\.(?:UTF-8|utf8)$/v

/**
 * The members of a listing that must have succeeded.
 *
 * @param listing - The result of `listArchiveMembers`.
 * @returns The parsed members of the successful listing.
 * @throws {Error} When the listing was refused.
 */
function listedMembers(listing: Awaited<ReturnType<typeof listArchiveMembers>>): ArchiveMember[] {
  if ("members" in listing) return listing.members
  throw new Error(listing.failureReason)
}

describe.skipIf(SKIP_UNDECODED_TAR)(
  "tar listing independent of the host locale (Issue #219)",
  () => {
    it.each([
      {
        expectedLocale: DEFAULT_LISTING_LOCALE,
        forceCLocale: false,
        name: "a UTF-8 C locale when the host has one",
      },
      { expectedLocale: /^C$/v, forceCLocale: true, name: "the LC_ALL=C decode fallback" },
    ])(
      "lists a non-ASCII member name exactly with $name",
      async ({ expectedLocale, forceCLocale }) => {
        await withScratch(async (root) => {
          const archivePath = join(root, "go.tar")
          writeUstar(archivePath, [
            { name: Buffer.from("go/"), type: "5" },
            { name: Buffer.from("go/test/fixedbugs/issue27836.dir/"), type: "5" },
            file(GO_MEMBER),
            { linkName: Buffer.from("Þfoo.go"), name: Buffer.from("go/test/Þlink"), type: "2" },
          ])
          const { conn } = localShellConnection({ env: cLocaleEnvironment(root, forceCLocale) })

          const script = await conn.exec(tarListingScript("-tvf", archivePath))
          const members = listedMembers(
            await listArchiveMembers(conn, { archivePath, source: archivePath })
          )

          const [prefix, flavor, locale] = script.stdout.split("\n")[0].split(" ")
          expect(prefix).toBe("paratix-tar-listing")
          expect(flavor).toBe(LOCAL_TAR_FLAVOR)
          expect(locale).toMatch(expectedLocale)
          expect(members.map((member) => [member.path, member.linkTarget])).toStrictEqual([
            ["go/", null],
            ["go/test/fixedbugs/issue27836.dir/", null],
            [GO_MEMBER, null],
            ["go/test/Þlink", "Þfoo.go"],
          ])
          expect(members.map((member) => archiveMemberUnsafeReason(member))).toStrictEqual([
            null,
            null,
            null,
            null,
          ])
        })
      }
    )

    it.each([false, true])(
      "refuses a member name whose bytes are not valid UTF-8 (forced C locale: %s)",
      async (forceCLocale) => {
        await withScratch(async (root) => {
          const archivePath = join(root, "inv.tar")
          writeUstar(archivePath, [file(Buffer.from([0x69, 0x6e, 0x76, 0xff, 0x78]))])
          const { conn } = localShellConnection({ env: cLocaleEnvironment(root, forceCLocale) })

          const listing = await listArchiveMembers(conn, { archivePath, source: archivePath })

          expect(listing).toStrictEqual({
            failureReason:
              'member name "inv\\\\377x" in the tar listing cannot be mapped to the extracted name (the decoded bytes are not valid UTF-8)',
          })
        })
      }
    )

    it.each([false, true])(
      "decodes a real backslash and still refuses it (forced C locale: %s)",
      async (forceCLocale) => {
        await withScratch(async (root) => {
          const archivePath = join(root, "bs.tar")
          writeUstar(archivePath, [file("app/a\\303")])
          const { conn } = localShellConnection({ env: cLocaleEnvironment(root, forceCLocale) })

          const members = listedMembers(
            await listArchiveMembers(conn, { archivePath, source: archivePath })
          )

          expect(members.map((member) => member.path)).toStrictEqual(["app/a\\303"])
          expect(archiveMemberUnsafeReason(members[0])).toContain(
            "contains a backslash or a U+FFFD replacement character"
          )
        })
      }
    )
  }
)
