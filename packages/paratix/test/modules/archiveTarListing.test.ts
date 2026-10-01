/**
 * Issue #219: unit tests for the locale-independent tar listing: the listing
 * script, its mode line, the escape decoder and how `listArchiveMembers`
 * applies them.
 */
import { describe, expect, it } from "vitest"

import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
  listArchiveMembersCommand,
} from "../../src/modules/archiveMemberValidation.js"
import {
  decodeTarListingName,
  splitTarListingModeLine,
  tarListingScript,
} from "../../src/modules/archiveTarListing.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const src = "/tmp/app.tar.gz"
const fields = "root/root 0 1970-01-01 00:00"
const bsdFields = "0 root   wheel       0 Jan  1  1970"

/**
 * List a mocked tar archive whose listing script prints `stdout`.
 *
 * @param stdout - The complete stdout of the listing script.
 * @returns The listing result.
 */
async function listMocked(stdout: string): ReturnType<typeof listArchiveMembers> {
  const mockSsh = createMockSsh({ [tarListingScript("-tvzf", src)]: { code: 0, stdout } })
  return listArchiveMembers(mockSsh, { archivePath: src, source: src })
}

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

describe("tarListingScript (Issue #219)", () => {
  it("detects the tar, picks a verified UTF-8 C locale and prints the mode line before tar", () => {
    expect(tarListingScript("-tvzf", "/tmp/it's.tar.gz")).toBe(
      [
        "case $(LC_ALL=C tar --version 2>/dev/null) in",
        "  'tar (GNU tar) '*) paratix_tar_flavor=gnu ;;",
        "  'bsdtar '*) paratix_tar_flavor=bsd ;;",
        "  *) paratix_tar_flavor=other ;;",
        "esac",
        "paratix_tar_locale=C",
        'if [ "$paratix_tar_flavor" != bsd ]; then',
        "  for paratix_tar_candidate in C.UTF-8 C.utf8; do",
        '    if [ "$(LC_ALL=$paratix_tar_candidate locale charmap 2>/dev/null)" = UTF-8 ]; then',
        "      paratix_tar_locale=$paratix_tar_candidate",
        "      break",
        "    fi",
        "  done",
        "fi",
        'printf \'%s %s %s\\n\' paratix-tar-listing "$paratix_tar_flavor" "$paratix_tar_locale"',
        'if [ "$paratix_tar_flavor" = gnu ]; then',
        "  LC_ALL=$paratix_tar_locale tar --quoting-style=escape -tvzf '/tmp/it'\\''s.tar.gz'",
        "else",
        "  LC_ALL=$paratix_tar_locale tar -tvzf '/tmp/it'\\''s.tar.gz'",
        "fi",
      ].join("\n")
    )
  })

  it.each([
    ["/tmp/a.tar", "-tvf"],
    ["/tmp/a.tar.gz", "-tvzf"],
    ["/tmp/a.tgz", "-tvzf"],
    ["/tmp/a.tar.bz2", "-tvjf"],
    ["/tmp/a.tar.xz", "-tvJf"],
  ])("is the listing command for %s", (source, flags) => {
    expect(listArchiveMembersCommand(source, "/tmp/x")).toBe(tarListingScript(flags, "/tmp/x"))
  })

  it("leaves the zip listing command unchanged", () => {
    expect(listArchiveMembersCommand("/tmp/a.zip", "/tmp/a.zip")).toBe("unzip -Zs '/tmp/a.zip'")
  })
})

describe("splitTarListingModeLine (Issue #219)", () => {
  it.each([
    ["gnu", "C.UTF-8"],
    ["gnu", "C.utf8"],
    ["gnu", "C"],
    ["bsd", "C"],
    ["other", "C.UTF-8"],
  ])("reads the mode line for %s tar under %s", (flavor, locale) => {
    expect(
      splitTarListingModeLine(`paratix-tar-listing ${flavor} ${locale}\nrest\n`)
    ).toStrictEqual({ body: "rest\n", mode: { flavor, locale } })
  })

  it("accepts a mode line without any tar output", () => {
    expect(splitTarListingModeLine("paratix-tar-listing gnu C")).toStrictEqual({
      body: "",
      mode: { flavor: "gnu", locale: "C" },
    })
  })

  it.each([
    ["no mode line", `-rw-r--r-- ${fields} app/file\n`],
    ["an empty listing", ""],
    ["an unknown flavor", "paratix-tar-listing star C\n"],
    ["an unknown locale", "paratix-tar-listing gnu en_US.UTF-8\n"],
    ["trailing text", "paratix-tar-listing gnu C extra\n"],
    ["a carriage return", "paratix-tar-listing gnu C\r\n"],
    ["a leading blank line", "\nparatix-tar-listing gnu C\n"],
  ])("refuses a listing with %s", (_name, stdout) => {
    expect(splitTarListingModeLine(stdout)).toStrictEqual({
      failureReason: expect.stringContaining(
        "tar listing does not start with the expected listing mode line"
      ),
    })
  })
})

describe("decodeTarListingName (Issue #219)", () => {
  it.each([
    ["plain", "app/file", "app/file"],
    ["raw non-ASCII", "app/Þfoo.go", "app/Þfoo.go"],
    [
      "octal UTF-8",
      "go/test/fixedbugs/issue27836.dir/\\303\\236foo.go",
      "go/test/fixedbugs/issue27836.dir/Þfoo.go",
    ],
    ["an escaped backslash", "a\\\\b", "a\\b"],
    ["an escaped backslash before digits", "a\\\\303", "a\\303"],
    ["a letter escape", "a\\tb\\nc", "a\tb\nc"],
    ["every letter escape", "\\a\\b\\f\\n\\r\\t\\v", "\u0007\b\f\n\r\t\v"],
    ["octal ASCII", "\\141", "a"],
    ["octal DEL", "x\\177", "x\u007F"],
    ["an escaped zero-width space", "zw\\342\\200\\213x", "zw\u200Bx"],
    ["raw and escaped UTF-8 mixed", "é\\303\\251", "éé"],
  ])("decodes %s", (_name, listed, expected) => {
    expect(decodeTarListingName(listed)).toStrictEqual({ name: expected })
  })

  it.each([
    ["an unknown letter escape", "a\\qb", '"\\\\qb"'],
    ["an escaped space", "a\\ b", '"\\\\ b"'],
    ["a trailing backslash", "ab\\", '"\\\\"'],
    ["a short octal escape", "a\\30", '"\\\\30"'],
    ["an octal escape above one byte", "a\\400", '"\\\\400"'],
    ["a non-octal digit", "a\\389", '"\\\\389"'],
  ])("refuses %s", (_name, listed, quoted) => {
    expect(decodeTarListingName(listed)).toStrictEqual({
      failureReason: `invalid escape sequence ${quoted}`,
    })
  })

  it.each([
    ["a lone continuation byte", "a\\200b"],
    ["a truncated sequence", "a\\303"],
    ["an invalid lead byte", "inv\\377x"],
    ["an overlong encoding", "\\300\\257"],
    ["an encoded surrogate", "\\355\\240\\200"],
  ])("refuses %s after decoding", (_name, listed) => {
    expect(decodeTarListingName(listed)).toStrictEqual({
      failureReason: "the decoded bytes are not valid UTF-8",
    })
  })
})

describe("listArchiveMembers with the listing mode line (Issue #219)", () => {
  it.each([
    ["gnu C", `-rw-r--r-- ${fields} go/\\303\\236foo.go`],
    ["gnu C.UTF-8", `-rw-r--r-- ${fields} go/Þfoo.go`],
    ["gnu C.utf8", `-rw-r--r-- ${fields} go/\\303\\236foo.go`],
    ["bsd C", `-rw-r--r--  ${bsdFields} go/\\303\\236foo.go`],
    ["other C.UTF-8", `-rw-r--r-- ${fields} go/Þfoo.go`],
  ])("yields the real name under %s", async (mode, line) => {
    const result = await listMocked(`paratix-tar-listing ${mode}\n${line}\n`)

    expect(result).toStrictEqual({
      members: [
        { format: "tar", kind: "file", linkTarget: null, mode: "-rw-r--r--", path: "go/Þfoo.go" },
      ],
    })
  })

  it("parses the bsdtar layout with a time column", async () => {
    const result = await listMocked(
      "paratix-tar-listing bsd C\n-rw-r--r--  0 bs5    wheel       0 Sep 29 18:55 app/a b\n"
    )

    expect(result).toMatchObject({ members: [{ kind: "file", path: "app/a b" }] })
  })

  it("decodes symlink and hardlink targets after splitting at the raw separator", async () => {
    const result = await listMocked(
      [
        "paratix-tar-listing gnu C",
        `lrwxrwxrwx ${fields} app/\\303\\236l -> \\303\\236t`,
        `hrw-r--r-- ${fields} app/h link to app/\\303\\236`,
        "",
      ].join("\n")
    )

    expect(result).toStrictEqual({
      members: [
        {
          format: "tar",
          kind: "symlink",
          linkTarget: "Þt",
          mode: "lrwxrwxrwx",
          path: "app/Þl",
        },
        { format: "tar", kind: "hardlink", linkTarget: "app/Þ", mode: "hrw-r--r--", path: "app/h" },
      ],
    })
  })

  it("keeps a decoded ` -> ` inside a name out of the separator split", async () => {
    // GNU tar never escapes spaces or `->`, so the listed text decides the
    // split; an escape that decodes to `-` or `>` cannot add a separator.
    const result = await listMocked(
      `paratix-tar-listing gnu C\nlrwxrwxrwx ${fields} app/a \\055\\076 b -> t\n`
    )

    expect(result).toMatchObject({ members: [{ linkTarget: "t", path: "app/a -> b" }] })
  })

  it("still refuses a raw separator that occurs twice", async () => {
    const result = await listMocked(
      `paratix-tar-listing gnu C\nlrwxrwxrwx ${fields} app/a -> b -> \\303\\236\n`
    )

    expect(result).toStrictEqual({
      failureReason: expect.stringContaining('link separator " -> " occurs more than once'),
    })
  })

  it("refuses a member name with an invalid escape", async () => {
    const result = await listMocked(
      `paratix-tar-listing gnu C.UTF-8\n-rw-r--r-- ${fields} app/a\\qb\n`
    )

    expect(result).toStrictEqual({
      failureReason:
        'member name "app/a\\\\qb" in the tar listing cannot be mapped to the extracted name (invalid escape sequence "\\\\qb")',
    })
  })

  it("refuses a member name whose bytes are not valid UTF-8", async () => {
    const result = await listMocked(
      `paratix-tar-listing gnu C\n-rw-r--r-- ${fields} app/inv\\377x\n`
    )

    expect(result).toStrictEqual({
      failureReason:
        'member name "app/inv\\\\377x" in the tar listing cannot be mapped to the extracted name (the decoded bytes are not valid UTF-8)',
    })
  })

  it("refuses a link target whose bytes are not valid UTF-8", async () => {
    const result = await listMocked(
      ["paratix-tar-listing bsd C", `lrwxrwxrwx  ${bsdFields} app/l -> \\377`, ""].join("\n")
    )

    expect(result).toStrictEqual({
      failureReason:
        'member name "\\\\377" in the tar listing cannot be mapped to the extracted name (the decoded bytes are not valid UTF-8)',
    })
  })

  it("keeps an escape of another tar as listed, where the backslash rule refuses it", async () => {
    const result = await listMocked(
      `paratix-tar-listing other C\n-rw-r--r-- ${fields} app/\\303\\236\n`
    )

    expect(result).toMatchObject({ members: [{ path: "app/\\303\\236" }] })
    expect(archiveMemberUnsafeReason(listedMembers(result)[0])).toContain(
      "contains a backslash or a U+FFFD replacement character"
    )
  })

  it("refuses a decoded control character with the control-character reason", async () => {
    const result = await listMocked(`paratix-tar-listing gnu C\n-rw-r--r-- ${fields} app/a\\nb\n`)

    expect(archiveMemberUnsafeReason(listedMembers(result)[0])).toBe(
      'member "app/a\\nb" contains control characters'
    )
  })

  it("refuses a listing without the mode line", async () => {
    const line = `-rw-r--r-- ${fields} app/file`
    const result = await listMocked(`${line}\n`)

    expect(result).toStrictEqual({
      failureReason: `tar listing does not start with the expected listing mode line: ${JSON.stringify(line)}`,
    })
  })

  it("does not let a forged mode line after the first one pass as a member", async () => {
    const result = await listMocked(
      `paratix-tar-listing other C\nparatix-tar-listing gnu C\n-rw-r--r-- ${fields} app/\\303\\236\n`
    )

    expect(result).toStrictEqual({
      failureReason: 'could not parse tar listing line: "paratix-tar-listing gnu C"',
    })
  })

  it("does not let a member named like the mode line change the mode", async () => {
    const result = await listMocked(
      `paratix-tar-listing other C\n-rw-r--r-- ${fields} paratix-tar-listing gnu C\n-rw-r--r-- ${fields} app/\\303\\236\n`
    )

    expect(result).toMatchObject({
      members: [{ path: "paratix-tar-listing gnu C" }, { path: "app/\\303\\236" }],
    })
  })

  // Issue #219: bsdtar prints ` link to TARGET` for every hardlink entry but
  // takes the mode character from the type bits of the header's mode field, so
  // a hardlink whose mode field carries S_IFREG, S_IFLNK or S_IFDIR lists with
  // `-`, `l` or `d` instead of `h`. Deciding link-ness from the mode character
  // alone let such a hardlink to a symlink bypass the hardlink rules.
  it.each([
    { mode: "hrw-r--r--", name: "the hardlink mode character" },
    { mode: "-rw-r--r--", name: "a regular-file mode character" },
    { mode: "lrw-r--r--", name: "a symlink mode character" },
    { mode: "drw-r--r--", name: "a directory mode character" },
  ])("reads a bsdtar ` link to ` line with $name as a hardlink", async ({ mode }) => {
    const result = await listMocked(
      `paratix-tar-listing bsd C\n${mode}  ${bsdFields} h link to a/b/s\n`
    )

    expect(result).toStrictEqual({
      members: [{ format: "tar", kind: "hardlink", linkTarget: "a/b/s", mode, path: "h" }],
    })
  })

  it("reads a bsdtar regular file named `notes link to readme` as a hardlink to readme", async () => {
    // Issue #219: bsdtar lists this regular file exactly like a hardlink
    // `notes` whose mode field carries S_IFREG, so the listing cannot tell them
    // apart; the parser reads the hardlink, whose rules are the stricter ones.
    const result = await listMocked(
      `paratix-tar-listing bsd C\n-rw-r--r--  ${bsdFields} notes link to readme\n`
    )

    expect(result).toStrictEqual({
      members: [
        {
          format: "tar",
          kind: "hardlink",
          linkTarget: "readme",
          mode: "-rw-r--r--",
          path: "notes",
        },
      ],
    })
  })

  it("keeps a bsdtar special file with ` link to ` in its name a special file", async () => {
    // Issue #219: a device named `dev link to x` lists like a hardlink with a
    // character-device mode field, so it stays refused as a special file.
    const result = await listMocked(
      ["paratix-tar-listing bsd C", `crw-r--r--  ${bsdFields} dev link to x`, ""].join("\n")
    )

    expect(result).toMatchObject({ members: [{ kind: "special", mode: "crw-r--r--" }] })
    expect(archiveMemberUnsafeReason(listedMembers(result)[0])).toContain("is a special file")
  })

  it.each([
    {
      line: `-rw-r--r--  ${bsdFields} f -> g`,
      member: { kind: "file", linkTarget: null, mode: "-rw-r--r--", path: "f -> g" },
      name: "a bsdtar regular file named f -> g",
    },
    {
      line: `lrwxrwxrwx  ${bsdFields} l -> t`,
      member: { kind: "symlink", linkTarget: "t", mode: "lrwxrwxrwx", path: "l" },
      name: "a bsdtar symlink",
    },
  ])("keeps $name as listed", async ({ line, member }) => {
    // Issue #219: libarchive always lists symlink entries with `l`, so on a
    // bsdtar line with another mode character ` -> ` is part of the name.
    const result = await listMocked(`paratix-tar-listing bsd C\n${line}\n`)

    expect(result).toStrictEqual({ members: [{ format: "tar", ...member }] })
  })

  it("keeps a GNU tar regular file whose name contains ` link to ` a regular file", async () => {
    // Issue #219: GNU tar derives the mode character from the typeflag, lists
    // every hardlink with `h` and prints ` link to ` only for hardlinks.
    const result = await listMocked(
      `paratix-tar-listing gnu C\n-rw-r--r-- ${fields} name link to y\n`
    )

    expect(result).toStrictEqual({
      members: [
        {
          format: "tar",
          kind: "file",
          linkTarget: null,
          mode: "-rw-r--r--",
          path: "name link to y",
        },
      ],
    })
  })

  it.each([
    { name: "the BusyBox ` -> ` separator", separator: " -> " },
    { name: "the ` link to ` separator", separator: " link to " },
  ])("reads a regular-file line of another tar with $name as a hardlink", async ({ separator }) => {
    // Issue #219: BusyBox tar marks hardlinks as regular files and lists them
    // as `name -> target`; extracting such an entry makes a hard link.
    const result = await listMocked(
      `paratix-tar-listing other C.UTF-8\n-rw-r--r-- ${fields} h${separator}a/b/s\n`
    )

    expect(result).toStrictEqual({
      members: [
        { format: "tar", kind: "hardlink", linkTarget: "a/b/s", mode: "-rw-r--r--", path: "h" },
      ],
    })
  })

  it("keeps a symlink line of another tar a symlink", async () => {
    const result = await listMocked(
      `paratix-tar-listing other C.UTF-8\nlrwxrwxrwx ${fields} l -> t\n`
    )

    expect(result).toStrictEqual({
      members: [{ format: "tar", kind: "symlink", linkTarget: "t", mode: "lrwxrwxrwx", path: "l" }],
    })
  })

  // Issue #219: once a separator marks a hardlink regardless of the mode
  // character, a remainder that carries it twice, or carries both separators,
  // has no recoverable name/target split and fails closed.
  it.each([
    {
      detail: 'link separator " link to " occurs more than once',
      line: `-rw-r--r--  ${bsdFields} a link to b link to c`,
      mode: "bsd C",
      name: "bsdtar `-` line a link to b link to c",
    },
    {
      detail: 'hardlink contains both " -> " and " link to "',
      line: `-rw-r--r--  ${bsdFields} a -> b link to c`,
      mode: "bsd C",
      name: "bsdtar `-` line a -> b link to c",
    },
    {
      detail: 'hardlink contains both " -> " and " link to "',
      line: `-rw-r--r--  ${bsdFields} a link to b -> c`,
      mode: "bsd C",
      name: "bsdtar `-` line a link to b -> c",
    },
    {
      detail: 'hardlink contains both " -> " and " link to "',
      line: `lrwxrwxrwx  ${bsdFields} a -> b link to c`,
      mode: "bsd C",
      name: "bsdtar `l` line a -> b link to c",
    },
    {
      detail: 'hardlink contains both " -> " and " link to "',
      line: `drw-r--r--  ${bsdFields} a link to b -> c`,
      mode: "bsd C",
      name: "bsdtar `d` line a link to b -> c",
    },
    {
      detail: 'link separator " -> " occurs more than once',
      line: `-rw-r--r-- ${fields} a -> b -> c`,
      mode: "other C.UTF-8",
      name: "another tar: `-` line a -> b -> c",
    },
    {
      detail: 'hardlink contains both " -> " and " link to "',
      line: `-rw-r--r-- ${fields} a -> b link to c`,
      mode: "other C.UTF-8",
      name: "another tar: `-` line a -> b link to c",
    },
  ])("refuses the ambiguous $name", async ({ detail, line, mode }) => {
    const result = await listMocked(`paratix-tar-listing ${mode}\n${line}\n`)

    expect(result).toStrictEqual({
      failureReason: `ambiguous tar listing line (${detail}): ${JSON.stringify(line)}`,
    })
  })
})
