/**
 * Locale-independent `tar -tv…f` listing for the member validation of
 * `archive.extract`.
 *
 * Issue #219: `tar` prints member names according to the locale of the exec
 * session, which Paratix does not control (ssh2 sends no `LANG`, minimal
 * images, non-login shells and `sudo` often leave a C/POSIX locale). In a C
 * locale GNU tar and bsdtar print every non-ASCII byte as a `\NNN` escape,
 * so a name such as `go/test/fixedbugs/issue27836.dir/Þfoo.go` reaches the
 * validation as `…/\303\236foo.go` and used to be refused.
 *
 * The listing therefore runs one small script ({@link tarListingScript}) that
 * detects the `tar` implementation, picks a UTF-8 C locale when the host has
 * one and reports both in a first line ({@link splitTarListingModeLine})
 * before `tar` prints anything. For GNU tar and bsdtar, whose escapes are
 * known and cover every backslash, each listed name is decoded back to its
 * bytes ({@link decodeTarListingName}) in every locale, so the same archive
 * yields the same names whichever locale the host offers. The output of any
 * other `tar` (for example BusyBox, which prints names raw) is used as
 * listed.
 */

import { shellQuote } from "../ssh.js"

/** Issue #219: the `tar` implementation the listing script detected. */
export type TarListingFlavor = "bsd" | "gnu" | "other"

/** Issue #219: the `LC_ALL` value the listing script ran `tar` under. */
export type TarListingLocale = "C.UTF-8" | "C.utf8" | "C"

/** Issue #219: how the listing was produced, as reported by its first line. */
export type TarListingMode = {
  /** The detected `tar` implementation. */
  flavor: TarListingFlavor
  /** The locale `tar` ran under. */
  locale: TarListingLocale
}

/** Issue #219: the first word of the mode line the listing script prints. */
export const TAR_LISTING_MODE_PREFIX = "paratix-tar-listing"

/**
 * Issue #219: the complete mode line. It starts with a word no `tar -tv`
 * member line can start with (those start with a mode string), and it is
 * printed before `tar` runs, so archive content can neither produce nor
 * suppress it; a copy further down fails to parse as a member line.
 */
const TAR_LISTING_MODE_LINE_PATTERN =
  /^paratix-tar-listing (?<flavor>bsd|gnu|other) (?<locale>C|C\.UTF-8|C\.utf8)$/v

/** Issue #219: the flavors a mode line may report. */
const TAR_LISTING_FLAVORS: readonly TarListingFlavor[] = ["bsd", "gnu", "other"]

/** Issue #219: the locales a mode line may report. */
const TAR_LISTING_LOCALES: readonly TarListingLocale[] = ["C.UTF-8", "C.utf8", "C"]

/** Issue #219: the longest part of an unexpected first line quoted in a refusal. */
const MODE_LINE_QUOTE_LIMIT = 200

/**
 * Issue #219: build the listing script for one archive.
 *
 * The script
 *
 * 1. reads the first line of `tar --version` to tell GNU tar
 *    (`tar (GNU tar) …`) and bsdtar (`bsdtar …`) from any other `tar`;
 * 2. picks `C.UTF-8`, then `C.utf8`, as `LC_ALL` when `locale charmap` reports
 *    `UTF-8` for it — glibc normalizes both spellings to the same locale, and
 *    a host whose `locale` binary is missing or lacks both locales falls back
 *    to `LC_ALL=C`. bsdtar always runs under `LC_ALL=C`: in a UTF-8 locale
 *    on macOS and FreeBSD it prints a byte raw whenever that byte alone is a
 *    printable Latin-1 character, even inside an escaped non-printable or
 *    invalid UTF-8 sequence, which makes the listing invalid UTF-8 for a name
 *    such as `a\u200Bb` that the C locale lists and decodes exactly;
 * 3. prints the mode line (see {@link splitTarListingModeLine});
 * 4. runs the listing under the chosen locale. GNU tar gets an explicit
 *    `--quoting-style=escape`, so a `TAR_OPTIONS` quoting style on the host
 *    cannot switch it to raw names the decoder would misread.
 *
 * The whole detection runs in the one listing exec, and the script exits
 * with the status of `tar`.
 *
 * @param flags - The `tar` list flags, for example `-tvzf`.
 * @param archivePath - The archive path on the remote host.
 * @returns The shell script that prints the mode line and the listing.
 */
export function tarListingScript(flags: string, archivePath: string): string {
  const archive = shellQuote(archivePath)
  return [
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
    `printf '%s %s %s\\n' ${TAR_LISTING_MODE_PREFIX} "$paratix_tar_flavor" "$paratix_tar_locale"`,
    'if [ "$paratix_tar_flavor" = gnu ]; then',
    `  LC_ALL=$paratix_tar_locale tar --quoting-style=escape ${flags} ${archive}`,
    "else",
    `  LC_ALL=$paratix_tar_locale tar ${flags} ${archive}`,
    "fi",
  ].join("\n")
}

/**
 * Issue #219: split the mode line off a listing produced by
 * {@link tarListingScript}.
 *
 * Only the first line is read as the mode line; it must match exactly.
 * Output without it is refused, because the decoding rules for the member
 * names would otherwise be a guess.
 *
 * @param stdout - The complete stdout of the listing script.
 * @returns The listing mode and the `tar` output after the mode line, or a
 *   failure reason.
 */
export function splitTarListingModeLine(
  stdout: string
): { body: string; mode: TarListingMode } | { failureReason: string } {
  const newline = stdout.indexOf("\n")
  const firstLine = newline === -1 ? stdout : stdout.slice(0, newline)
  const groups = TAR_LISTING_MODE_LINE_PATTERN.exec(firstLine)?.groups
  const flavor = TAR_LISTING_FLAVORS.find((candidate) => candidate === groups?.flavor)
  const locale = TAR_LISTING_LOCALES.find((candidate) => candidate === groups?.locale)
  if (flavor === undefined || locale === undefined) {
    return {
      failureReason: `tar listing does not start with the expected listing mode line: ${JSON.stringify(firstLine.slice(0, MODE_LINE_QUOTE_LIMIT))}`,
    }
  }
  return { body: newline === -1 ? "" : stdout.slice(newline + 1), mode: { flavor, locale } }
}

/**
 * Issue #219: whether member names of this listing are decoded with
 * {@link decodeTarListingName}. GNU tar (quoting style `escape`) and bsdtar
 * print every backslash in a name as `\\` and every byte they do not print
 * raw as a `\NNN` or single-letter escape, in any locale, so decoding is
 * exact for them. Any other `tar` keeps its names as listed.
 *
 * @param mode - The flavor and locale reported by the mode line.
 * @returns True when member names are decoded.
 */
export function tarListingDecodesNames(mode: TarListingMode): boolean {
  return mode.flavor !== "other"
}

/**
 * Issue #219: the single-letter escapes GNU tar (quoting style `escape`) and
 * bsdtar use, mapped to the characters they stand for. Control characters
 * decoded here are refused afterwards by the control-character guard of the
 * member validation.
 */
const TAR_LETTER_ESCAPES: ReadonlyMap<string, string> = new Map([
  ["\\", "\\"],
  ["a", "\u0007"],
  ["b", "\b"],
  ["f", "\f"],
  ["n", "\n"],
  ["r", "\r"],
  ["t", "\t"],
  ["v", "\v"],
])

/**
 * Issue #219: one escape sequence GNU tar or bsdtar produce: `\NNN` for one
 * byte in octal (`000`–`377`) or a single-letter escape. Splitting at it
 * scans left to right, so `\\303` is an escaped backslash before `303`.
 */
const TAR_ESCAPE_SPLIT_PATTERN = /(?<escape>\\(?:[0-3][0-7]{2}|[\\abfnrtv]))/v

/** Issue #219: the length of the longest escape sequence, `\NNN`. */
const TAR_LONGEST_ESCAPE_LENGTH = 4

/** Issue #219: the radix of a `\NNN` escape. */
const OCTAL_RADIX = 8

/**
 * Issue #219: the byte an escape sequence stands for.
 *
 * @param escape - An escape sequence matched by {@link TAR_ESCAPE_SPLIT_PATTERN}.
 * @returns The byte.
 */
function tarEscapeBytes(escape: string): Buffer {
  const body = escape.slice(1)
  const letter = TAR_LETTER_ESCAPES.get(body)
  return letter === undefined
    ? Buffer.of(Number.parseInt(body, OCTAL_RADIX))
    : Buffer.from(letter, "latin1")
}

/**
 * Issue #219: turn a listed name back into the bytes stored in the archive.
 *
 * @param listed - The name or link target as the listing printed it.
 * @returns The bytes, or why a backslash does not start a known escape.
 */
function tarListingNameBytes(listed: string): { failureReason: string } | Buffer {
  // `split` with a capturing group alternates text (even indexes) and escape
  // sequences (odd indexes).
  const parts = listed.split(TAR_ESCAPE_SPLIT_PATTERN)
  const stray = parts.find((part, index) => index % 2 === 0 && part.includes("\\"))
  if (stray !== undefined) {
    const at = stray.indexOf("\\")
    return {
      failureReason: `invalid escape sequence ${JSON.stringify(stray.slice(at, at + TAR_LONGEST_ESCAPE_LENGTH))}`,
    }
  }
  return Buffer.concat(
    parts.map((part, index) => (index % 2 === 0 ? Buffer.from(part, "utf8") : tarEscapeBytes(part)))
  )
}

/**
 * Issue #219: decode a member name or link target listed by GNU tar or
 * bsdtar back to the name stored in the archive.
 *
 * Characters outside escapes stand for their own UTF-8 bytes; `\\` is a
 * backslash, `\NNN` one byte in octal, and `\a`, `\b`, `\f`, `\n`, `\r`,
 * `\t`, `\v` the matching control byte. The bytes are then decoded as strict
 * UTF-8, so a name whose bytes are not valid UTF-8 — and any other escape
 * sequence — is refused instead of being mapped to a name that differs from
 * the one extracted.
 *
 * @param listed - The name or link target as the listing printed it.
 * @returns The decoded name, or why it cannot be mapped.
 */
export function decodeTarListingName(listed: string): { failureReason: string } | { name: string } {
  if (!listed.includes("\\")) return { name: listed }
  const bytes = tarListingNameBytes(listed)
  if (!Buffer.isBuffer(bytes)) return bytes
  try {
    return { name: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) }
  } catch {
    return { failureReason: "the decoded bytes are not valid UTF-8" }
  }
}
