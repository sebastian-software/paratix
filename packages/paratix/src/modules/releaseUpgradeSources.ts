// R-0000184: cap the wall-clock duration of every release-upgrade step at
// 30 minutes by default. Long-running upgrades (e.g. cross-version Ubuntu)
// can override this via the public `timeout` option, but unbounded runs
// are unsafe — the runner would otherwise hang indefinitely on a stuck
// `do-release-upgrade` or apt-get invocation.
const RELEASE_UPGRADE_DEFAULT_TIMEOUT_MINUTES = 30
const RELEASE_UPGRADE_SECONDS_PER_MINUTE = 60
const RELEASE_UPGRADE_MS_PER_SECOND = 1000
export const RELEASE_UPGRADE_DEFAULT_TIMEOUT_MS =
  RELEASE_UPGRADE_DEFAULT_TIMEOUT_MINUTES *
  RELEASE_UPGRADE_SECONDS_PER_MINUTE *
  RELEASE_UPGRADE_MS_PER_SECOND

const APT_SOURCES_LIST_DIRECTORY = "/etc/apt/sources.list.d/"
const ASCII_CONTROL_BOUNDARY = 0x20
const ASCII_DEL_CODE_POINT = 0x7f

/**
 * @param filePath - A path produced by `find -print0` over the apt sources
 *   directory.
 * @returns `true` when the path stays inside the expected directory and
 *   carries no ASCII control characters that would break downstream tooling.
 */
export function isAcceptableSourcesPath(filePath: string): boolean {
  if (!filePath.startsWith(APT_SOURCES_LIST_DIRECTORY)) return false
  for (let index = 0; index < filePath.length; index++) {
    const code = filePath.codePointAt(index)
    if (code === undefined) continue
    if (code < ASCII_CONTROL_BOUNDARY || code === ASCII_DEL_CODE_POINT) return false
  }
  return true
}

// R-0000240: a sources file enumerated by `find -print0` may vanish or
// become unreadable between enumeration and the subsequent `readFile`
// (operator cleanup, package removal, mount churn). Treat ENOENT-style
// errors as "skip this file" so a single transient absence does not abort
// the entire release upgrade. Other classes of errors (permission denied,
// SSH transport failure) are still re-thrown by callers.
//
// R-0000286: prefer `error.code === "ENOENT"` so non-English locales and
// SFTP/SSH provider variants are detected reliably. The string pattern
// remains as a fallback for transports that surface the condition only via
// the message text (e.g. localized `cat:` stderr).
const VANISHED_SOURCES_FILE_PATTERN =
  /no such file|enoent|cannot stat|cannot open|datei oder verzeichnis nicht gefunden|fichier ou r[ée]pertoire/iv

function getNodeErrorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined
  if (!("code" in error)) return undefined
  const { code } = error
  return typeof code === "string" ? code : undefined
}

/**
 * Detect the error shapes that indicate a sources file vanished between
 * enumeration and read.
 *
 * Prefers `error.code === "ENOENT"` as the structured signal — see
 * {@link wrapMissingSourcesFileError} for the helper that decorates a raw
 * SSH/SFTP failure with that code. Falls back to a localized message
 * pattern for transports that only surface the condition via stderr.
 *
 * @param error - The error value caught from `readFile`/`writeFile`.
 * @returns `true` when the error indicates ENOENT for the sources file.
 */
export function isVanishedSourcesFileError(error: unknown): boolean {
  if (getNodeErrorCode(error) === "ENOENT") return true
  const message = error instanceof Error ? error.message : String(error)
  return VANISHED_SOURCES_FILE_PATTERN.test(message)
}

/**
 * Decorate an arbitrary error with `code: "ENOENT"` when its rendered
 * message matches a known "missing file" shape. Lets callers attach the
 * structured error code that {@link isVanishedSourcesFileError} prefers,
 * without losing the original error stack or message. Errors that do not
 * look like a missing-file failure are returned as-is.
 *
 * Returns a wrapper Error rather than mutating the input so existing
 * stack/cause information stays intact and the caller does not have to
 * own the input lifetime.
 *
 * @param error - The raw error value caught from a sources-file read/write.
 * @returns The original error when the structured code is already present
 *   or the message does not match; otherwise a new Error carrying
 *   `code: "ENOENT"` and `cause: error`.
 */
export function wrapMissingSourcesFileError(error: unknown): unknown {
  if (!(error instanceof Error)) return error
  if (getNodeErrorCode(error) === "ENOENT") return error
  if (!VANISHED_SOURCES_FILE_PATTERN.test(error.message)) return error
  const wrapped: NodeJS.ErrnoException = new Error(error.message, { cause: error })
  wrapped.code = "ENOENT"
  return wrapped
}

// R-0000241: Default mode used when no original mode could be captured —
// matches the historical apt sources permission and the canonical
// distribution defaults shipped under `/etc/apt/`.
export const APT_SOURCES_DEFAULT_MODE = "0644"

const OCTAL_MODE_LENGTH_WITHOUT_LEADING_ZERO = 3

/**
 * Normalize a raw `stat -c '%a'` output to the four-digit octal form that
 * `ssh.writeFile`/`guardedWriteFile` expect.
 *
 * @param raw - Trimmed stdout from a `stat -c '%a'` invocation.
 * @returns The four-digit octal mode, or {@link APT_SOURCES_DEFAULT_MODE}
 *   when the input is empty.
 */
export function normalizeSourcesFileMode(raw: string): string {
  if (raw.length === 0) return APT_SOURCES_DEFAULT_MODE
  return raw.length === OCTAL_MODE_LENGTH_WITHOUT_LEADING_ZERO ? `0${raw}` : raw
}

type ReadSourcesFileModeSsh = {
  exec: (
    command: string,
    options: { ignoreExitCode: boolean; silent: boolean }
  ) => Promise<{ code: number; stdout: string }>
}

/**
 * Read the POSIX mode of `path` via `stat -c '%a'` and normalize the result
 * to the four-digit octal form `guardedWriteFile`/`writeFile` expect. Falls
 * back to {@link APT_SOURCES_DEFAULT_MODE} when stat fails (e.g. ENOENT
 * mid-flight).
 *
 * @param ssh - Active SSH connection (subset typed for testability).
 * @param path - The remote path to inspect.
 * @param shellQuote - Function quoting `path` for safe shell interpolation.
 * @returns The captured mode, or the apt default when stat fails.
 */
export async function readSourcesFileMode(
  ssh: ReadSourcesFileModeSsh,
  path: string,
  shellQuote: (value: string) => string
): Promise<string> {
  const result = await ssh.exec(`stat -c '%a' ${shellQuote(path)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return APT_SOURCES_DEFAULT_MODE
  return normalizeSourcesFileMode(result.stdout.trim())
}

const RELEASE_DERIVED_SUITE_SUFFIXES = ["-updates", "-security", "-backports"] as const
const DEBIAN_SUPPORTED_PREDECESSORS = {
  bookworm: "bullseye",
  bullseye: "buster",
  buster: "stretch",
  trixie: "bookworm",
} as const
const APT_LIST_SUITE_PATTERN =
  // eslint-disable-next-line security/detect-unsafe-regex -- Line-bounded apt source field parser; captures only the suite token.
  /^(?<prefix>[ \t]*(?:deb|deb-src)[ \t]+(?:\[[^\]\r\n]*\][ \t]+)?[^ \t\r\n]+[ \t]+)(?<suite>[^ \t\r\n]+)/gmv
const DEB822_SUITES_LINE_PATTERN = /^Suites:(?<suites>[^\r\n]*)$/gimv

function rewriteReleaseSuite(
  suite: string,
  currentCodename: string,
  targetCodename: string
): string {
  if (suite === currentCodename) return targetCodename
  for (const suffix of RELEASE_DERIVED_SUITE_SUFFIXES) {
    if (suite === `${currentCodename}${suffix}`) return `${targetCodename}${suffix}`
  }
  return suite
}

export function isSupportedDebianUpgradePath(
  currentCodename: string,
  targetCodename: string
): boolean {
  switch (targetCodename) {
    case "bookworm":
    case "bullseye":
    case "buster":
    case "trixie": {
      return DEBIAN_SUPPORTED_PREDECESSORS[targetCodename] === currentCodename
    }
    default: {
      return false
    }
  }
}

export function rewriteAptSourcesContent(parameters: {
  currentCodename: string
  originalContent: string
  remotePath: string
  targetCodename: string
}): string {
  const { currentCodename, originalContent, remotePath, targetCodename } = parameters
  const rewriteSuite = (suite: string): string =>
    rewriteReleaseSuite(suite, currentCodename, targetCodename)

  if (remotePath.endsWith(".sources")) {
    return originalContent.replaceAll(
      DEB822_SUITES_LINE_PATTERN,
      (_line, suites: string) => `Suites:${suites.replaceAll(/\S+/gv, rewriteSuite)}`
    )
  }

  return originalContent.replaceAll(
    APT_LIST_SUITE_PATTERN,
    (_line, prefix: string, suite: string) => `${prefix}${rewriteSuite(suite)}`
  )
}
