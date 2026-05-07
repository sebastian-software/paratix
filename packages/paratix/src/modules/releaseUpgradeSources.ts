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
