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
