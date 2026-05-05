import { readFileSync } from "node:fs"

type PackageJsonWithVersion = {
  version: string
}

const SEMVER_CORE_IDENTIFIER_COUNT = 3

function isDigit(value: string): boolean {
  return value >= "0" && value <= "9"
}

function isIdentifierCharacter(value: string): boolean {
  return (value >= "a" && value <= "z") || (value >= "A" && value <= "Z") || isDigit(value)
}

function isNumericIdentifier(value: string): boolean {
  if (value === "") return false
  for (const character of value) {
    if (!isDigit(character)) return false
  }

  return value === "0" || !value.startsWith("0")
}

function isValidLabel(value: string): boolean {
  if (value === "") return false

  for (const character of value) {
    if (character !== "-" && !isIdentifierCharacter(character)) return false
  }

  return true
}

function isValidPrereleaseLabel(value: string): boolean {
  if (!isValidLabel(value)) return false

  for (const character of value) {
    if (!isDigit(character)) return true
  }

  return isNumericIdentifier(value)
}

function splitSemverSuffix(version: string, separator: "-" | "+"): [string, string | undefined] {
  const firstIndex = version.indexOf(separator)
  if (firstIndex === -1) return [version, undefined]
  if (separator === "+" && version.includes(separator, firstIndex + 1)) {
    return [version, ""]
  }

  return [version.slice(0, firstIndex), version.slice(firstIndex + 1)]
}

function areDotSeparatedLabelsValid(
  value: string | undefined,
  validateLabel: (label: string) => boolean
): boolean {
  if (value === undefined) return true

  return value.split(".").every((label) => validateLabel(label))
}

function isValidSemverVersion(version: string): boolean {
  const [withoutBuild, build] = splitSemverSuffix(version, "+")
  const [coreVersion, prerelease] = splitSemverSuffix(withoutBuild, "-")
  const coreIdentifiers = coreVersion.split(".")

  return (
    coreIdentifiers.length === SEMVER_CORE_IDENTIFIER_COUNT &&
    coreIdentifiers.every((identifier) => isNumericIdentifier(identifier)) &&
    areDotSeparatedLabelsValid(prerelease, isValidPrereleaseLabel) &&
    areDotSeparatedLabelsValid(build, isValidLabel)
  )
}

function isPackageJsonWithVersion(value: unknown): value is PackageJsonWithVersion {
  return (
    typeof value === "object" &&
    value !== null &&
    "version" in value &&
    typeof value.version === "string" &&
    isValidSemverVersion(value.version)
  )
}

function readCreateParatixPackageVersion(): string {
  const packageJsonUrl = new URL("../package.json", import.meta.url)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const packageJson: unknown = JSON.parse(readFileSync(packageJsonUrl, "utf8"))

  if (!isPackageJsonWithVersion(packageJson)) {
    throw new Error("create-paratix package.json must contain a valid semver version.")
  }

  return packageJson.version
}

export function deriveParatixDependencyRange(): string {
  return `^${readCreateParatixPackageVersion()}`
}
