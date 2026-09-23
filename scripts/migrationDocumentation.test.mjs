import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { it } from "node:test"

const MIGRATION_PATH = "docs/user-guide/migration.md"
const PACKAGES = ["paratix", "create-paratix"]
const FIELDS = ["Before", "Now", "Upgrade"]
const UPGRADE_TEXT = "Set the new option."

function linesOf(markdown, path) {
  if (typeof markdown !== "string" || !markdown.trim()) {
    throw new Error(`${path}: document is empty`)
  }
  return markdown.replaceAll("\r\n", "\n").split("\n")
}

function isDigit(character) {
  return character >= "0" && character <= "9"
}

function isPrereleaseCharacter(character) {
  return (
    isDigit(character) ||
    (character >= "a" && character <= "z") ||
    (character >= "A" && character <= "Z") ||
    character === "-"
  )
}

function isVersion(value) {
  const dash = value.indexOf("-")
  const core = dash === -1 ? value : value.slice(0, dash)
  const prerelease = dash === -1 ? undefined : value.slice(dash + 1)
  const components = core.split(".")
  const validCore =
    components.length === 3 &&
    components.every(
      (part) => part.length > 0 && [...part].every((character) => isDigit(character))
    )
  const validPrerelease =
    prerelease === undefined ||
    prerelease
      .split(".")
      .every(
        (part) =>
          part.length > 0 && [...part].every((character) => isPrereleaseCharacter(character))
      )
  return validCore && validPrerelease
}

function releaseVersion(line, path, lineNumber) {
  const closing = line.indexOf("]", 4)
  const version = line.slice(4, closing)
  const suffix = line.slice(closing + 1)
  if (!line.startsWith("## [") || !isVersion(version) || (suffix && !suffix.startsWith("("))) {
    throw new Error(`${path}:${lineNumber}: malformed release version heading: ${line}`)
  }
  return version
}

function finishBreakingSection(state) {
  const parser = state
  if (parser.breakingLine !== undefined && !parser.breakingContent) {
    throw new Error(
      `${parser.path}:${parser.breakingLine}: ${parser.packageName} ${parser.version} has an empty BREAKING CHANGES section`
    )
  }
  parser.breakingLine = undefined
  parser.breakingContent = false
}

function startRelease(state, line, lineNumber) {
  finishBreakingSection(state)
  const version = releaseVersion(line, state.path, lineNumber)
  if (state.versions.has(version)) {
    throw new Error(`${state.path}:${lineNumber}: duplicate release version ${version}`)
  }
  const parser = state
  parser.version = version
  state.versions.add(version)
}

function startBreakingSection(state, line, lineNumber) {
  const validHeading = line === "### ⚠ BREAKING CHANGES" || line === "### BREAKING CHANGES"
  if (!state.version || !validHeading) {
    throw new Error(
      `${state.path}:${lineNumber}: visible BREAKING CHANGES must be a ### heading inside a release`
    )
  }
  finishBreakingSection(state)
  state.breaking.add(state.version)
  const parser = state
  parser.breakingLine = lineNumber
}

function consumeChangelogLine(state, line, lineNumber) {
  if (line.startsWith("##") && line[2] !== "#") return startRelease(state, line, lineNumber)
  if (line.toUpperCase().includes("BREAKING CHANGES")) {
    return startBreakingSection(state, line, lineNumber)
  }
  if (line.startsWith("### ")) return finishBreakingSection(state)
  if (state.breakingLine !== undefined && line.trim()) {
    const parser = state
    parser.breakingContent = true
  }
}

function breakingVersions(markdown, packageName) {
  const path = `packages/${packageName}/CHANGELOG.md`
  const lines = linesOf(markdown, path)
  if (lines[0].trim() !== "# Changelog") throw new Error(`${path}: expected # Changelog title`)
  const state = {
    breaking: new Set(),
    breakingContent: false,
    packageName,
    path,
    versions: new Set(),
  }
  for (const [index, line] of lines.entries()) consumeChangelogLine(state, line, index + 1)
  finishBreakingSection(state)
  if (state.versions.size === 0) throw new Error(`${path}: no release version headings found`)
  return state.breaking
}

function startPackage(state, line) {
  const name = line.startsWith("## `") && line.endsWith("`") ? line.slice(4, -1) : undefined
  const parser = state
  parser.packageName = PACKAGES.includes(name) ? name : undefined
  parser.currentEntry = undefined
}

function startMigrationEntry(state, line, lineNumber) {
  const parser = state
  parser.currentEntry = undefined
  if (!state.packageName) return
  const version = line.slice(4).split(":", 1)[0]
  if (!isVersion(version)) return
  const entry = { fields: new Map(), line: lineNumber }
  const candidates = state.entries.get(state.packageName)
  candidates.set(version, [...(candidates.get(version) ?? []), entry])
  parser.currentEntry = entry
}

function consumeEntryLine(entry, line) {
  const field = FIELDS.find((name) => line.startsWith(`**${name}:**`))
  if (field) {
    const candidate = entry
    if (entry.fields.has(field)) candidate.duplicateField = field
    entry.fields.set(field, line.slice(field.length + 5).trimStart())
    candidate.activeField = field
  } else if (entry.activeField) {
    entry.fields.set(entry.activeField, `${entry.fields.get(entry.activeField)}\n${line}`)
  }
}

function consumeMigrationLine(state, line, lineNumber) {
  if (line.startsWith("## ")) return startPackage(state, line)
  if (line.startsWith("### ")) return startMigrationEntry(state, line, lineNumber)
  if (state.currentEntry) consumeEntryLine(state.currentEntry, line)
}

function migrationEntries(markdown) {
  const lines = linesOf(markdown, MIGRATION_PATH)
  if (lines[0].trim() !== "# Migration Notes") {
    throw new Error(`${MIGRATION_PATH}: expected # Migration Notes title`)
  }
  const state = { entries: new Map(PACKAGES.map((name) => [name, new Map()])) }
  for (const [index, line] of lines.entries()) consumeMigrationLine(state, line, index + 1)
  return state.entries
}

function hasPlaceholder(content) {
  const lower = content.toLowerCase()
  return lower.includes("todo") || lower.includes("tbd") || lower.includes("coming soon")
}

function entryProblem(entry) {
  if (entry.duplicateField) return `duplicate ${entry.duplicateField} field`
  for (const name of FIELDS) {
    const content = entry.fields.get(name)?.trim()
    if (!content) return `missing or empty ${name} field`
    if (hasPlaceholder(content)) return `${name} field contains a placeholder`
  }
}

function verifyDocumentation(changelogs, migration) {
  const breaking = new Map(PACKAGES.map((name) => [name, breakingVersions(changelogs[name], name)]))
  const entries = migrationEntries(migration)
  for (const [packageName, versions] of breaking) {
    for (const version of versions) {
      const candidates = entries.get(packageName)?.get(version) ?? []
      if (candidates.length === 0) {
        throw new Error(
          `packages/${packageName}/CHANGELOG.md: ${packageName} ${version} BREAKING CHANGES requires an entry under ## \`${packageName}\` / ### ${version} in ${MIGRATION_PATH}`
        )
      }
      if (candidates.some((entry) => entryProblem(entry) === undefined)) continue
      const details = candidates
        .map((entry) => `line ${entry.line}: ${entryProblem(entry)}`)
        .join("; ")
      throw new Error(
        `${MIGRATION_PATH}: ${packageName} ${version} has no complete migration entry (${details})`
      )
    }
  }
  return breaking
}

const CHANGELOG = `# Changelog

## [1.2.3](https://example.test/compare) (2026-09-23)

### ⚠ BREAKING CHANGES

* The old behavior changed.
`
const NO_BREAKING = `# Changelog

## [1.2.3](https://example.test/compare) (2026-09-23)

### Features

* Add a new option.
`
const ENTRY = `### 1.2.3: changed behavior

**Before:** The old behavior applied.

**Now:** The new behavior applies.

**Upgrade:** ${UPGRADE_TEXT}
`

function guide(paratix = "", createParatix = "") {
  return `# Migration Notes

## \`paratix\`

${paratix}
## \`create-paratix\`

${createParatix}`
}

function changelogs(paratix = CHANGELOG, createParatix = NO_BREAKING) {
  return { "create-paratix": createParatix, paratix }
}

function expectFailure(changelogDocuments, migration, message) {
  assert.throws(() => verifyDocumentation(changelogDocuments, migration), message)
}

it("accepts a complete note for the matching package and version", () => {
  assert.deepEqual(
    [...(verifyDocumentation(changelogs(), guide(ENTRY)).get("paratix") ?? [])],
    ["1.2.3"]
  )
})

it("matches a documented prerelease to the same package and version", () => {
  const version = "1.2.3-beta.1"
  const prereleaseChangelog = CHANGELOG.replace("1.2.3", version)
  const prereleaseEntry = ENTRY.replace("1.2.3", version)
  const breaking = verifyDocumentation(changelogs(prereleaseChangelog), guide(prereleaseEntry))
  assert.deepEqual([...(breaking.get("paratix") ?? [])], [version])
})

it("does not require a note for a release without BREAKING CHANGES", () => {
  assert.doesNotThrow(() => verifyDocumentation(changelogs(NO_BREAKING), guide()))
})

it("rejects a missing note and notes for another package or version", () => {
  const wrongVersion = ENTRY.replace("1.2.3", "1.2.4")
  for (const migration of [guide(), guide("", ENTRY), guide(wrongVersion)]) {
    expectFailure(changelogs(), migration, /paratix 1\.2\.3.*requires an entry/v)
  }
})

it("rejects empty fields and obvious placeholders", () => {
  const invalidEntries = [
    ENTRY.replace(UPGRADE_TEXT, ""),
    ENTRY.replace("The old behavior applied.", "TODO"),
    ENTRY.replace("The new behavior applies.", "TBD"),
    ENTRY.replace(UPGRADE_TEXT, "coming soon"),
  ]
  for (const entry of invalidEntries) {
    expectFailure(changelogs(), guide(entry), /no complete migration entry/v)
  }
})

it("accepts one complete entry among several for the same version", () => {
  const incomplete = ENTRY.replace(UPGRADE_TEXT, "TODO")
  assert.doesNotThrow(() => verifyDocumentation(changelogs(), guide(`${incomplete}\n${ENTRY}`)))
})

it("rejects malformed or empty document structure", () => {
  expectFailure(changelogs(""), guide(ENTRY), /document is empty/v)
  expectFailure(changelogs("# Changelog\n"), guide(ENTRY), /no release version headings/v)
  expectFailure(changelogs(), "", /document is empty/v)
  expectFailure(changelogs(), guide().replace("## `paratix`", "## paratix"), /requires an entry/v)
  expectFailure(changelogs(), guide(ENTRY.replace("### 1.2.3:", "## 1.2.3:")), /requires an entry/v)
  expectFailure(
    changelogs(CHANGELOG.replace("## [1.2.3]", "## 1.2.3")),
    guide(ENTRY),
    /malformed release version heading/v
  )
  const malformedNextRelease = `${CHANGELOG}\n##[1.2.4]\n\n### ⚠ BREAKING CHANGES\n\n* Another change.\n`
  expectFailure(
    changelogs(malformedNextRelease),
    guide(ENTRY),
    /malformed release version heading/v
  )
})

it("rejects a visible malformed or empty BREAKING CHANGES section", () => {
  const malformed = CHANGELOG.replace("### ⚠ BREAKING CHANGES", "* BREAKING CHANGES")
  const empty = CHANGELOG.replace("* The old behavior changed.", "")
  expectFailure(changelogs(malformed), guide(ENTRY), /must be a ### heading/v)
  expectFailure(changelogs(empty), guide(ENTRY), /empty BREAKING CHANGES section/v)
})

it("checks the real paratix 0.18.0 release and migration note", () => {
  const realChangelogs = {
    "create-paratix": readFileSync("packages/create-paratix/CHANGELOG.md", "utf8"),
    paratix: readFileSync("packages/paratix/CHANGELOG.md", "utf8"),
  }
  const realMigration = readFileSync("docs/user-guide/migration.md", "utf8")
  const breaking = verifyDocumentation(realChangelogs, realMigration)
  assert.ok(
    breaking.get("paratix")?.has("0.18.0"),
    "expected the real 0.18.0 BREAKING CHANGES section"
  )
})
