/* eslint-disable security/detect-non-literal-fs-filename -- Fixtures only write inside their own temporary directory. */
import assert from "node:assert/strict"
import { execFileSync, spawnSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { afterEach, test } from "node:test"

import { checkImporter, checkWorkspace } from "./checkVitestCompatibility.mjs"

const temporaryDirectories = []
const manifestFilename = "package.json"
const modulesDirectory = "node_modules"
const vitestVersionFixed = "4.1.11"
const vitestLink = "node_modules/vitest"
const paratixImporter = "packages/paratix"
const coverageName = "@vitest/coverage-v8"
const script = join(import.meta.dirname, "checkVitestCompatibility.mjs")

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true })
  }
})

function json(path, value) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(value))
}

function fixtureWorkspace() {
  const root = mkdtempSync(join(tmpdir(), "vitest-compatibility-"))
  temporaryDirectories.push(root)
  json(join(root, manifestFilename), {
    name: "fixture",
    packageManager: "pnpm@12.11.2",
    private: true,
  })
  writeFileSync(join(root, "pnpm-workspace.yaml"), 'packages:\n  - "packages/*"\n  - "website"\n')
  return root
}

function fixture(
  vitestVersion = vitestVersionFixed,
  coverageVersion = /** @type {string | null} */ (vitestVersion),
  importer = "."
) {
  const root = fixtureWorkspace()
  const directory = join(root, importer)
  const dependencies = { vitest: vitestVersion }
  if (coverageVersion !== null) dependencies[coverageName] = coverageVersion
  json(join(directory, manifestFilename), {
    devDependencies: dependencies,
    name: "fixture-importer",
    packageManager: "pnpm@12.11.2",
    private: true,
  })
  const vitest = join(root, "node_modules/.pnpm", `vitest@${vitestVersion}`, vitestLink)
  const coverage = join(
    root,
    "node_modules/.pnpm",
    `coverage@${coverageVersion}`,
    modulesDirectory,
    coverageName
  )
  json(join(vitest, manifestFilename), {
    name: "vitest",
    peerDependencies: { [coverageName]: vitestVersion },
    peerDependenciesMeta: { [coverageName]: { optional: true } },
    version: vitestVersion,
  })
  link(vitest, join(directory, vitestLink))
  if (coverageVersion !== null) {
    json(join(coverage, manifestFilename), {
      name: coverageName,
      peerDependencies: { vitest: coverageVersion },
      version: coverageVersion,
    })
    link(coverage, join(directory, modulesDirectory, coverageName))
    link(coverage, join(dirname(vitest), coverageName))
    link(vitest, join(dirname(dirname(coverage)), "vitest"))
  }
  return { coverage, directory, root, vitest }
}

function link(target, path) {
  mkdirSync(dirname(path), { recursive: true })
  symlinkSync(target, path, "dir")
}

for (const importer of [".", paratixImporter, "packages/create-paratix", "website"]) {
  test(`rejects resolved 4.1.11/4.1.10 in ${importer}, despite compatible manifest ranges`, () => {
    const { directory } = fixture(vitestVersionFixed, "4.1.10", importer)
    json(join(directory, manifestFilename), {
      devDependencies: { [coverageName]: "^4.1.10", vitest: "^4.1.10" },
    })
    assert.throws(() => checkImporter(directory), /requires .*4\.1\..*, resolved 4\.1\./v)
  })
}

test("accepts resolved 4.1.11/4.1.11", () => {
  assert.equal(checkImporter(fixture().directory), 2)
})

test("allows an optional companion that is not installed", () => {
  assert.equal(checkImporter(fixture(vitestVersionFixed, null).directory), 1)
})

test("does not require equality for the independently versioned ESLint plugin", () => {
  const { directory } = fixture()
  json(join(directory, manifestFilename), {
    devDependencies: {
      "@vitest/eslint-plugin": "1.6.24",
      [coverageName]: vitestVersionFixed,
      vitest: vitestVersionFixed,
    },
  })
  json(join(directory, "node_modules/@vitest/eslint-plugin/package.json"), {
    name: "@vitest/eslint-plugin",
    peerDependencies: { vitest: "*" },
    version: "1.6.24",
  })
  assert.equal(checkImporter(directory), 2)
})

test("checks compatible peer ranges without imposing version equality", () => {
  const { coverage, directory, vitest } = fixture("5.0.4", "5.0.3")
  json(join(vitest, manifestFilename), {
    name: "vitest",
    peerDependencies: { [coverageName]: "^5.0.0" },
    version: "5.0.4",
  })
  json(join(coverage, manifestFilename), {
    name: coverageName,
    peerDependencies: { vitest: "^5.0.0-beta.5 || >=5.0.0" },
    version: "5.0.3",
  })
  assert.equal(checkImporter(directory), 2)
})

test("keeps different compatible importer contexts independent", () => {
  const first = fixture("4.1.10", "4.1.10", paratixImporter)
  const second = fixture(vitestVersionFixed, vitestVersionFixed, "packages/create-paratix")
  assert.equal(checkImporter(first.directory), 2)
  assert.equal(checkImporter(second.directory), 2)
})

test("rejects missing declared links even when a parent can resolve the package", () => {
  const { directory, root, vitest } = fixture(vitestVersionFixed, null, paratixImporter)
  rmSync(join(directory, vitestLink))
  link(vitest, join(root, vitestLink))
  assert.throws(() => checkImporter(directory), /Cannot read declared vitest/v)
})

test("rejects missing and ambiguous in-scope metadata", () => {
  const { coverage, directory } = fixture()
  json(join(coverage, manifestFilename), { name: coverageName, version: vitestVersionFixed })
  assert.throws(() => checkImporter(directory), /Missing Vitest peer metadata/v)
  json(join(directory, manifestFilename), {
    dependencies: { vitest: vitestVersionFixed },
    devDependencies: { vitest: vitestVersionFixed },
  })
  assert.throws(() => checkImporter(directory), /Ambiguous vitest/v)
})

test("does not treat filesystem failures as an absent optional peer", () => {
  const { directory, vitest } = fixture(vitestVersionFixed, null)
  mkdirSync(join(dirname(vitest), coverageName, manifestFilename), { recursive: true })
  assert.throws(() => checkImporter(directory), /EISDIR/v)
})

test("fails incomplete security PR installed state, then accepts a same-PR paired repair", () => {
  const { coverage, directory } = fixture(vitestVersionFixed, "4.1.10")
  assert.throws(() => checkImporter(directory), /requires/v)
  // Simulates the resulting installed files after companion + lockfile repair and frozen install.
  json(join(directory, manifestFilename), {
    devDependencies: { [coverageName]: vitestVersionFixed, vitest: vitestVersionFixed },
  })
  json(join(coverage, manifestFilename), {
    name: coverageName,
    peerDependencies: { vitest: vitestVersionFixed },
    version: vitestVersionFixed,
  })
  assert.equal(checkImporter(directory), 2)
})

test("rejects unsupported package managers before discovering importers", () => {
  const { root } = fixture()
  json(join(root, manifestFilename), { packageManager: "pnpm@10.0.0" })
  assert.throws(() => checkWorkspace(root), /pnpm@12/v)
})

test("CLI discovers all workspace importers and returns failure then success", () => {
  const { coverage, root } = fixture(vitestVersionFixed, "4.1.10", paratixImporter)
  // Retain pnpm 12's separate package-manager document to avoid bootstrap downloads.
  const managerLock = readFileSync(join(import.meta.dirname, "../pnpm-lock.yaml"), "utf8").split(
    "\n---\n"
  )[0]
  writeFileSync(
    join(root, "pnpm-lock.yaml"),
    `${managerLock}\n---\nlockfileVersion: '9.0'\nimporters:\n  .: {}\n`
  )
  const failed = spawnSync(process.execPath, [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, npm_config_manage_package_manager_versions: "false" },
  })
  assert.equal(failed.status, 1, failed.stderr)
  assert.match(failed.stderr, /packages\/paratix: .*requires/v)
  json(join(coverage, manifestFilename), {
    name: coverageName,
    peerDependencies: { vitest: vitestVersionFixed },
    version: vitestVersionFixed,
  })
  const stdout = execFileSync(process.execPath, [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, npm_config_manage_package_manager_versions: "false" },
  })
  assert.match(stdout, /checked 2 installed package contexts/v)
})
