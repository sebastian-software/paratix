/* eslint-disable security/detect-non-literal-fs-filename -- Fixtures only write inside their own temporary directory. */
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { afterEach, describe, it } from "node:test"

import {
  decideRustCheck,
  EXPECTED_CARGO_DENY_VERSION,
  isRustInputPath,
  readGitState,
  runRustCheck,
  RUST_CHECK_STEPS,
} from "./rustCheck.mjs"

const MERGE_BASE = "0123456789abcdef0123456789abcdef01234567"
const CARGO_TOML = "packages/ssh-native/Cargo.toml"
const README = "packages/ssh-native/README.md"
const SOURCE_FILE = "packages/ssh-native/src/lib.rs"
const NO_CHANGES_REASON = `no Rust changes under packages/ssh-native since merge-base ${MERGE_BASE} (PARATIX_RUST_CHECK=auto)`
const temporaryDirectories = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { force: true, recursive: true })
  }
})

function gitStateWith(changedPaths) {
  return () => ({ changedPaths, mergeBase: MERGE_BASE })
}

function unexpectedGitRead() {
  throw new Error("git state must not be read")
}

function missingBaseState() {
  return { mergeBase: undefined, unavailableReason: "origin/main is not resolvable" }
}

describe("decideRustCheck", () => {
  it("lets PARATIX_RUST_CHECK=skip take precedence over CI=true", () => {
    assert.deepEqual(
      decideRustCheck({
        environment: { CI: "true", PARATIX_RUST_CHECK: "skip" },
        readGitState: unexpectedGitRead,
      }),
      { reason: "PARATIX_RUST_CHECK=skip", run: false }
    )
  })

  it("runs PARATIX_RUST_CHECK=always without CI and without reading Git state", () => {
    assert.deepEqual(
      decideRustCheck({
        environment: { PARATIX_RUST_CHECK: "always" },
        readGitState: unexpectedGitRead,
      }),
      { reason: "PARATIX_RUST_CHECK=always", run: true }
    )
  })

  it("aborts on an unknown PARATIX_RUST_CHECK value even with CI=true", () => {
    const error = errorFrom(decideRustCheck, {
      environment: { CI: "true", PARATIX_RUST_CHECK: "Always" },
      readGitState: unexpectedGitRead,
    })
    assert.equal(
      error.message,
      'Unsupported PARATIX_RUST_CHECK value "Always". Expected one of: always, skip, auto.'
    )
  })

  it("runs the default auto mode in CI without reading Git state", () => {
    assert.deepEqual(
      decideRustCheck({ environment: { CI: "true" }, readGitState: unexpectedGitRead }),
      { reason: "CI=true (default auto)", run: true }
    )
  })

  it("treats an empty PARATIX_RUST_CHECK as the default auto mode", () => {
    assert.deepEqual(
      decideRustCheck({
        environment: { PARATIX_RUST_CHECK: "" },
        readGitState: gitStateWith([]),
      }),
      { reason: NO_CHANGES_REASON, run: false }
    )
  })

  it("skips auto mode when nothing changed since the merge-base", () => {
    assert.deepEqual(decideRustCheck({ environment: {}, readGitState: gitStateWith([]) }), {
      reason: NO_CHANGES_REASON,
      run: false,
    })
  })

  it("runs auto mode when a Rust input changed since the merge-base", () => {
    assert.deepEqual(
      decideRustCheck({
        environment: { PARATIX_RUST_CHECK: "auto" },
        readGitState: gitStateWith([SOURCE_FILE, CARGO_TOML, SOURCE_FILE]),
      }),
      {
        reason: `Rust inputs changed since merge-base ${MERGE_BASE}: ${CARGO_TOML}, ${SOURCE_FILE} (PARATIX_RUST_CHECK=auto)`,
        run: true,
      }
    )
  })

  it("does not run auto mode for non-Rust changes under packages/ssh-native", () => {
    assert.deepEqual(
      decideRustCheck({
        environment: {},
        readGitState: gitStateWith([
          README,
          "packages/ssh-native/index.js",
          "packages/ssh-native/npm/linux-x64-gnu/package.json",
        ]),
      }),
      { reason: NO_CHANGES_REASON, run: false }
    )
  })

  it("runs auto mode when origin/main is not resolvable", () => {
    assert.deepEqual(decideRustCheck({ environment: {}, readGitState: missingBaseState }), {
      reason: "origin/main is not resolvable (PARATIX_RUST_CHECK=auto)",
      run: true,
    })
  })
})

function pathsClassifiedAs(paths, isInput) {
  return paths.filter((path) => isRustInputPath(path) === isInput)
}

describe("isRustInputPath", () => {
  it("accepts the Rust inputs of packages/ssh-native only", () => {
    const inputs = [
      SOURCE_FILE,
      "packages/ssh-native/src/nested/module.rs",
      "packages/ssh-native/build.rs",
      CARGO_TOML,
      "packages/ssh-native/Cargo.lock",
      "packages/ssh-native/rust-toolchain.toml",
      "packages/ssh-native/deny.toml",
    ]
    const nonInputs = [
      README,
      "packages/ssh-native/test/binding.test.mjs",
      "packages/ssh-native/target/release/build.rs",
      "packages/ssh-native/npm/darwin-arm64/package.json",
      "packages/paratix/src/ssh.ts",
      "packages/ssh-native-other/src/lib.rs",
      "Cargo.toml",
    ]
    assert.deepEqual(pathsClassifiedAs(inputs, false), [])
    assert.deepEqual(pathsClassifiedAs(nonInputs, true), [])
  })
})

function git(directory, ...gitArguments) {
  return execFileSync("git", gitArguments, {
    cwd: directory,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "test@example.invalid",
      GIT_AUTHOR_NAME: "Test",
      GIT_COMMITTER_EMAIL: "test@example.invalid",
      GIT_COMMITTER_NAME: "Test",
    },
    stdio: ["ignore", "pipe", "pipe"],
  })
}

function writeRepositoryFile(root, path, content) {
  const absolutePath = join(root, path)
  mkdirSync(dirname(absolutePath), { recursive: true })
  writeFileSync(absolutePath, content)
}

function fixtureRepository({ withBase = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), "rust-check-"))
  temporaryDirectories.push(root)
  git(root, "init", "--quiet", "--initial-branch=main")
  writeRepositoryFile(root, SOURCE_FILE, "pub fn base() {}\n")
  writeRepositoryFile(root, README, "# ssh-native\n")
  git(root, "add", "--all")
  git(root, "commit", "--quiet", "--message", "base")
  if (withBase) git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
  const execGit = (gitArguments) => git(root, ...gitArguments)
  return { execGit, root }
}

function changedPathsOf(execGit) {
  return readGitState(execGit).changedPaths ?? []
}

function decideFor(execGit) {
  return decideRustCheck({ environment: {}, readGitState: () => readGitState(execGit) })
}

describe("readGitState against a temporary Git repository", () => {
  it("reports no Rust changes when the tree matches the merge-base", () => {
    const { execGit } = fixtureRepository()
    const decision = decideFor(execGit)
    assert.equal(decision.run, false)
    assert.match(decision.reason, /^no Rust changes under packages\/ssh-native since merge-base/v)
  })

  it("detects an untracked Rust source file", () => {
    const { execGit, root } = fixtureRepository()
    writeRepositoryFile(root, "packages/ssh-native/src/new.rs", "pub fn added() {}\n")
    assert.deepEqual(changedPathsOf(execGit), ["packages/ssh-native/src/new.rs"])
    assert.equal(decideFor(execGit).run, true)
  })

  it("detects committed and unstaged Rust changes since the merge-base", () => {
    const { execGit, root } = fixtureRepository()
    writeRepositoryFile(root, CARGO_TOML, '[package]\nname = "fixture"\n')
    git(root, "add", CARGO_TOML)
    git(root, "commit", "--quiet", "--message", "manifest")
    writeRepositoryFile(root, SOURCE_FILE, "pub fn changed() {}\n")
    assert.deepEqual(changedPathsOf(execGit).toSorted(), [CARGO_TOML, SOURCE_FILE])
    assert.equal(decideFor(execGit).run, true)
  })

  it("ignores a README change under packages/ssh-native", () => {
    const { execGit, root } = fixtureRepository()
    writeRepositoryFile(root, README, "# ssh-native\n\nUpdated.\n")
    assert.deepEqual(changedPathsOf(execGit), [README])
    assert.equal(decideFor(execGit).run, false)
  })

  it("runs when origin/main does not exist", () => {
    const { execGit } = fixtureRepository({ withBase: false })
    assert.deepEqual(decideFor(execGit), {
      reason: "origin/main is not resolvable (PARATIX_RUST_CHECK=auto)",
      run: true,
    })
  })
})

function fakeRunCommand({ denyVersion = EXPECTED_CARGO_DENY_VERSION, failingStep = "" } = {}) {
  const calls = []
  const runCommand = (command, commandArguments, options) => {
    calls.push({ arguments: commandArguments, command, cwd: options.cwd })
    if (commandArguments.join(" ") === "deny --version") {
      return { signal: null, status: 0, stdout: `cargo-deny ${denyVersion}\n` }
    }
    const failing = failingStep !== "" && commandArguments[0] === failingStep
    return { signal: null, status: failing ? 1 : 0 }
  }
  return { calls, runCommand }
}

function failingDenyRunCommand() {
  const calls = []
  const runCommand = (command, commandArguments) => {
    calls.push(commandArguments)
    return { signal: null, status: 101, stdout: "" }
  }
  return { calls, runCommand }
}

function ignoreLog() {}

function createLogCollector() {
  const logs = []
  return {
    log(line) {
      logs.push(line)
    },
    logs,
  }
}

function errorFrom(callable, options) {
  try {
    callable(options)
  } catch (error) {
    return error
  }
  return assert.fail("Expected a thrown error.")
}

function commandLines(calls) {
  return calls.map((call) => [call.command, ...call.arguments].join(" "))
}

function workingDirectories(calls) {
  return [...new Set(calls.map((call) => call.cwd))]
}

function ranSubcommand(calls, subcommand) {
  return calls.some((call) => call.arguments[0] === subcommand)
}

function hasLogContaining(logs, fragment) {
  return logs.some((line) => line.includes(fragment))
}

function stepNames() {
  return RUST_CHECK_STEPS.map((step) => step.name)
}

function pinnedCargoDenyVersions(workflow) {
  return [...workflow.matchAll(/CARGO_DENY_VERSION: "(?<version>[^"]+)"/gv)].map(
    (match) => match.groups?.version
  )
}

const ALWAYS_ENVIRONMENT = { PARATIX_RUST_CHECK: "always" }

describe("runRustCheck", () => {
  it("logs the skip reason and runs no command for PARATIX_RUST_CHECK=skip", () => {
    const { calls, runCommand } = fakeRunCommand()
    const { log, logs } = createLogCollector()
    runRustCheck({
      environment: { CI: "true", PARATIX_RUST_CHECK: "skip" },
      execGit: unexpectedGitRead,
      log,
      runCommand,
    })
    assert.deepEqual(logs, ["rust:check skipped: PARATIX_RUST_CHECK=skip"])
    assert.deepEqual(calls, [])
  })

  it("runs fmt, clippy, test and deny in packages/ssh-native", () => {
    const { calls, runCommand } = fakeRunCommand()
    runRustCheck({
      environment: ALWAYS_ENVIRONMENT,
      log: ignoreLog,
      repositoryRoot: "/repository",
      runCommand,
    })
    assert.deepEqual(commandLines(calls), [
      "cargo deny --version",
      "cargo fmt --check",
      "cargo clippy --locked --all-targets -- -D warnings",
      "cargo test --locked",
      "cargo deny --locked check licenses bans sources",
    ])
    assert.deepEqual(workingDirectories(calls), ["/repository/packages/ssh-native"])
  })

  it("stops at the first failing step and names it", () => {
    const { calls, runCommand } = fakeRunCommand({ failingStep: "clippy" })
    const error = errorFrom(runRustCheck, {
      environment: ALWAYS_ENVIRONMENT,
      log: ignoreLog,
      runCommand,
    })
    assert.equal(error.message, "cargo clippy failed (exit code 1).")
    assert.equal(ranSubcommand(calls, "test"), false)
  })

  it("aborts before the checks when cargo-deny is missing", () => {
    const { calls, runCommand } = failingDenyRunCommand()
    const error = errorFrom(runRustCheck, {
      environment: ALWAYS_ENVIRONMENT,
      log: ignoreLog,
      runCommand,
    })
    assert.match(error.message, /cargo install --locked cargo-deny@0\.20\.2/v)
    assert.equal(calls.length, 1)
  })

  it("warns about a different cargo-deny version", () => {
    const { runCommand } = fakeRunCommand({ denyVersion: "0.99.0" })
    const { log, logs } = createLogCollector()
    runRustCheck({ environment: ALWAYS_ENVIRONMENT, log, runCommand })
    assert.equal(hasLogContaining(logs, "cargo-deny 0.99.0 found, CI uses 0.20.2"), true)
  })

  it("keeps the step list in the documented order", () => {
    assert.deepEqual(stepNames(), ["cargo fmt", "cargo clippy", "cargo test", "cargo deny"])
  })
})

describe("CI pins", () => {
  it("installs the cargo-deny version that rust:check expects", () => {
    const workflow = readFileSync(
      join(import.meta.dirname, "..", ".github", "workflows", "ci.yml"),
      "utf8"
    )
    assert.deepEqual(pinnedCargoDenyVersions(workflow), [EXPECTED_CARGO_DENY_VERSION])
  })
})
