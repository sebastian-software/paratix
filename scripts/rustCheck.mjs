import { execFileSync, spawnSync } from "node:child_process"
import { dirname, join, resolve } from "node:path"
import { pathToFileURL } from "node:url"

// Rust checks for packages/ssh-native (#255). `PARATIX_RUST_CHECK` selects
// whether they run: `always`, `skip` or `auto` (the default). An explicit
// `always`/`skip` beats `CI=true`; any other value aborts so a typo never
// silently disables the checks. `auto` runs in CI, when `origin/main` cannot
// be resolved, or when a Rust input changed since the merge-base with
// `origin/main` (committed, staged, unstaged or untracked).

const REPOSITORY_ROOT = dirname(import.meta.dirname)
export const RUST_CHECK_ENVIRONMENT_VARIABLE = "PARATIX_RUST_CHECK"
export const RUST_CHECK_MODES = ["always", "skip", "auto"]
export const RUST_PACKAGE_DIRECTORY = "packages/ssh-native"
export const BASE_REFERENCE = "origin/main"
// Keep in sync with CARGO_DENY_VERSION in .github/workflows/ci.yml; a test
// asserts that both values match.
export const EXPECTED_CARGO_DENY_VERSION = "0.20.2"

const RUST_INPUT_FILES = new Set([
  "build.rs",
  "Cargo.lock",
  "Cargo.toml",
  "deny.toml",
  "rust-toolchain.toml",
])
const RUST_INPUT_SOURCE_DIRECTORY = "src/"
const LOG_PREFIX = "rust:check"

export const RUST_CHECK_STEPS = [
  { arguments: ["fmt", "--check"], name: "cargo fmt" },
  {
    arguments: ["clippy", "--locked", "--all-targets", "--", "-D", "warnings"],
    name: "cargo clippy",
  },
  { arguments: ["test", "--locked"], name: "cargo test" },
  {
    arguments: ["deny", "--locked", "check", "licenses", "bans", "sources"],
    name: "cargo deny",
  },
]

export class RustCheckError extends Error {
  name = "RustCheckError"
}

export function resolveRustCheckMode(environment) {
  const value = environment[RUST_CHECK_ENVIRONMENT_VARIABLE]
  if (value === undefined || value === "") return { explicit: false, mode: "auto" }
  if (RUST_CHECK_MODES.includes(value)) return { explicit: true, mode: value }
  throw new RustCheckError(
    `Unsupported ${RUST_CHECK_ENVIRONMENT_VARIABLE} value ${JSON.stringify(value)}. ` +
      `Expected one of: ${RUST_CHECK_MODES.join(", ")}.`
  )
}

// Paths are repository-relative with forward slashes, as printed by git.
export function isRustInputPath(path) {
  const prefix = `${RUST_PACKAGE_DIRECTORY}/`
  if (!path.startsWith(prefix)) return false
  const packagePath = path.slice(prefix.length)
  return packagePath.startsWith(RUST_INPUT_SOURCE_DIRECTORY) || RUST_INPUT_FILES.has(packagePath)
}

function environmentVariableReason(mode) {
  return `${RUST_CHECK_ENVIRONMENT_VARIABLE}=${mode}`
}

function decideFromGitState(gitState) {
  const autoReason = environmentVariableReason("auto")
  if (gitState.mergeBase === undefined) {
    return { reason: `${gitState.unavailableReason} (${autoReason})`, run: true }
  }
  const changedInputs = [
    ...new Set(gitState.changedPaths.filter((path) => isRustInputPath(path))),
  ].toSorted()
  if (changedInputs.length === 0) {
    return {
      reason: `no Rust changes under ${RUST_PACKAGE_DIRECTORY} since merge-base ${gitState.mergeBase} (${autoReason})`,
      run: false,
    }
  }
  return {
    reason: `Rust inputs changed since merge-base ${gitState.mergeBase}: ${changedInputs.join(", ")} (${autoReason})`,
    run: true,
  }
}

// Pure decision: `readGitState` is only called for `auto` outside CI and
// returns either `{ mergeBase, changedPaths }` or
// `{ mergeBase: undefined, unavailableReason }`.
export function decideRustCheck({ environment, readGitState }) {
  const { explicit, mode } = resolveRustCheckMode(environment)
  if (mode === "skip") return { reason: environmentVariableReason(mode), run: false }
  if (mode === "always") return { reason: environmentVariableReason(mode), run: true }
  if (environment.CI === "true") {
    const source = explicit ? environmentVariableReason(mode) : "default auto"
    return { reason: `CI=true (${source})`, run: true }
  }
  return decideFromGitState(readGitState())
}

function nullSeparated(stdout) {
  return stdout.split("\0").filter((entry) => entry !== "")
}

// `execGit(arguments)` returns stdout and throws on a non-zero exit.
export function readGitState(execGit) {
  try {
    execGit(["rev-parse", "--verify", "--quiet", `${BASE_REFERENCE}^{commit}`])
  } catch {
    return { mergeBase: undefined, unavailableReason: `${BASE_REFERENCE} is not resolvable` }
  }
  let mergeBase
  try {
    mergeBase = execGit(["merge-base", "HEAD", BASE_REFERENCE]).trim()
  } catch {
    return {
      mergeBase: undefined,
      unavailableReason: `no merge-base between HEAD and ${BASE_REFERENCE}`,
    }
  }
  // `git diff <commit>` compares the merge-base with the working tree, which
  // covers committed, staged and unstaged changes; `--no-renames` reports
  // both sides of a rename.
  const trackedChanges = execGit([
    "diff",
    "--name-only",
    "--no-renames",
    "-z",
    mergeBase,
    "--",
    RUST_PACKAGE_DIRECTORY,
  ])
  const untrackedFiles = execGit([
    "ls-files",
    "--others",
    "--exclude-standard",
    "-z",
    "--",
    RUST_PACKAGE_DIRECTORY,
  ])
  return {
    changedPaths: [...nullSeparated(trackedChanges), ...nullSeparated(untrackedFiles)],
    mergeBase,
  }
}

function defaultExecGit(gitArguments) {
  return execFileSync("git", gitArguments, {
    cwd: REPOSITORY_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  })
}

function defaultRunCommand(command, commandArguments, options) {
  return spawnSync(command, commandArguments, options)
}

function describeFailure(result) {
  if (result.error !== undefined) return result.error.message
  if (result.signal !== null && result.signal !== undefined) return `signal ${result.signal}`
  return `exit code ${result.status}`
}

function assertCargoDeny({ cwd, log, runCommand }) {
  const installHint = `Install it with: cargo install --locked cargo-deny@${EXPECTED_CARGO_DENY_VERSION}`
  const result = runCommand("cargo", ["deny", "--version"], { cwd, encoding: "utf8" })
  if (result.error !== undefined && result.error.code === "ENOENT") {
    throw new RustCheckError(
      "cargo was not found on PATH. Install the Rust toolchain with rustup; the version is pinned in " +
        `${RUST_PACKAGE_DIRECTORY}/rust-toolchain.toml.`
    )
  }
  if (result.status !== 0) {
    throw new RustCheckError(
      `cargo-deny is not available (${describeFailure(result)}). ${installHint}`
    )
  }
  const version = String(result.stdout).trim().split(/\s+/v).at(-1)
  if (version !== EXPECTED_CARGO_DENY_VERSION) {
    log(
      `${LOG_PREFIX} warning: cargo-deny ${version} found, CI uses ${EXPECTED_CARGO_DENY_VERSION}. ${installHint}`
    )
  }
}

export function runRustCheckSteps({ cwd, log, runCommand }) {
  assertCargoDeny({ cwd, log, runCommand })
  for (const step of RUST_CHECK_STEPS) {
    log(`${LOG_PREFIX}: ${step.name}`)
    const result = runCommand("cargo", step.arguments, { cwd, stdio: "inherit" })
    if (result.error !== undefined || result.status !== 0) {
      throw new RustCheckError(`${step.name} failed (${describeFailure(result)}).`)
    }
  }
}

export function runRustCheck(options) {
  const {
    environment = process.env,
    execGit = defaultExecGit,
    log = console.log,
    repositoryRoot = REPOSITORY_ROOT,
    runCommand = defaultRunCommand,
  } = options ?? {}
  const decision = decideRustCheck({ environment, readGitState: () => readGitState(execGit) })
  if (!decision.run) {
    log(`${LOG_PREFIX} skipped: ${decision.reason}`)
    return decision
  }
  log(`${LOG_PREFIX} running: ${decision.reason}`)
  runRustCheckSteps({ cwd: join(repositoryRoot, RUST_PACKAGE_DIRECTORY), log, runCommand })
  log(`${LOG_PREFIX} passed`)
  return decision
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    runRustCheck()
  } catch (error) {
    console.error(`${LOG_PREFIX} failed: ${error.message}`)
    process.exitCode = 1
  }
}
