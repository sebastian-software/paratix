// #255 B3: registry-side preflights of the release mode. Everything here
// runs before the first `npm publish`:
// - provenance of already published versions (resume rule),
// - the trusted-publishing (OIDC) token exchange for every missing package,
// - a source check that the installed npm still implements the OIDC flow
//   this preflight replicates (verified against npm 11.16.0).
import { join } from "node:path"

import { integrityToHex } from "./publishArtefacts.mjs"

export const NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
const NPM_OIDC_AUDIENCE = "npm:registry.npmjs.org"
const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
const REPOSITORY_URL = "https://github.com/sebastian-software/paratix"
const EXPECTED_WORKFLOW = {
  path: ".github/workflows/publish.yml",
  ref: "refs/heads/main",
  repository: REPOSITORY_URL,
}
const INVOCATION_ID_PATTERN =
  /^https:\/\/github\.com\/sebastian-software\/paratix\/actions\/runs\/(?<runId>\d+)\/attempts\/\d+$/v
const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/v
const NATIVE_SOURCE_DIRECTORY = "packages/ssh-native"
// Literal fragments of npm's lib/utils/oidc.js (npm 11.16.0).
// eslint-disable-next-line no-template-curly-in-string -- Literal source text searched in npm's oidc.js.
const NPM_OIDC_ENDPOINT_TEMPLATE = "/-/npm/v1/oidc/token/exchange/package/${escapedPackageName}"
// eslint-disable-next-line no-template-curly-in-string -- Literal source text searched in npm's oidc.js.
const NPM_OIDC_AUDIENCE_TEMPLATE = "npm:${new URL(registry).hostname}"
const JSON_ACCEPT_HEADER = "application/json"
const UTF8 = "utf8"
const TRUSTED_PUBLISHING_HINT =
  "configure trusted publishing with scripts/configure-trust.sh for this package " +
  "(repository sebastian-software/paratix, workflow publish.yml) and re-run the release"

function packageUrlName(name) {
  return name.startsWith("@") ? `%40${name.slice(1)}` : name
}

// npm-package-arg's escapedName: the scope separator is percent-encoded.
export function escapedPackageName(name) {
  return name.replace("/", "%2f")
}

async function npmViewDist({ commandRunner, name, repositoryRoot, version }) {
  const { stdout } = await commandRunner.execFile(
    "npm",
    ["view", `${name}@${version}`, "dist", "--json"],
    { cwd: repositoryRoot }
  )
  try {
    return JSON.parse(stdout)
  } catch (error) {
    throw new Error(`npm view ${name}@${version} dist returned invalid JSON.`, { cause: error })
  }
}

function provenanceError(label, reason) {
  return new Error(
    `${label} is already published, but its provenance cannot be accepted: ${reason}. ` +
      "Only versions published by .github/workflows/publish.yml on refs/heads/main of " +
      "sebastian-software/paratix can be resumed; investigate the registry state manually."
  )
}

function readAttestationsUrl(dist, label) {
  const url = dist?.attestations?.url
  if (typeof url !== "string") throw provenanceError(label, "dist.attestations.url is missing")
  let parsedUrl
  try {
    parsedUrl = new URL(url)
  } catch {
    throw provenanceError(label, `dist.attestations.url ${JSON.stringify(url)} is invalid`)
  }
  if (parsedUrl.origin !== NPM_REGISTRY_ORIGIN) {
    throw provenanceError(label, `attestations are served from ${parsedUrl.origin}`)
  }
  return parsedUrl
}

async function fetchProvenanceStatement({ fetch, label, url }) {
  let attestations
  try {
    const response = await fetch(url, { headers: { Accept: JSON_ACCEPT_HEADER } })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const body = await response.json()
    attestations = body?.attestations
  } catch (error) {
    throw provenanceError(label, `attestations could not be fetched (${error.message})`)
  }
  const provenance = Array.isArray(attestations)
    ? attestations.find((attestation) => attestation?.predicateType === SLSA_PROVENANCE_V1)
    : undefined
  const payload = provenance?.bundle?.dsseEnvelope?.payload
  if (typeof payload !== "string") throw provenanceError(label, "no SLSA v1 provenance attestation")
  try {
    return JSON.parse(Buffer.from(payload, "base64").toString(UTF8))
  } catch {
    throw provenanceError(label, "the provenance payload is unreadable")
  }
}

function assertProvenanceWorkflow(statement, label) {
  const workflow = statement?.predicate?.buildDefinition?.externalParameters?.workflow
  const mismatches = Object.entries(EXPECTED_WORKFLOW)
    .filter(([key, expected]) => workflow?.[key] !== expected)
    .map(([key, expected]) => `${key} ${JSON.stringify(workflow?.[key])} (expected ${expected})`)
  if (mismatches.length === 0) return
  throw provenanceError(label, `foreign build workflow: ${mismatches.join(", ")}`)
}

function assertProvenanceSubject({ integrityHex, label, name, statement, version }) {
  const subjectName = `pkg:npm/${packageUrlName(name)}@${version}`
  const subjects = Array.isArray(statement?.subject) ? statement.subject : []
  const subject = subjects.find((candidate) => candidate?.name === subjectName)
  if (subject === undefined) throw provenanceError(label, `no subject ${subjectName}`)
  if (subject.digest?.sha512 !== integrityHex) {
    throw provenanceError(label, "the subject sha512 digest does not match dist.integrity")
  }
}

function readProvenanceRunId(predicate, label) {
  const invocationId = predicate?.runDetails?.metadata?.invocationId
  const runId = INVOCATION_ID_PATTERN.exec(String(invocationId))?.groups?.runId
  if (runId !== undefined) return runId
  throw provenanceError(label, `unexpected invocationId ${JSON.stringify(invocationId)}`)
}

function readProvenanceCommit(predicate, label) {
  const sourceDependency = predicate?.buildDefinition?.resolvedDependencies?.[0]
  const commit = sourceDependency?.digest?.gitCommit
  if (typeof commit === "string" && GIT_COMMIT_PATTERN.test(commit)) return commit
  throw provenanceError(label, `unexpected source commit ${JSON.stringify(commit)}`)
}

function readProvenanceRun(statement, label) {
  const predicate = statement?.predicate
  return {
    commit: readProvenanceCommit(predicate, label),
    runId: readProvenanceRunId(predicate, label),
  }
}

// #255 B3: reads `dist` of a published version and validates its SLSA v1
// provenance. Returns { commit, integrity, runId } of the publishing run.
// The attestation signature itself is verified by the registry on upload;
// this check pins the build identity (repository, workflow, ref) and binds
// the statement to the published tarball digest.
export async function readPublishedProvenance({
  commandRunner,
  fetch,
  name,
  repositoryRoot,
  version,
}) {
  const label = `${name}@${version}`
  const dist = await npmViewDist({ commandRunner, name, repositoryRoot, version })
  const integrityHex = integrityToHex(dist?.integrity)
  if (integrityHex === undefined)
    throw provenanceError(label, "dist.integrity is not a sha512 value")
  const url = readAttestationsUrl(dist, label)
  const statement = await fetchProvenanceStatement({ fetch, label, url })
  assertProvenanceWorkflow(statement, label)
  assertProvenanceSubject({ integrityHex, label, name, statement, version })
  return { ...readProvenanceRun(statement, label), integrity: dist.integrity }
}

// #255 B3: a version published by an earlier workflow run is only resumed
// when the Rust/binding sources are unchanged since its commit, so the
// already published binaries still match the current sources.
export async function assertNativeSourcesUnchangedSince({
  commandRunner,
  commit,
  label,
  repositoryRoot,
}) {
  try {
    await commandRunner.execFile(
      "git",
      ["diff", "--quiet", `${commit}..HEAD`, "--", NATIVE_SOURCE_DIRECTORY],
      { cwd: repositoryRoot }
    )
  } catch (error) {
    if (error?.code === 1) {
      throw new Error(
        `${label} was published from ${commit}, but ${NATIVE_SOURCE_DIRECTORY} changed since then. ` +
          "Bump the release version instead of resuming the earlier release.",
        { cause: error }
      )
    }
    throw new Error(
      `Could not compare ${NATIVE_SOURCE_DIRECTORY} between ${commit} and HEAD for ${label}. ` +
        "publish.yml must check out the full history (actions/checkout with fetch-depth: 0).",
      { cause: error }
    )
  }
}

async function readJsonBody(response) {
  try {
    return await response.json()
  } catch {
    return null
  }
}

function notPublishableError(name, reason) {
  return new Error(`${name} is not publishable (${reason}): ${TRUSTED_PUBLISHING_HINT}.`)
}

async function requestIdToken({ environment, fetch, name }) {
  const requestUrl = environment.ACTIONS_ID_TOKEN_REQUEST_URL
  const requestToken = environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!requestUrl || !requestToken) {
    throw notPublishableError(
      name,
      "ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN are missing; the publish job needs `permissions: id-token: write`"
    )
  }
  const url = new URL(requestUrl)
  url.searchParams.append("audience", NPM_OIDC_AUDIENCE)
  const response = await fetch(url, {
    headers: { Accept: JSON_ACCEPT_HEADER, Authorization: `Bearer ${requestToken}` },
  })
  if (!response.ok)
    throw notPublishableError(name, `ID token request failed with HTTP ${response.status}`)
  const body = await readJsonBody(response)
  const idToken = body?.value
  if (typeof idToken !== "string" || idToken === "") {
    throw notPublishableError(name, "the ID token response has no value")
  }
  return idToken
}

// #255 B3 (decision 4a): proves that npm accepts this workflow as trusted
// publisher for the package by running the same token exchange npm runs
// during `npm publish`. The exchange publishes nothing; the returned token
// is masked immediately and discarded. Neither the ID token nor the npm
// token is ever logged.
export async function assertTrustedPublishing({ environment, fetch, name, workflowCommands }) {
  const idToken = await requestIdToken({ environment, fetch, name })
  workflowCommands.write(`::add-mask::${idToken}\n`)
  const response = await fetch(
    `${NPM_REGISTRY_ORIGIN}/-/npm/v1/oidc/token/exchange/package/${escapedPackageName(name)}`,
    { headers: { Accept: JSON_ACCEPT_HEADER, Authorization: `Bearer ${idToken}` }, method: "POST" }
  )
  if (!response.ok)
    throw notPublishableError(name, `token exchange failed with HTTP ${response.status}`)
  const body = await readJsonBody(response)
  const token = body?.token
  if (typeof token !== "string" || token === "") {
    throw notPublishableError(name, "the token exchange response has no token")
  }
  workflowCommands.write(`::add-mask::${token}\n`)
  console.log(`${name}: trusted publishing token exchange succeeded.`)
}

async function readNpmInstallation({ commandRunner, fs, repositoryRoot }) {
  const runOptions = { cwd: repositoryRoot }
  const versionResult = await commandRunner.execFile("npm", ["--version"], runOptions)
  const version = versionResult.stdout.trim()
  console.log(`Using npm ${version}.`)
  const globalRootResult = await commandRunner.execFile("npm", ["root", "-g"], runOptions)
  const globalRoot = globalRootResult.stdout.trim()
  const npmDirectory = join(globalRoot, "npm")
  const manifest = JSON.parse(await fs.readFile(join(npmDirectory, "package.json"), UTF8))
  const oidcSource = await fs.readFile(join(npmDirectory, "lib/utils/oidc.js"), UTF8)
  return { installedVersion: manifest?.version, npmDirectory, oidcSource, version }
}

// #255 B3: the OIDC preflight replicates npm's endpoint and audience. Abort
// when the npm that will publish no longer contains exactly that flow.
export async function assertNpmOidcSource({ commandRunner, fs, repositoryRoot }) {
  let installation
  try {
    installation = await readNpmInstallation({ commandRunner, fs, repositoryRoot })
  } catch (error) {
    throw new Error(
      `Could not inspect the installed npm (${error.message}); the installed npm no longer matches the verified OIDC flow; re-verify the endpoint.`,
      { cause: error }
    )
  }
  const { installedVersion, npmDirectory, oidcSource, version } = installation
  const problems = [
    installedVersion === version
      ? ""
      : `${npmDirectory}/package.json reports ${installedVersion}, npm --version ${version}`,
    oidcSource.includes(NPM_OIDC_ENDPOINT_TEMPLATE) ? "" : "token exchange endpoint not found",
    oidcSource.includes(NPM_OIDC_AUDIENCE_TEMPLATE) ? "" : "audience construction not found",
  ].filter((problem) => problem !== "")
  if (problems.length === 0) return
  throw new Error(
    `The installed npm no longer matches the verified OIDC flow (${problems.join("; ")}); re-verify the endpoint.`
  )
}
