import { randomUUID } from "node:crypto"

import type { SshConnection } from "../types.js"
import type { HostCertificatePolicy } from "./sshHostCertificatePolicy.js"

import { shellQuote } from "../ssh.js"
import {
  certificateCommand,
  type CertificateFileState,
  contentHash,
  inspectCertificateFile,
  sameState,
} from "./sshCertificateFiles.js"
import { HOST_CERTIFICATE_PENDING } from "./sshdCommitLock.js"
import {
  type HostPending,
  parsePending,
  type PendingFile,
  type PendingState,
} from "./sshHostCertificatePendingSchema.js"
import { HOST_SSHD_CONFIG, type HostTarget, readHostKey } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

const MAX_PENDING_BYTES = 65_536

export type { HostPending, PendingFile, PendingState } from "./sshHostCertificatePendingSchema.js"

function unsafePending(): HostCertificateError {
  return new HostCertificateError("Unsafe host certificate Pending state")
}

export function pendingDirectory(pending: HostPending): string {
  return `/var/lib/paratix/host-certificate-state-${pending.id}`
}
export function pendingSidecar(
  pending: HostPending,
  role: string,
  kind: "candidate" | "original"
): string {
  return `${pendingDirectory(pending)}/${kind}-${role}`
}

export async function readHostPending(ssh: SshConnection): Promise<null | PendingState> {
  const file = await inspectCertificateFile(ssh, HOST_CERTIFICATE_PENDING, { preserve: true })
  if (file === null) return null
  if (
    file.metadata !== "600 0 0" ||
    (await certificateCommand(ssh, `stat -c '%h' -- ${shellQuote(HOST_CERTIFICATE_PENDING)}`)) !==
      "1"
  )
    throw unsafePending()
  const raw = await certificateCommand(
    ssh,
    `head -c ${MAX_PENDING_BYTES + 1} -- ${shellQuote(HOST_CERTIFICATE_PENDING)}`
  )
  if (Buffer.byteLength(raw) > MAX_PENDING_BYTES) throw unsafePending()
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw unsafePending()
  }
  return { hash: file.hash, manifest: parsePending(parsed) }
}

const STATE_FUNCTION = `
paratix_state() {
  if [ -L "$1" ]; then return 1; fi
  if [ ! -e "$1" ]; then printf missing; return; fi
  [ -f "$1" ] && [ "$(stat -c '%h' -- "$1")" = 1 ] || return 1
  printf '%s %s' "$(sha256sum -- "$1" | cut -d ' ' -f 1)" "$(stat -c '%a %u %g' -- "$1")"
}
`
function stateWord(value: CertificateFileState): string {
  return value === null ? "missing" : `${value.hash} ${value.metadata}`
}
function assertState(path: string, expected: CertificateFileState): string {
  return `[ "$(paratix_state ${shellQuote(path)})" = ${shellQuote(stateWord(expected))} ] || { echo 'Host certificate transaction file conflict' >&2; exit 76; };`
}
function assertMarker(current: null | PendingState): string {
  return assertState(
    HOST_CERTIFICATE_PENDING,
    current === null ? null : { hash: current.hash, metadata: "600 0 0" }
  )
}
function assertDependencies(pending: HostPending): string {
  return [
    assertState(pending.policy.hostKeyPath, pending.hostKeyState),
    ...pending.dependencies.map((item) => assertState(item.path, item.state)),
  ].join("\n")
}
function assertDirectory(pending: HostPending): string {
  const directory = shellQuote(pendingDirectory(pending))
  return `[ ! -L ${directory} ] && [ -d ${directory} ] && [ "$(stat -c '%a %u %g' -- ${directory})" = '700 0 0' ] || { echo 'Unsafe host certificate snapshot directory' >&2; exit 76; };`
}
function assertSidecar(
  pending: HostPending,
  file: PendingFile,
  kind: "candidate" | "original"
): string {
  const expected = file[kind]
  if (expected === null) return ""
  return assertState(pendingSidecar(pending, file.role, kind), {
    hash: expected.hash,
    metadata: "600 0 0",
  })
}

/**
 * All active paths must be either the recorded old or new state, never foreign bytes.
 * @param ssh - Connection scoped to the current fenced commit.
 * @param current - Recorded manifest and expected marker hash.
 */
export async function verifyHostPending(ssh: SshConnection, current: PendingState): Promise<void> {
  const pending = current.manifest
  const host = await readHostKey(ssh, pending.policy)
  if (host.publicKey !== pending.publicKey || !sameState(host.state, pending.hostKeyState))
    throw unsafePending()
  for (const file of [...pending.files, ...pending.dependencies]) {
    // eslint-disable-next-line no-await-in-loop -- validate every active ancestor before recovery writes
    await inspectCertificateFile(ssh, file.path, { preserve: true })
  }
  const complete = pending.phase.startsWith("complete-")
  const files = pending.files.map((file) => {
    if (complete)
      return assertState(
        file.path,
        pending.phase === "complete-new" ? file.candidate : file.original
      )
    return `[ "$(paratix_state ${shellQuote(file.path)})" = ${shellQuote(stateWord(file.original))} ] || [ "$(paratix_state ${shellQuote(file.path)})" = ${shellQuote(stateWord(file.candidate))} ] || { echo 'External change blocks host certificate recovery' >&2; exit 76; };\n${assertSidecar(pending, file, "candidate")}\n${assertSidecar(pending, file, "original")}`
  })
  await certificateCommand(
    ssh,
    `${STATE_FUNCTION}\n${assertMarker(current)}\n${assertDependencies(pending)}\n${complete ? "" : assertDirectory(pending)}\n${files.join("\n")}`
  )
}

/**
 * Atomic marker transition; the immutable snapshot set remains untouched.
 * @param ssh - Connection scoped to the current fenced commit.
 * @param current - Expected durable state before the transition.
 * @param phase - Next recovery or completion phase.
 * @returns The atomically published manifest and its content hash.
 */
export async function transitionHostPending(
  ssh: SshConnection,
  current: PendingState,
  phase: HostPending["phase"]
): Promise<PendingState> {
  const manifest = { ...current.manifest, phase }
  const completion = phase.startsWith("complete-")
    ? manifest.files
        .map((file) =>
          assertState(file.path, phase === "complete-new" ? file.candidate : file.original)
        )
        .join("\n")
    : ""
  const raw = `${JSON.stringify(manifest)}\n`
  const temporary = `${pendingDirectory(manifest)}/manifest-next`
  await ssh.writeFile(temporary, raw, { mode: "0600" })
  await certificateCommand(
    ssh,
    `${STATE_FUNCTION}\n${assertMarker(current)}\n${assertDependencies(manifest)}\n${completion}\nmv -T -- ${shellQuote(temporary)} ${shellQuote(HOST_CERTIFICATE_PENDING)}`
  )
  return { hash: contentHash(raw), manifest }
}

export async function prepareHostPending(
  ssh: SshConnection,
  input: { certificate: string; policy: HostCertificatePolicy; target: HostTarget }
): Promise<PendingState> {
  const { policy, target } = input
  const manifest: HostPending = {
    dependencies: target.dependencies,
    files: [
      {
        candidate: { hash: contentHash(input.certificate), metadata: "644 0 0" },
        original: target.certificateState,
        path: policy.certificatePath,
        role: "certificate",
      },
      {
        candidate: {
          hash: contentHash(target.desiredConfig),
          metadata: target.configState?.metadata ?? "644 0 0",
        },
        original: target.configState,
        path: HOST_SSHD_CONFIG,
        role: "config",
      },
    ],
    hostKeyState: target.hostKeyState,
    id: randomUUID(),
    phase: "prepared",
    policy,
    publicKey: target.publicKey,
    version: 1,
  }
  const directory = pendingDirectory(manifest)
  await certificateCommand(ssh, `umask 077; mkdir -- ${shellQuote(directory)}`)
  try {
    await ssh.writeFile(pendingSidecar(manifest, "certificate", "candidate"), input.certificate, {
      mode: "0600",
    })
    await ssh.writeFile(pendingSidecar(manifest, "config", "candidate"), target.desiredConfig, {
      mode: "0600",
    })
    if (target.certificateContent !== null)
      await ssh.writeFile(
        pendingSidecar(manifest, "certificate", "original"),
        target.certificateContent,
        { mode: "0600" }
      )
    await ssh.writeFile(pendingSidecar(manifest, "config", "original"), target.configContent, {
      mode: "0600",
    })
    return { hash: "", manifest }
  } catch (error) {
    await certificateCommand(ssh, `rm -rf -- ${shellQuote(directory)}`)
    throw error
  }
}

/**
 * Publish only after complete candidate validation; no active file changes precede this.
 * @param ssh - Connection scoped to the current fenced commit.
 * @param prepared - Complete immutable snapshots awaiting publication.
 * @returns The published manifest and its content hash.
 */
export async function publishHostPending(
  ssh: SshConnection,
  prepared: PendingState
): Promise<PendingState> {
  const manifest = prepared.manifest
  const raw = `${JSON.stringify(manifest)}\n`
  const temporary = `${pendingDirectory(manifest)}/manifest-next`
  await ssh.writeFile(temporary, raw, { mode: "0600" })
  const sources = manifest.files
    .flatMap((file) => [
      assertState(file.path, file.original),
      assertSidecar(manifest, file, "candidate"),
      assertSidecar(manifest, file, "original"),
    ])
    .join("\n")
  await certificateCommand(
    ssh,
    `${STATE_FUNCTION}\n${assertMarker(null)}\n${assertDependencies(manifest)}\n${assertDirectory(manifest)}\n${sources}\nmv -T -- ${shellQuote(temporary)} ${shellQuote(HOST_CERTIFICATE_PENDING)}`
  )
  return { hash: contentHash(raw), manifest }
}

/**
 * Restore sources are copied, never renamed or consumed, making rollback repeatable.
 * @param ssh - Connection scoped to the current fenced commit.
 * @param current - Expected manifest, dependencies and restore sources.
 * @param input - Recorded file and candidate or original state to publish.
 * @param input.file - Manifest file containing expected old and new hashes and metadata.
 * @param input.kind - Immutable source selecting publication or restoration.
 */
export async function publishHostFile(
  ssh: SshConnection,
  current: PendingState,
  input: { file: PendingFile; kind: "candidate" | "original" }
): Promise<void> {
  const { file, kind } = input
  const pending = current.manifest
  const expected = file[kind]
  await inspectCertificateFile(ssh, file.path, { preserve: true })
  const target = shellQuote(file.path)
  const either = `[ "$(paratix_state ${target})" = ${shellQuote(stateWord(file.original))} ] || [ "$(paratix_state ${target})" = ${shellQuote(stateWord(file.candidate))} ] || { echo 'External change blocks certificate publication' >&2; exit 76; };`
  const publish =
    expected === null
      ? `rm -f -- ${target}`
      : `
paratix_copy=$(mktemp -p ${shellQuote(file.path.slice(0, file.path.lastIndexOf("/")) || "/")} -- .paratix-host-copy.XXXXXX)
trap 'rm -f -- "$paratix_copy"' EXIT HUP INT TERM
cp -- ${shellQuote(pendingSidecar(pending, file.role, kind))} "$paratix_copy"
chown 0:${expected.metadata.split(" ")[2]} -- "$paratix_copy"
chmod ${expected.metadata.split(" ")[0]} -- "$paratix_copy"
[ "$(paratix_state "$paratix_copy")" = ${shellQuote(stateWord(expected))} ] || exit 76
mv -T -- "$paratix_copy" ${target}
`
  await certificateCommand(
    ssh,
    `set -e\n${STATE_FUNCTION}\n${assertMarker(current)}\n${assertDirectory(pending)}\n${assertDependencies(pending)}\n${assertSidecar(pending, file, kind)}\n${either}\nif [ "$(paratix_state ${target})" = ${shellQuote(stateWord(expected))} ]; then exit 0; fi\n${publish}\n${assertState(file.path, expected)}`
  )
}

export async function cleanupHostPending(ssh: SshConnection, current: PendingState): Promise<void> {
  if (!current.manifest.phase.startsWith("complete-")) throw unsafePending()
  await verifyHostPending(ssh, current)
  const directory = shellQuote(pendingDirectory(current.manifest))
  // The manifest is a sibling file and is unlinked last, after the sidecar directory.
  // A kill during any deletion leaves a valid complete manifest, never a broken active one.
  await certificateCommand(
    ssh,
    `set -e\n${STATE_FUNCTION}\n${assertMarker(current)}\n${assertDependencies(current.manifest)}\nif [ -e ${directory} ] || [ -L ${directory} ]; then\n${assertDirectory(current.manifest)}\nfind ${directory} -mindepth 1 -maxdepth 1 -type f -delete\nrmdir -- ${directory}\nfi\nrm -- ${shellQuote(HOST_CERTIFICATE_PENDING)}`
  )
}

export async function hostPendingExists(ssh: SshConnection): Promise<boolean> {
  return ssh.test(
    `[ -e ${shellQuote(HOST_CERTIFICATE_PENDING)} ] || [ -L ${shellQuote(HOST_CERTIFICATE_PENDING)} ]`
  )
}
