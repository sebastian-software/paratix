import { createHash, randomUUID } from "node:crypto"
import { posix } from "node:path"

import type { ExecOptions, ExecResult, ModuleResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { flagLockRefreshGuard } from "./flagLockRefresh.js"
import { type MutexLockHandle, withMutexLock } from "./mutexLock.js"
import { sshdLeaseAcquisition } from "./sshdLeaseAcquisition.js"

const GUARDED_COMMAND_TIMEOUT_MS = 120_000
const LEASE_STALE_SECONDS = 120

export const SSHD_LEASE_NAME = "etc-ssh-sshd-config-mutex"
export const HOST_CERTIFICATE_PENDING = "/var/lib/paratix/host-certificate-pending"
const COMMIT_LOCK = "/var/lib/paratix/sshd-commit.lock"
const OPTIONS = { ignoreExitCode: true, silent: true } as const

// The lock inode is never removed. Both lease changes and prepared target commands take
// this lock, so a stopped living process prevents lease reclamation as well as mutation.
const PREPARE_LOCK = `
command -v flock >/dev/null || { echo 'sshd commits require flock' >&2; exit 73; }
paratix_safe_directory() {
  [ ! -L "$1" ] && [ -d "$1" ] &&
  [ "$(stat -c '%u' -- "$1")" = 0 ] &&
  [ "$(find "$1" -maxdepth 0 -perm /022 -print)" = '' ]
}
for paratix_parent in /var /var/lib; do
  paratix_safe_directory "$paratix_parent" || { echo 'Unsafe sshd lock parent' >&2; exit 73; }
done
if [ ! -e /var/lib/paratix ] && [ ! -L /var/lib/paratix ]; then
  (umask 022; mkdir /var/lib/paratix) 2>/dev/null || :
fi
paratix_safe_directory /var/lib/paratix || { echo 'Unsafe Paratix state directory' >&2; exit 73; }
if [ ! -e ${COMMIT_LOCK} ] && [ ! -L ${COMMIT_LOCK} ]; then
  (umask 077; set -C; : > ${COMMIT_LOCK}) 2>/dev/null || :
fi
[ ! -L ${COMMIT_LOCK} ] && [ -f ${COMMIT_LOCK} ] &&
[ "$(stat -c '%a %u %g %h' -- ${COMMIT_LOCK})" = '600 0 0 1' ] || { echo 'Unsafe sshd OS lock' >&2; exit 73; }
exec 9<>${COMMIT_LOCK}
flock -x -w 30 9 || { echo 'Timed out waiting for living sshd commit process' >&2; exit 73; }
`

function lockedCommand(
  command: string,
  guard?: { allowPending: boolean; handle: MutexLockHandle }
): string {
  let fence = ""
  if (guard !== undefined) {
    fence = `${flagLockRefreshGuard(guard.handle)} || { echo 'Stale sshd controller lease' >&2; exit 74; };\n`
    if (!guard.allowPending)
      fence += `[ ! -e ${HOST_CERTIFICATE_PENDING} ] && [ ! -L ${HOST_CERTIFICATE_PENDING} ] || { echo 'Unresolved host certificate Pending blocks sshd writers' >&2; exit 75; };`
  }
  // The shell executing the prepared command inherits fd 9 until process exit.
  return `${PREPARE_LOCK}\n${fence}\n# paratix-sshd-commit-body\n${command}`
}

function scopedConnection(
  base: SshConnection,
  guard?: { allowPending: boolean; handle: MutexLockHandle }
): SshConnection {
  const exec = async (command: string, options?: ExecOptions): Promise<ExecResult> =>
    base.exec(lockedCommand(command, guard), {
      ...options,
      timeout: options?.timeout ?? GUARDED_COMMAND_TIMEOUT_MS,
    })
  const output = async (command: string): Promise<string> => {
    const result = await exec(command, OPTIONS)
    if (result.code !== 0) throw new Error(result.stderr.trim() || "sshd guarded command failed")
    return result.stdout.trim()
  }
  return {
    addPort: (port) => base.addPort(port),
    disconnect() {
      base.disconnect()
    },
    downloadFile: async (remote, local) => base.downloadFile(remote, local),
    exec,
    exists: async (path) => base.exists(path),
    getConnectionInfo: () => base.getConnectionInfo(),
    async lines(command) {
      const value = await output(command)
      return value.split("\n")
    },
    output,
    probeSudo: async () => base.probeSudo(),
    readFile: async (path) => base.readFile(path),
    reconnect: async (options) => base.reconnect(options),
    removePort(port) {
      base.removePort(port)
    },
    sha256: async (path) => base.sha256(path),
    async test(command) {
      const result = await exec(command, OPTIONS)
      return result.code === 0
    },
    updateHost(host) {
      base.updateHost(host)
    },
    async uploadFile() {
      await Promise.reject(
        new Error("Direct upload is unavailable inside an sshd commit; use a prepared public file")
      )
    },
    async writeFile(path, content, options) {
      // SFTP may stage bytes but cannot be the active writer: the target process owns
      // the lease check, complete-payload verification and atomic publication under the kernel lock.
      const parent = shellQuote(posix.dirname(path))
      const target = shellQuote(path)
      const mode = options?.mode ?? "0600"
      const expectedBytes = Buffer.byteLength(content, "utf8")
      const expectedHash = createHash("sha256").update(content, "utf8").digest("hex")
      if (!/^[0-7]{3,4}$/v.test(mode)) throw new Error("Invalid sshd file mode")
      const result = await exec(
        `
set -e
paratix_write=$(mktemp -p ${parent} -- .paratix-sshd-write.XXXXXX)
trap 'rm -f -- "$paratix_write"' EXIT HUP INT TERM
cat > "$paratix_write"
paratix_received_hash=$(sha256sum -- "$paratix_write")
[ "$(stat -c '%s' -- "$paratix_write")" = '${expectedBytes}' ] &&
[ "\${paratix_received_hash%% *}" = '${expectedHash}' ] || { echo 'sshd guarded file integrity check failed' >&2; exit 76; }
chmod ${mode} -- "$paratix_write"
mv -T -- "$paratix_write" ${target}
`,
        { ...OPTIONS, input: content }
      )
      if (result.code !== 0)
        throw new Error(result.stderr.trim() || "sshd guarded file publication failed")
    },
  }
}

/**
 * Shared lease, with kernel serialization of lease changes and every target commit.
 * @param ssh - Active target connection used to acquire the shared lease.
 * @param options - Writer identity, Pending policy and fenced commit body.
 * @param options.allowPending - Permit only the recovery owner to work with unresolved Pending.
 * @param options.name - Module name used in lease-acquisition diagnostics.
 * @param options.section - Commit body receiving the fenced connection and lease identity.
 * @returns The commit result or lease-acquisition failure.
 */
export async function withSshdCommitLease(
  ssh: SshConnection,
  options: {
    allowPending?: boolean
    name: string
    section: (ssh: SshConnection, handle: MutexLockHandle) => Promise<ModuleResult>
  }
): Promise<ModuleResult> {
  const coordinated = scopedConnection(ssh)
  const holder = { token: randomUUID() }
  const result = await withMutexLock(coordinated, {
    acquisition: sshdLeaseAcquisition(coordinated, {
      lockName: SSHD_LEASE_NAME,
      staleSeconds: LEASE_STALE_SECONDS,
      token: holder.token,
    }),
    failureMessage: `[${options.name}] failed to acquire sshd configuration lease`,
    heartbeat: { intervalMilliseconds: 10_000 },
    holder,
    lockName: SSHD_LEASE_NAME,
    propagateSectionThrows: true,
    section: async (handle) =>
      options.section(
        scopedConnection(ssh, { allowPending: options.allowPending ?? false, handle }),
        handle
      ),
    staleSeconds: LEASE_STALE_SECONDS,
    waitSeconds: 180,
  })
  return result.kind === "ok" ? result.value : result.failure
}
