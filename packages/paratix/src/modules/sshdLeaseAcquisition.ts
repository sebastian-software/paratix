import type { SshConnection } from "../types.js"
import type { FlagLockAcquireResult } from "./flagLock.js"
import type { FlagLockWaitBudget } from "./flagLockWait.js"
import type { MutexLockAcquisition } from "./mutexLock.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { flagLockDisplayPath, FLAGS_DIRECTORY, validateFlagName } from "./flagLock.js"
import { flagLockAgeThreshold, validateFlagLockHolder } from "./flagLockScripts.js"

const CONTENDED_EXIT = 77
const WAIT_ROUND_SECONDS = 1
const MILLISECONDS_PER_SECOND = 1000
const INITIALIZATION_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/v

type AcquisitionIdentity = { lockName: string; staleSeconds: number; token: string }

function preparationGuard(directory: string, marker: string): string {
  // A reserved UUID-named preparation file is recoverable only when its protection
  // and bytes prove a prefix of that filename's public token. Arbitrary malformed
  // holder files, sidecars, symlinks and foreign payloads remain untouched.
  return `
if [ -n "$paratix_entries" ]; then
  [ ! -e ${marker} ] && [ ! -L ${marker} ] &&
  [ "$(stat -c '%a %u %g' -- ${directory})" = '700 0 0' ] &&
  [ ! -L "$paratix_entries" ] && [ -f "$paratix_entries" ] &&
  [ "$(stat -c '%a %u %g %h' -- "$paratix_entries")" = '600 0 0 1' ] || { echo 'Unsafe sshd initialization evidence' >&2; exit 76; }
  paratix_initial_token="\${paratix_entries##*/holder.pending-}"
  [ "\${#paratix_initial_token}" = 36 ] &&
  printf '%s' "$paratix_initial_token" | LC_ALL=C grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 76
  [ "$paratix_entries" = ${directory}/holder.pending-"$paratix_initial_token" ] || exit 76
  paratix_other=$(find ${directory} -mindepth 1 -maxdepth 1 ! -name holder ! -path "$paratix_entries" -print -quit) || exit 76
  [ -z "$paratix_other" ] || exit 76
  paratix_size=$(stat -c '%s' -- "$paratix_entries")
  [ "$paratix_size" -le 37 ] || exit 76
  paratix_expected=$(printf '%s\\n' "$paratix_initial_token" | head -c "$paratix_size" | sha256sum | cut -d ' ' -f 1)
  paratix_actual=$(sha256sum -- "$paratix_entries" | cut -d ' ' -f 1)
  [ "\${#paratix_expected}" = 64 ] && [ "$paratix_expected" = "$paratix_actual" ] || { echo 'Foreign sshd initialization payload' >&2; exit 76; }
fi
`
}

function acquisitionCommand(identity: AcquisitionIdentity): string {
  const directory = shellQuote(flagLockDisplayPath(identity.lockName))
  const marker = shellQuote(`${flagLockDisplayPath(identity.lockName)}/holder`)
  const token = shellQuote(identity.token)
  const prepared = shellQuote(
    `${flagLockDisplayPath(identity.lockName)}/holder.pending-${identity.token}`
  )
  const staleMinutes = String(flagLockAgeThreshold(identity.staleSeconds).mminMinutes)
  // The caller runs this entire command under the permanent sshd kernel lock. No
  // controller round trip separates mkdir, initial marker publication and readback.
  // Failed initialization retains evidence; it never cleans up a possibly foreign lease.
  return `
# paratix-sshd-lease-acquire
set -e
if [ ! -e ${FLAGS_DIRECTORY} ] && [ ! -L ${FLAGS_DIRECTORY} ]; then
  (umask 022; mkdir -- ${FLAGS_DIRECTORY})
fi
paratix_safe_directory ${FLAGS_DIRECTORY} || { echo 'Unsafe sshd lease parent' >&2; exit 76; }
if [ -e ${directory} ] || [ -L ${directory} ]; then
  paratix_safe_directory ${directory} || { echo 'Unsafe sshd lease directory' >&2; exit 76; }
  paratix_entries=$(find ${directory} -mindepth 1 -maxdepth 1 ! -name holder -print -quit) || exit 76
  ${preparationGuard(directory, marker)}
  if [ -e ${marker} ] || [ -L ${marker} ]; then
    [ ! -L ${marker} ] && [ -f ${marker} ] &&
    [ "$(stat -c '%u %h' -- ${marker})" = '0 1' ] &&
    [ "$(find ${marker} -maxdepth 0 -perm /022 -print)" = '' ] &&
    [ -n "$(awk 'NR==1{print $1}' ${marker})" ] || { echo 'Unsafe sshd lease marker' >&2; exit 76; }
    if [ -n "$(find ${marker} -maxdepth 0 -mmin +${staleMinutes} -print)" ]; then
      rm -- ${marker}
      rmdir -- ${directory}
    fi
  elif [ -n "$(find ${directory} -maxdepth 0 -mmin +${staleMinutes} -print)" ]; then
    # Only an old, safe, empty directory can represent interrupted initialization.
    # A validated reserved preparation file is removed first; a repeated crash may
    # leave the same safe empty directory for the following bounded recovery.
    if [ -n "$paratix_entries" ]; then
      [ -n "$(find "$paratix_entries" -maxdepth 0 -mmin +${staleMinutes} -print)" ] || exit ${String(CONTENDED_EXIT)}
      rm -- "$paratix_entries"
    fi
    rmdir -- ${directory}
  fi
fi
umask 077
if mkdir -- ${directory} 2>/dev/null; then
  chown 0:0 -- ${directory}
  chmod 0700 -- ${directory}
  (umask 077; set -C; printf '%s\\n' ${token} > ${prepared})
  [ "$(awk 'NR==1{print $1}' ${prepared})" = ${token} ] || exit 76
  mv -T -n -- ${prepared} ${marker}
  [ ! -e ${prepared} ] && [ ! -L ${prepared} ] || exit 76
  [ "$(awk 'NR==1{print $1}' ${marker})" = ${token} ] || exit 76
  printf '%s\\n' ${token}
else
  exit ${String(CONTENDED_EXIT)}
fi
`
}

async function acquire(
  ssh: SshConnection,
  identity: AcquisitionIdentity
): Promise<FlagLockAcquireResult> {
  const result = await ssh.exec(acquisitionCommand(identity), {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === CONTENDED_EXIT) return { kind: "contended" }
  if (result.code !== 0 || result.stdout.trim() !== identity.token)
    return {
      failure: failed("sshd atomic lease acquisition failed; retained lease evidence"),
      kind: "failed",
    }
  return { holderToken: identity.token, kind: "acquired" }
}

async function waitForRetry(budget: FlagLockWaitBudget): Promise<boolean> {
  if (budget.isExhausted()) return false
  const pollSeconds = Math.min(WAIT_ROUND_SECONDS, budget.nextPollSeconds())
  const startedAt = Date.now()
  // A controller timer holds neither a remote exec channel nor the target OS lock.
  // Every following observation/reclaim happens in the next short atomic acquisition.
  await new Promise<void>((resolve) => {
    setTimeout(resolve, pollSeconds * MILLISECONDS_PER_SECOND)
  })
  budget.recordRound({ held: true, pollSeconds, startedAt })
  return !budget.isExhausted()
}

/**
 * Coordinate only sshd acquisition; the supplied connection locks each complete target command.
 * @param ssh - Kernel-serialized connection for short lease operations.
 * @param identity - Validated lease name, stale threshold and new controller token.
 * @returns Atomic acquisition and controller-side waiting for the existing mutex lifecycle.
 */
export function sshdLeaseAcquisition(
  ssh: SshConnection,
  identity: AcquisitionIdentity
): MutexLockAcquisition {
  validateFlagName(identity.lockName, "lockName")
  validateFlagLockHolder({ token: identity.token })
  if (!INITIALIZATION_TOKEN.test(identity.token))
    throw new Error("sshd initialization requires a controller UUID token")
  flagLockAgeThreshold(identity.staleSeconds)
  return { tryAcquire: async () => acquire(ssh, identity), waitForRetry }
}
