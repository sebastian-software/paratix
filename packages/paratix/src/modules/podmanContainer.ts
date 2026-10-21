import { randomUUID } from "node:crypto"
import { posix } from "node:path"

import type { SshConnection } from "../types.js"
import type { PodmanConfiguration, PodmanCredentials, PodmanStatus } from "./podmanHelpers.js"

import { shellQuote } from "../ssh.js"
import { parsePodmanStatus, PODMAN_STATUSES, PodmanError } from "./podmanHelpers.js"
import { PODMAN_HELPER_SCRIPT } from "./podmanHelperScript.js"
import { PODMAN_PROTOCOL_BASE_CODE } from "./podmanTypes.js"

function pathGuards(path: string, create: boolean): string {
  const parts = path.split("/").filter(Boolean)
  return ["/", ...parts.map((_, index) => `/${parts.slice(0, index + 1).join("/")}`)]
    .map((current) => {
      const quoted = shellQuote(current)
      const creation = create
        ? `mkdir -m 0700 -- ${quoted} >/dev/null 2>&1 || finish UNSAFE_PATH;`
        : ":;"
      return `if [ -L ${quoted} ]; then finish UNSAFE_PATH; fi
if [ ! -e ${quoted} ]; then ${creation} fi
if [ -e ${quoted} ]; then
  [ -d ${quoted} ] || finish UNSAFE_PATH
  owner=$(stat -c '%u' -- ${quoted}) || finish UNSAFE_PATH
  mode=$(stat -c '%a' -- ${quoted}) || finish UNSAFE_PATH
  [ "$owner" = 0 ] && [ "$((0$mode & 022))" = 0 ] || finish UNSAFE_PATH
fi`
    })
    .join("\n")
}

function patMountArgument(mount: string): string {
  return mount.length === 0 ? "" : `--volume ${shellQuote(mount)}`
}

function targetToken(config: PodmanConfiguration): string | undefined {
  return config.source?.passwordFileLocation === "target" ? config.source.passwordFile : undefined
}

function targetGuards(target: string | undefined): string {
  if (target === undefined) return ""
  const parent = posix.dirname(target)
  return `${pathGuards(parent, false)}\n[ -d ${shellQuote(parent)} ] || finish UNSAFE_PATH`
}

function helperCommand(
  config: PodmanConfiguration,
  phase: "check" | "commit" | "prepare",
  attempt: string
): string {
  const target = targetToken(config)
  const authMode = phase === "commit" ? "rw" : "ro"
  const work = phase === "prepare" ? '--volume "$work:/work:rw"' : ""
  const patMount = target === undefined ? "" : `${posix.dirname(target)}:/pat:ro`
  const pat = phase === "commit" ? "" : patMountArgument(patMount)
  const args = [
    phase,
    config.operation,
    config.registry,
    posix.basename(config.authFile),
    target === undefined ? "" : posix.basename(target),
  ]
  return `
${pathGuards(posix.dirname(config.authFile), false)}
${targetGuards(target)}
if [ "$mounted" = 1 ]; then
  [ "$(readlink -f -- ${shellQuote(posix.dirname(config.authFile))})" = ${shellQuote(posix.dirname(config.authFile))} ] || finish UNSAFE_PATH
fi
podman run --rm ${phase === "commit" || config.operation === "logout" ? "" : "--interactive"} \\
  --name ${shellQuote(`paratix-auth-${attempt}-${phase}`)} --cidfile "$work/${phase}.cid" \\
  --pull=never --user 0:0 --userns=host --network=none --read-only --read-only-tmpfs=false \\
  --cap-drop=all --security-opt no-new-privileges --security-opt label=disable --log-driver=none \\
  $auth_mount ${pat} ${work} \\
  --entrypoint python3 ${shellQuote(config.helperImage)} -I -B -c ${shellQuote(PODMAN_HELPER_SCRIPT)} \\
  ${args.map((arg) => shellQuote(arg)).join(" ")} "$mounted" "$work_leaf" >/dev/null 2>&1
phase_code=$?
`.replaceAll("$auth_mount", `\${auth_mount:+--volume} \${auth_mount:+"$auth_mount:${authMode}"}`)
}

/**
 * The wrapper communicates solely through fixed exit codes and empty streams.
 * @param config - Validated public configuration without resolved credentials.
 * @param mode - Non-mutating check or transactional apply.
 * @returns A secret-free host shell command.
 */
export function buildPodmanCommand(config: PodmanConfiguration, mode: "apply" | "check"): string {
  const authParent = posix.dirname(config.authFile)
  const target = targetToken(config)
  const attempt = randomUUID()
  const prepare = mode === "apply" ? "prepare" : "check"
  const workTemplate =
    mode === "apply"
      ? `${authParent}/.paratix-auth.XXXXXXXXXXXX`
      : "/run/.paratix-auth.XXXXXXXXXXXX"
  const authMount = `${authParent}:/auth`
  const statusCases = PODMAN_STATUSES.map(
    (status, index) => `${status}) exit ${String(PODMAN_PROTOCOL_BASE_CODE + index)} ;;`
  ).join("\n")
  const script = `
set +x
exec 2>/dev/null
umask 077
finish() {
  case "$1" in
${statusCases}
    *) exit 89 ;;
  esac
}
work=''
cleanup() {
  [ -n "$work" ] || return 0
  for phase in check prepare commit; do
    if [ -f "$work/$phase.cid" ] && [ ! -L "$work/$phase.cid" ]; then
      cid=$(cat "$work/$phase.cid")
      case "$cid" in ''|*[!a-f0-9]*) ;; *) [ "\${#cid}" = 64 ] && podman rm --force "$cid" >/dev/null 2>&1 ;; esac
    fi
  done
  rm -rf -- "$work" >/dev/null 2>&1
}
trap cleanup EXIT
trap 'finish UNKNOWN' HUP INT TERM
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] || finish UNSAFE_PATH
if [ -f /sys/fs/selinux/enforce ]; then
  [ "$(cat /sys/fs/selinux/enforce)" = 0 ] || finish SELINUX
fi
${pathGuards(authParent, false)}
${targetGuards(target)}
${absentLogout(config)}
command -v podman >/dev/null 2>&1 || finish HELPER_FAILED
podman image exists ${shellQuote(config.helperImage)} >/dev/null 2>&1 || finish IMAGE_MISSING
${mode === "apply" ? pathGuards(authParent, true) : ""}
mounted=0
auth_mount=''
if [ -d ${shellQuote(authParent)} ]; then
  mounted=1
  auth_mount=${shellQuote(authMount)}
fi
work=$(mktemp -d ${shellQuote(workTemplate)}) || finish HELPER_FAILED
work_leaf=$(basename "$work") || finish HELPER_FAILED
${helperCommand(config, prepare, attempt)}
case "$phase_code" in
  0) finish OK ;;
  10) ${mode === "check" ? "finish NEEDS_APPLY" : "mode_only=0"} ;;
  ${mode === "apply" ? "11) mode_only=1 ;;" : ""}
  *) finish HELPER_FAILED ;;
esac
${mode === "apply" ? applyBody(config, attempt) : ""}
`
  return `sh -c ${shellQuote(script)}`
}

function absentLogout(config: PodmanConfiguration): string {
  if (config.operation === "login") return ""
  return `if [ ! -e ${shellQuote(config.authFile)} ] && [ ! -L ${shellQuote(config.authFile)} ]; then finish OK; fi`
}

function applyBody(config: PodmanConfiguration, attempt: string): string {
  const hostCommand =
    config.operation === "login"
      ? `username=$(cat "$work/username") || finish HOST_FAILED
  podman login --compat-auth-file "$work/compat" --username "$username" --password-stdin --tls-verify=true ${shellQuote(config.registry)} <"$work/token" >/dev/null 2>&1`
      : `podman logout --compat-auth-file "$work/compat" ${shellQuote(config.registry)} </dev/null >/dev/null 2>&1`
  return `
if [ "$mode_only" = 0 ]; then
  ${hostCommand}
  host_code=$?
  [ "$host_code" = 0 ] || finish HOST_FAILED
fi
${helperCommand(config, "commit", attempt)}
case "$phase_code" in
  12) finish CHANGED ;;
  21) finish CONFLICT ;;
  *) finish UNKNOWN ;;
esac`
}

const FAILURE_MESSAGES: Partial<Record<PodmanStatus, string>> = {
  CONFLICT: "auth file changed concurrently; publication was refused",
  HELPER_FAILED: "file helper failed before publication",
  HOST_FAILED: "host authentication command failed before publication",
  IMAGE_MISSING: "preload the pinned helper image in the rootful Podman store",
  SELINUX: "SELinux Enforcing is unsupported; no auth mutation was attempted",
  UNKNOWN: "completion is unknown; the auth change may already be applied",
  UNSAFE_PATH: "unsafe target path or execution identity",
}

export async function executePodman(
  ssh: SshConnection,
  config: PodmanConfiguration,
  parameters: { credentials: PodmanCredentials; mode: "apply" | "check" }
): Promise<PodmanStatus> {
  const { credentials, mode } = parameters
  const secrets = Object.values(credentials)
  if (credentials.password !== undefined && credentials.username !== undefined) {
    secrets.push(Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64"))
  }
  let status: PodmanStatus
  try {
    const result = await ssh.exec(buildPodmanCommand(config, mode), {
      ignoreExitCode: true,
      input:
        config.operation === "login"
          ? `${JSON.stringify({ version: 1, ...credentials })}\n`
          : undefined,
      maxOutputBytes: 128,
      secrets,
      silent: true,
      strictUtf8Stdout: true,
    })
    status = parsePodmanStatus(result)
  } catch {
    throw new PodmanError("completion is unknown; remote output was discarded")
  }
  const failure = FAILURE_MESSAGES[status]
  if (failure !== undefined) throw new PodmanError(failure)
  const allowed = mode === "check" ? ["OK", "NEEDS_APPLY"] : ["OK", "CHANGED"]
  if (!allowed.includes(status))
    throw new PodmanError("invalid remote phase status; completion is unknown")
  return status
}
