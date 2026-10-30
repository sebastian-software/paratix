// Local target: a non-root OpenSSH sshd on 127.0.0.1, run as the current OS
// user (Linux and macOS). Without root there is no PAM and no password or
// keyboard-interactive login; those tests run against Docker only.
import { spawn } from "node:child_process"
import { once } from "node:events"
import { createWriteStream } from "node:fs"
import { readFile, writeFile } from "node:fs/promises"
import { userInfo } from "node:os"
import { join } from "node:path"

import { freePorts, waitForBanners } from "./net.mjs"

export const LOCAL_SSHD = process.env.SSH_NATIVE_IT_SSHD ?? "/usr/sbin/sshd"
const READY_TIMEOUT_MS = 15_000
const STOP_TIMEOUT_MS = 5000

/**
 * @param fixtures the generated fixtures
 * @param paths run directory, ports
 * @returns the sshd_config text
 */
function localConfig(fixtures, paths) {
  const { mainPort, runDir, userCaPort } = paths
  return `# Generated per run by test/integration/lib/local-target.mjs.
Port ${mainPort}
Port ${userCaPort}
ListenAddress 127.0.0.1
HostKey ${fixtures.hostKey}
PidFile ${join(runDir, "sshd.pid")}
AuthorizedKeysFile ${fixtures.authorizedKeys}
StrictModes no
UsePAM no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowAgentForwarding yes
AllowTcpForwarding no
X11Forwarding no
MaxAuthTries 20
MaxSessions 10
Subsystem sftp internal-sftp
LogLevel ERROR

# H1: only the user CA vouches for keys on this port.
Match LocalPort ${userCaPort}
  TrustedUserCAKeys ${fixtures.userCaPublic}
  AuthorizedKeysFile none
  AuthenticationMethods publickey
`
}

/**
 * @param child the sshd process
 * @returns resolves once it exited (at most after a SIGKILL)
 */
async function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = once(child, "exit")
  child.kill("SIGTERM")
  const timer = setTimeout(() => child.kill("SIGKILL"), STOP_TIMEOUT_MS)
  await exited
  clearTimeout(timer)
}

/**
 * Starts the local sshd. Its stop is registered through `defer` right after
 * the spawn, before any await; a failed start leaves it to the runner's
 * teardown.
 *
 * @param fixtures the generated fixtures (principal = current user)
 * @param options private run directory (config, pid file, log) and the
 *   runner's cleanup registration
 * @returns the target description
 */
export async function startLocalTarget(fixtures, options) {
  const { defer, runDir } =
    /** @type {{ runDir: string, defer: (cleanup: () => Promise<void>) => void }} */ (options)
  // Distinct ports: every listener stays open until both are taken.
  const [mainPort, userCaPort] = await freePorts(2)
  const ports = { mainPort, userCaPort }
  const configPath = join(runDir, "sshd_config")
  await writeFile(configPath, localConfig(fixtures, { ...ports, runDir }), { mode: 0o600 })
  const logPath = join(runDir, "sshd.log")
  const log = createWriteStream(logPath)
  const child = spawn(LOCAL_SSHD, ["-D", "-e", "-f", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
  })
  child.stderr.pipe(log)
  defer(async () => {
    await stopProcess(child)
    log.end()
  })
  try {
    // Ready only once every profile port greets.
    await waitForBanners([mainPort, userCaPort], READY_TIMEOUT_MS, { process: child })
  } catch (error) {
    const output = await readFile(logPath, "utf8").catch(() => "")
    throw new Error(`local sshd did not start: ${output.trim()}`, { cause: error })
  }
  return {
    features: { pam: false, tmpfs: false },
    host: "127.0.0.1",
    kind: "local",
    password: null,
    ports: {
      keyboardInteractive: null,
      main: mainPort,
      password: null,
      userCa: userCaPort,
    },
    user: userInfo().username,
  }
}
