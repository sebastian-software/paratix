// THROWAWAY SPIKE (issue #254): spawns a NON-ROOT OpenSSH sshd for local runs.
// Non-root sshd can only log in the user running it and cannot do password
// or keyboard-interactive authentication (no PAM, no shadow access).
import { spawn } from "node:child_process"
import { mkdtempSync, writeFileSync } from "node:fs"
import { createConnection, createServer } from "node:net"
import { tmpdir } from "node:os"
import { join } from "node:path"

export const SSHD_PATH = process.env.SPIKE_SSHD_PATH ?? "/usr/sbin/sshd"
const SFTP_SERVER_CANDIDATES = [
  "/usr/lib/openssh/sftp-server",
  "/usr/libexec/sftp-server",
  "/usr/libexec/openssh/sftp-server",
]

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer()
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

async function waitForPort(port, deadlineMs) {
  const deadline = Date.now() + deadlineMs
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const socket = createConnection({ host: "127.0.0.1", port })
      socket.once("data", () => {
        socket.destroy()
        resolve(true)
      })
      socket.once("error", () => resolve(false))
    })
    if (ok) return
    await new Promise((r) => setTimeout(r, 50))
  }
  throw new Error(`local sshd did not open port ${port}`)
}

/**
 * Starts sshd with a main profile and a `MaxSessions 1` profile (second port).
 * @param {{ fixtureDir: string }} options
 */
export async function startLocalSshd({ fixtureDir }) {
  const { existsSync } = await import("node:fs")
  const sftpServer = SFTP_SERVER_CANDIDATES.find((p) => existsSync(p)) ?? "internal-sftp"
  const dir = mkdtempSync(join(tmpdir(), "paratix-spike-sshd-"))
  const port = await freePort()
  const maxSessionsPort = await freePort()
  const config = `
Port ${port}
Port ${maxSessionsPort}
ListenAddress 127.0.0.1
HostKey ${join(fixtureDir, "host_ed25519")}
HostKey ${join(fixtureDir, "host_ecdsa")}
HostKey ${join(fixtureDir, "host_rsa")}
HostCertificate ${join(fixtureDir, "host_ed25519-cert.pub")}
TrustedUserCAKeys ${join(fixtureDir, "user_ca.pub")}
AuthorizedKeysFile ${join(fixtureDir, "authorized_keys")}
PidFile ${join(dir, "sshd.pid")}
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
Subsystem sftp ${sftpServer}
LogLevel ERROR

Match LocalPort ${maxSessionsPort}
  MaxSessions 1
`
  const configPath = join(dir, "sshd_config")
  writeFileSync(configPath, config)
  const child = spawn(SSHD_PATH, ["-D", "-e", "-f", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
  })
  let stderr = ""
  child.stderr.on("data", (d) => {
    stderr += d.toString()
  })
  const exited = new Promise((resolve) => child.once("exit", resolve))
  try {
    await Promise.race([
      waitForPort(port, 10_000),
      exited.then((code) => {
        throw new Error(`local sshd exited early (${code}): ${stderr}`)
      }),
    ])
  } catch (error) {
    child.kill("SIGKILL")
    throw error
  }
  return {
    port,
    maxSessionsPort,
    configPath,
    get stderr() {
      return stderr
    },
    async stop() {
      if (child.exitCode === null) {
        child.kill("SIGTERM")
        await exited
      }
    },
  }
}
