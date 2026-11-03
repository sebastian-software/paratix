// Invoked only by the process-recovery integration test. No production fault hook is needed.
import { readFile } from "node:fs/promises"

import type { ExecOptions } from "../../src/types.js"

import { ssh } from "../../src/modules/ssh.js"
import { SshConnectionImpl } from "../../src/ssh.js"

const input: unknown = JSON.parse(process.env.PARATIX_HOST_CRASH_INPUT ?? "null")
if (typeof input !== "object" || input === null) throw new Error("Missing crash fixture input")
const port: unknown = Reflect.get(input, "port")
const bootstrap: unknown = Reflect.get(input, "bootstrap")
const hostKey: unknown = Reflect.get(input, "hostKey")
const caKey: unknown = Reflect.get(input, "caKey")
if (
  typeof port !== "number" ||
  typeof bootstrap !== "string" ||
  typeof hostKey !== "string" ||
  typeof caKey !== "string"
)
  throw new Error("Invalid crash fixture input")
const connection = new SshConnectionImpl("127.0.0.1", {
  expectedHostPublicKey: hostKey,
  ports: [port],
  privateKey: bootstrap,
  strictHostKeyChecking: "yes",
  user: "root",
})
await connection.connect()
const checkpoint: unknown = Reflect.get(input, "checkpoint") ?? "between-publishes"
if (typeof checkpoint !== "string") throw new Error("Invalid crash checkpoint")
const beforeEvents = new Map([
  ["before-complete-old", "marker-complete-old"],
  ["before-complete", "marker-complete-new"],
  ["before-reload", "reload"],
])
const afterEvents = new Map([
  ["after-complete-old", "marker-complete-old"],
  ["after-complete", "marker-complete-new"],
  ["after-config", "config"],
  ["after-reload", "reload"],
  ["before-active", "marker-prepared"],
  ["between-publishes", "certificate"],
  ["rollback-certificate", "restore-certificate"],
  ["rollback-config", "restore-config"],
])
const COPY_PUBLICATION = 'mv -T -- "$paratix_copy"'
const TARGET_KILL = 'printf "%s" "$$" > /run/host-crash-target-pid; kill -KILL $$'
function includesAll(command: string, parts: string[]): boolean {
  return parts.every((part) => command.includes(part))
}
function commandEvents(command: string): Set<string> {
  const predicates: Array<[string, boolean]> = [
    [
      "marker",
      includesAll(command, [
        "mv -T --",
        "/manifest-next'",
        "'/var/lib/paratix/host-certificate-pending'",
      ]),
    ],
    [
      "certificate",
      includesAll(command, [COPY_PUBLICATION, "'/etc/ssh/ssh_host_ed25519_key-cert.pub'"]),
    ],
    ["config", includesAll(command, [COPY_PUBLICATION, "'/etc/ssh/sshd_config'"])],
    ["restore-certificate", includesAll(command, [COPY_PUBLICATION, "/original-certificate'"])],
    ["restore-config", includesAll(command, [COPY_PUBLICATION, "/original-config'"])],
    ["reload", command.endsWith("systemctl reload ssh")],
    ["cleanup", command.includes("-mindepth 1 -maxdepth 1 -type f -delete")],
  ]
  return new Set(predicates.filter(([, selected]) => selected).map(([event]) => event))
}
function injectCleanupKill(command: string, selectedCheckpoint: string): string {
  if (selectedCheckpoint === "cleanup-directory")
    return command.replace(/rmdir -- [^\n]+/v, (statement) => `${statement}\n${TARGET_KILL}`)
  if (selectedCheckpoint === "cleanup-marker") return `${command}\n${TARGET_KILL}`
  const match = /find (?<directory>.+) -mindepth 1 -maxdepth 1 -type f -delete/v.exec(command)
  if (match?.groups === undefined) throw new Error("Missing cleanup statement")
  const count = Number(selectedCheckpoint.slice("cleanup-".length))
  return command.replace(
    match[0],
    () => `paratix_deleted=0
for paratix_sidecar in $(find ${match.groups?.directory} -mindepth 1 -maxdepth 1 -type f | sort); do
  rm -- "$paratix_sidecar"
  paratix_deleted=$((paratix_deleted + 1))
  if [ "$paratix_deleted" = ${String(count)} ]; then ${TARGET_KILL}; fi
done`
  )
}
async function killAfterCleanup(command: string, options?: ExecOptions): Promise<never> {
  try {
    await execute(injectCleanupKill(command, String(checkpoint)), options)
  } catch {
    /* SIGKILL may close the SSH channel without an exit status. */
  }
  const gone = await execute(
    "test -s /run/host-crash-target-pid && { test ! -e /proc/$(cat /run/host-crash-target-pid) || grep -q '^State:.*Z' /proc/$(cat /run/host-crash-target-pid)/status; } && flock -n /var/lib/paratix/sshd-commit.lock true",
    { ignoreExitCode: true, silent: true }
  )
  if (gone.code !== 0) throw new Error("Cleanup target process death was not observed")
  process.kill(process.pid, "SIGKILL")
  throw new Error("Controller SIGKILL was not delivered")
}
function hasCheckpoint(events: Set<string>, table: Map<string, string>): boolean {
  return events.has(table.get(String(checkpoint)) ?? "")
}
const execute = connection.exec.bind(connection)
let markerPhase = ""
connection.exec = async (command, options) => {
  if (command.includes("/manifest-next'") && typeof options?.input === "string") {
    const manifest = JSON.parse(options.input) as { phase: string }
    markerPhase = manifest.phase
  }
  const events = commandEvents(command)
  if (events.has("marker")) events.add(`marker-${markerPhase}`)
  if (hasCheckpoint(events, beforeEvents)) process.kill(process.pid, "SIGKILL")
  const targetKill = checkpoint.startsWith("cleanup-") && events.has("cleanup")
  if (targetKill) return killAfterCleanup(command, options)
  const result = await execute(command, options)
  if (result.code === 0 && hasCheckpoint(events, afterEvents)) process.kill(process.pid, "SIGKILL")
  return result
}
const module = ssh.hostCertificate({
  principals: ["host.test"],
  renewBefore: "1h",
  signer: ssh.signer.local({ caKey, caPublicKey: await readFile(`${caKey}.pub`, "utf8") }),
  validity: "1d",
})
try {
  const result = await module.apply(connection, {})
  if (result.status === "failed") throw result.error ?? new Error("Crash worker apply failed")
} finally {
  connection.disconnect()
}
throw new Error("Crash checkpoint was not reached")
