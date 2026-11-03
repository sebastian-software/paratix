import { execFile } from "node:child_process"

import { createTrustFixture, type TrustFixture } from "./certificateTrustHarness.js"

export const CLIENT_USER = "hostclient"
export const CLIENT_HOME = "/srv/host-client"
export const CLIENT_KNOWN_HOSTS = `${CLIENT_HOME}/.ssh/known_hosts`
export const HOST_ALIAS = "service.example.test"
const ASSETS = "/run/host-trust"

export type HostProbe = { code: number; stderr: string; stdout: string }
export type HostCaFixture = TrustFixture & {
  hostCa1: string
  hostCa2: string
  hostKey: string
  probeHost: (port?: number, alias?: string) => Promise<HostProbe>
  resetClients: () => Promise<void>
}

const SETUP = `set -eu
groupadd client
useradd --create-home --home-dir ${CLIENT_HOME} --gid client --shell /bin/sh ${CLIENT_USER}
useradd --create-home --shell /bin/sh target
passwd -d ${CLIENT_USER}
passwd -d target
mkdir -p ${ASSETS}
for name in ca1 ca2 host client; do
  ssh-keygen -q -t ed25519 -N '' -f ${ASSETS}/$name
done
cp ${ASSETS}/client ${CLIENT_HOME}/identity
chown ${CLIENT_USER}:client ${CLIENT_HOME}/identity
chmod 600 ${CLIENT_HOME}/identity
for name in good wrong-ca wrong-principal; do
  cp ${ASSETS}/host.pub ${ASSETS}/$name.pub
  ca=ca1
  principal=${HOST_ALIAS}
  if [ "$name" = wrong-ca ]; then ca=ca2; fi
  if [ "$name" = wrong-principal ]; then principal=other.example.test; fi
  ssh-keygen -q -s ${ASSETS}/$ca -h -I "$name" -n "$principal" -V -5m:+1h ${ASSETS}/$name.pub
done
port=2221
for name in good wrong-ca wrong-principal unsigned; do
  config=${ASSETS}/$name.conf
  cat > "$config" <<CONFIG
Port $port
ListenAddress 127.0.0.1
HostKey ${ASSETS}/host
PidFile ${ASSETS}/$name.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedKeysFile ${ASSETS}/client.pub
AllowUsers target
AllowAgentForwarding no
LogLevel VERBOSE
CONFIG
  if [ "$name" != unsigned ]; then
    printf 'HostCertificate %s\\n' ${ASSETS}/$name-cert.pub >> "$config"
  fi
  /usr/sbin/sshd -t -f "$config"
  /usr/sbin/sshd -f "$config" -E ${ASSETS}/$name.log
  port=$((port + 1))
done`

async function hostProbe(containerId: string, port: number, alias: string): Promise<HostProbe> {
  return new Promise((resolve, reject) => {
    const env = { ...process.env }
    delete env.SSH_AUTH_SOCK
    execFile(
      "docker",
      [
        "exec",
        containerId,
        "runuser",
        "-u",
        CLIENT_USER,
        "--",
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        `HOME=${CLIENT_HOME}`,
        "LC_ALL=C",
        "ssh",
        "-v",
        "-F",
        "/dev/null",
        "-p",
        String(port),
        "-i",
        `${CLIENT_HOME}/identity`,
        "-o",
        "CertificateFile=none",
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        `UserKnownHostsFile=${CLIENT_KNOWN_HOSTS}`,
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "KnownHostsCommand=none",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        `HostKeyAlias=${alias}`,
        "-o",
        "ConnectTimeout=5",
        "target@127.0.0.1",
        "id -un",
      ],
      { env, timeout: 15_000 },
      (error, stdout, stderr) => {
        if (error === null) resolve({ code: 0, stderr, stdout: stdout.trim() })
        else if (typeof error.code === "number")
          resolve({ code: error.code, stderr, stdout: stdout.trim() })
        else reject(new Error("Target-system host verification probe failed", { cause: error }))
      }
    )
  })
}

export async function createHostCaFixture(packageDirectory: string): Promise<HostCaFixture> {
  const fixture = await createTrustFixture(packageDirectory)
  try {
    await fixture.container(["sh", "-c", SETUP])
    const containerId = await fixture.container(["hostname"])
    return {
      ...fixture,
      hostCa1: await fixture.container(["cat", `${ASSETS}/ca1.pub`]),
      hostCa2: await fixture.container(["cat", `${ASSETS}/ca2.pub`]),
      hostKey: await fixture.container(["cat", `${ASSETS}/host.pub`]),
      probeHost: async (port = 2221, alias = HOST_ALIAS) => hostProbe(containerId, port, alias),
      async resetClients() {
        await fixture.container([
          "sh",
          "-c",
          `rm -rf ${CLIENT_HOME}/.ssh; rm -f /root/.ssh/known_hosts /root/.ssh/known_hosts.old; chown ${CLIENT_USER}:client ${CLIENT_HOME}; chmod 0751 ${CLIENT_HOME}`,
        ])
      },
    }
  } catch (error) {
    await fixture.cleanup()
    throw error
  }
}
