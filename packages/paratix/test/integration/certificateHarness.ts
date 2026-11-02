import { execFile } from "node:child_process"
import { mkdir, readFile, rename } from "node:fs/promises"
import { join } from "node:path"

import {
  createIntegrationEnvironment,
  type IntegrationEnvironment,
  runInIntegrationContainer,
} from "./harness.js"

const FILE_PRINCIPAL = "paratix-deploy"

export type CertificateEnvironment = {
  certificatePath: string
  filePrivateKeyPath: string
} & IntegrationEnvironment

async function execute(command: string, args: string[], env = process.env): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { env, timeout: 15_000 }, (error, stdout, stderr) => {
      if (error != null) {
        reject(
          new Error(`Certificate fixture command failed: ${command}: ${stderr}`, { cause: error })
        )
        return
      }
      resolve(stdout)
    })
  })
}

async function generateRsaKey(path: string): Promise<void> {
  await execute("ssh-keygen", ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", path])
}

async function signUserKey(caPath: string, keyPath: string, principal: string): Promise<void> {
  await execute("ssh-keygen", [
    "-q",
    "-s",
    caPath,
    "-I",
    "paratix-integration",
    "-n",
    principal,
    "-V",
    "-5m:+1d",
    `${keyPath}.pub`,
  ])
}

async function moveExternalCertificate(workspaceHome: string, keyPath: string): Promise<string> {
  const certificateDirectory = join(workspaceHome, "external certificates")
  await mkdir(certificateDirectory, { mode: 0o700 })
  const certificatePath = join(certificateDirectory, "deployment certificate.pub")
  // OpenSSH must receive CertificateFile: no implicit <IdentityFile>-cert.pub remains.
  await rename(`${keyPath}-cert.pub`, certificatePath)
  return certificatePath
}

async function writeServerFile(
  environment: IntegrationEnvironment,
  path: string,
  content: string
): Promise<void> {
  await runInIntegrationContainer(environment, [
    "sh",
    "-c",
    'printf "%s" "$1" > "$2"',
    "certificate-fixture",
    content,
    path,
  ])
}

export async function createCertificateEnvironment(
  packageDirectory: string
): Promise<CertificateEnvironment> {
  const environment = await createIntegrationEnvironment(packageDirectory)
  try {
    const caPath = join(environment.workspaceHome, ".ssh", "user_ca_rsa")
    const filePrivateKeyPath = join(environment.workspaceHome, ".ssh", "file_rsa")
    await generateRsaKey(caPath)
    await generateRsaKey(filePrivateKeyPath)
    await signUserKey(caPath, filePrivateKeyPath, FILE_PRINCIPAL)
    await signUserKey(caPath, environment.clientPrivateKeyPath, "paratix")
    const certificatePath = await moveExternalCertificate(
      environment.workspaceHome,
      filePrivateKeyPath
    )
    await writeServerFile(
      environment,
      "/etc/ssh/test-user-ca.pub",
      await readFile(`${caPath}.pub`, "utf8")
    )
    await writeServerFile(
      environment,
      "/etc/ssh/test-authorized-principals",
      `paratix\n${FILE_PRINCIPAL}\n`
    )
    return { ...environment, certificatePath, filePrivateKeyPath }
  } catch (error) {
    await environment.cleanup()
    throw error
  }
}

export async function listAgentIdentities(socket: string): Promise<string> {
  return execute("ssh-add", ["-L"], { ...process.env, SSH_AUTH_SOCK: socket })
}
