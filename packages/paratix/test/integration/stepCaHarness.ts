import { randomUUID } from "node:crypto"
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { trustCommand } from "./certificateTrustHarness.js"

// Official stable CA and CLI releases. All keys, TLS roots and contexts are per fixture.
const INITIALIZE_TIMEOUT_MS = 120_000
const LAUNCHER_MODE = 0o700
const CA_IMAGE = "smallstep/step-ca:0.30.2"
const CLI_IMAGE = "smallstep/step-cli:0.31.0"
export const STEP_PASSWORD = "marked-isolated-step-jwk-password"
export const STEP_REFERENCE = "op://isolated-step-fixture/item/password"
export type StepFixture = {
  caPublicKey: string
  cleanup: () => Promise<void>
  directory: string
  root: string
  wrongRoot: string
}

type StepContext = {
  caDirectory: string
  directory: string
  dockerHost: string
  initializer: string
  label: string
  name: string
  password: string
  root: string
  wrongRoot: string
}
async function stepContext(): Promise<StepContext> {
  const directory = await mkdtemp(join(tmpdir(), "paratix-real-step-ca-"))
  const id = randomUUID()
  const caDirectory = join(directory, "ca")
  return {
    caDirectory,
    directory,
    dockerHost:
      process.env.DOCKER_HOST ??
      (await trustCommand("docker", [
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
      ])),
    initializer: `paratix-step-init-${id}`,
    label: `com.paratix.step-fixture=${id}`,
    name: `paratix-step-ca-${id}`,
    password: join(directory, "password"),
    root: join(caDirectory, "certs/root_ca.crt"),
    wrongRoot: join(directory, "wrong-root.pem"),
  }
}
async function initializeCa(context: StepContext): Promise<void> {
  const { caDirectory, initializer, label, password } = context
  await writeFile(password, STEP_PASSWORD, { mode: 0o600 })
  await trustCommand("docker", [
    "run",
    "--detach",
    "--name",
    initializer,
    "--user",
    "0",
    "--label",
    label,
    "--env",
    "STEPPATH=/test-ca",
    "--entrypoint",
    "sh",
    CLI_IMAGE,
    "-c",
    "sleep infinity",
  ])
  await trustCommand("docker", ["cp", password, `${initializer}:/password`])
  await trustCommand(
    "docker",
    [
      "exec",
      initializer,
      "step",
      "ca",
      "init",
      "--deployment-type",
      "standalone",
      "--name",
      "Paratix isolated test CA",
      "--dns",
      "127.0.0.1",
      "--address",
      ":9000",
      "--provisioner",
      "paratix-jwk",
      "--password-file",
      "/password",
      "--provisioner-password-file",
      "/password",
      "--ssh",
      "--no-db",
    ],
    INITIALIZE_TIMEOUT_MS
  )
  await trustCommand("docker", ["cp", `${initializer}:/test-ca`, caDirectory])
  await trustCommand("docker", ["rm", "-f", initializer])
}
async function configureCa(context: StepContext): Promise<void> {
  const configPath = join(context.caDirectory, "config/ca.json")
  const config = JSON.parse(await readFile(configPath, "utf8")) as {
    authority: { backdate?: string; claims?: Record<string, unknown> }
  }
  config.authority.backdate = "0s"
  config.authority.claims = {
    defaultHostSSHCertDuration: "1h",
    enableSSHCA: true,
    maxHostSSHCertDuration: "48h",
    minHostSSHCertDuration: "1s",
  }
  await writeFile(configPath, JSON.stringify(config))
}
async function startCa(context: StepContext): Promise<void> {
  const { caDirectory, label, name, password } = context
  await trustCommand("docker", [
    "run",
    "--detach",
    "--name",
    name,
    "--label",
    label,
    "--user",
    "0",
    "--env",
    "STEPPATH=/test-ca",
    "--entrypoint",
    "sh",
    CA_IMAGE,
    "-c",
    "sleep infinity",
  ])
  await trustCommand("docker", ["cp", caDirectory, `${name}:/test-ca`])
  await trustCommand("docker", ["cp", password, `${name}:/password`])
  await trustCommand("docker", [
    "exec",
    "--detach",
    name,
    "step-ca",
    "/test-ca/config/ca.json",
    "--password-file",
    "/password",
  ])
  await trustCommand("docker", [
    "exec",
    name,
    "sh",
    "-c",
    "for attempt in $(seq 1 100); do step ca health --ca-url https://127.0.0.1:9000 --root /test-ca/certs/root_ca.crt >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1",
  ])
}
async function writeLauncher(context: StepContext): Promise<void> {
  const { directory, dockerHost, label, name, root, wrongRoot } = context
  await trustCommand("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=untrusted-fixture",
    "-keyout",
    join(directory, "wrong-root.key"),
    "-out",
    wrongRoot,
  ])
  const launcher = `#!${process.execPath}
const fs=require('node:fs');const cp=require('node:child_process');
const args=process.argv.slice(2);const dir=process.cwd();
fs.appendFileSync(${JSON.stringify(join(directory, "argv.jsonl"))},JSON.stringify(args)+'\\n');
const env={PATH:process.env.PATH,DOCKER_HOST:${JSON.stringify(dockerHost)}};
const run=(args)=>cp.spawnSync('docker',args,{env,encoding:'utf8'});
const translated=args.map(arg=>arg===${JSON.stringify(root)}?'/fixture-root.pem':arg===${JSON.stringify(wrongRoot)}?'/wrong-root.pem':[dir,process.env.HOME].some(prefix=>arg.startsWith(prefix+'/'))?'/request/'+arg.slice(arg.lastIndexOf('/')+1):arg);
const created=run(['create','--user','0','--label',${JSON.stringify(label)},'--network',${JSON.stringify(`container:${name}`)},'--workdir','/request','--env','HOME=/request','--env','STEPPATH=/request','--entrypoint','step',${JSON.stringify(CLI_IMAGE)},...translated]);
if(created.status!==0){process.stderr.write(created.stderr);process.exit(1)}
const client=created.stdout.trim();let status=1;
try {
  for(const [source,destination] of [[dir+'/.',client+':/request'],[${JSON.stringify(root)},client+':/fixture-root.pem'],[${JSON.stringify(wrongRoot)},client+':/wrong-root.pem']]){const copied=run(['cp',source,destination]);if(copied.status!==0)throw Error(copied.stderr)}
  const result=run(['start','--attach',client]);process.stdout.write(result.stdout);process.stderr.write(result.stderr);status=result.status??1;fs.appendFileSync(${JSON.stringify(join(directory, "diagnostics.jsonl"))},JSON.stringify({status,stderr:result.stderr.replaceAll(${JSON.stringify(STEP_PASSWORD)},'[redacted]')})+'\\n');
  if(args[0]==='ssh'&&!args.includes('--help')&&status===0){const copied=run(['cp',client+':/request/host-cert.pub',dir+'/host-cert.pub']);if(copied.status!==0)throw Error(copied.stderr)}
} catch(error){process.stderr.write(String(error));status=1} finally {run(['rm','-f',client])}
process.exit(status);
`
  await writeFile(join(directory, "step"), launcher, { mode: LAUNCHER_MODE })
  await chmod(join(directory, "step"), LAUNCHER_MODE)
}
export async function createStepFixture(): Promise<StepFixture> {
  const context = await stepContext()
  const cleanup = async (): Promise<void> => {
    const clients = await trustCommand("docker", [
      "ps",
      "-aq",
      "--filter",
      `label=${context.label}`,
    ])
    if (clients !== "") await trustCommand("docker", ["rm", "-f", ...clients.split("\n")])
    await rm(context.directory, { force: true, recursive: true })
  }
  try {
    await initializeCa(context)
    await configureCa(context)
    await startCa(context)
    await writeLauncher(context)
    return {
      caPublicKey: await readFile(join(context.caDirectory, "certs/ssh_host_ca_key.pub"), "utf8"),
      cleanup,
      directory: context.directory,
      root: context.root,
      wrongRoot: context.wrongRoot,
    }
  } catch (error) {
    await cleanup()
    throw error
  }
}
