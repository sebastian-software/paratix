import { spawn } from "node:child_process"

export type PodmanTerminalAction = {
  bytes?: string
  prompt: string
  response?: string
  signal?: "SIGTERM"
}
export type PodmanProcessResult = { code: number; output: string; responses: number }

// The PTY belongs to the controller. No Python binary is used on the SSH target.
const DRIVER = String.raw`
import errno, fcntl, json, os, pty, select, signal, subprocess, sys, termios, time
config = json.loads(sys.argv[1])
master, slave = pty.openpty()
def terminal():
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
process = subprocess.Popen(config["argv"], stdin=slave, stdout=slave, stderr=slave, env=config["env"], cwd=config["cwd"], preexec_fn=terminal)
os.close(slave)
output = bytearray()
step = 0
cursor = 0
deadline = time.monotonic() + 45
try:
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("Podman CLI PTY did not finish")
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
        text = output.decode("utf-8", "replace")
        if step < len(config["actions"]):
            action = config["actions"][step]
            position = text.find(action["prompt"], cursor)
            if position >= 0:
                cursor = position + len(action["prompt"])
                if "signal" in action:
                    process.send_signal(getattr(signal, action["signal"]))
                else:
                    value = action.get("bytes", action.get("response", "") + "\n")
                    os.write(master, value.encode())
                step += 1
        if process.poll() is not None and not readable:
            break
    code = process.wait(timeout=5)
    print(json.dumps({"code": code, "output": output.decode("utf-8", "replace"), "responses": step}))
finally:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    os.close(master)
`

/**
 * Execute the real CLI with kernel terminal semantics and prompt-driven input.
 * @param options - Controller process, environment, directory and terminal actions.
 * @param options.actions - Prompt-triggered input and signal actions.
 * @param options.argv - CLI executable and arguments.
 * @param options.cwd - Working directory for the CLI process.
 * @param options.env - Process environment for the CLI process.
 * @returns The process exit code, captured terminal output and response count.
 */
export async function runPodmanPty(options: {
  actions: PodmanTerminalAction[]
  argv: string[]
  cwd: string
  env: NodeJS.ProcessEnv
}): Promise<PodmanProcessResult> {
  const child = spawn("python3", ["-u", "-c", DRIVER, JSON.stringify(options)], {
    cwd: options.cwd,
    stdio: ["ignore", "pipe", "pipe"],
  })
  let stdout = ""
  let stderr = ""
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString()
  })
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString()
  })
  return new Promise((resolve, reject) => {
    child.once("error", reject)
    child.once("close", (code) => {
      if (code === 0) {
        try {
          resolve(JSON.parse(stdout) as PodmanProcessResult)
        } catch {
          reject(new Error("Podman PTY fixture returned invalid JSON"))
        }
      } else reject(new Error(`Podman PTY fixture failed: ${stderr}`))
    })
  })
}
