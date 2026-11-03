/* oxlint-disable vitest/no-conditional-in-test -- Table-driven cases explicitly select fixture inputs and expected outcomes; every case runs its assertions. */
import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { inspect } from "node:util"
import { afterEach, describe, expect, it, vi } from "vitest"

import { readSignerCertificate } from "../src/modules/sshSignerFiles.js"
import {
  HostCertificateError,
  signerProcess,
  withSignerDirectory,
} from "../src/modules/sshSignerProcess.js"

const MARKER = "marked-signer-process-credential"
const directories: string[] = []

async function directory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "paratix-signer-process-test-"))
  directories.push(path)
  return path
}
function options(path: string, signal = new AbortController().signal) {
  return { directory: path, signal, stage: "test controller request" }
}
function assert(error: unknown) {
  expect(error).toBeInstanceOf(HostCertificateError)
  expect(inspect(error, { depth: null })).not.toContain(MARKER)
  expect(error).not.toHaveProperty("cause")
}

describe("controller signer process test context", () => {
  afterEach(async () => {
    vi.useRealTimers()
    vi.unstubAllEnvs()
    await Promise.all(
      directories.splice(0).map(async (path) => rm(path, { force: true, recursive: true }))
    )
  })

  describe("bounded private controller processes", () => {
    it.each(["success", "failure"] as const)(
      "uses a private 0700 directory and removes every file after %s",
      async (outcome) => {
        let temporary = ""
        const operation = withSignerDirectory(async (path) => {
          temporary = path
          const directoryState = await stat(path)
          expect(directoryState.mode & 0o777).toBe(0o700)
          await writeFile(join(path, "credential"), MARKER, { mode: 0o600 })
          const credentialState = await stat(join(path, "credential"))
          expect(credentialState.mode & 0o777).toBe(0o600)
          if (outcome === "failure") throw new Error("fixture failure")
          return "public certificate"
        })
        const expected = { failure: new Error("fixture failure"), success: "public certificate" }
        expect(await operation.catch((error: unknown) => error)).toStrictEqual(expected[outcome])
        await expect(access(temporary)).rejects.toThrow("ENOENT")
      }
    )

    it("passes literal argv without a shell and excludes ambient credentials, agents and personal CLI contexts", async () => {
      const path = await directory()
      const unwantedFile = join(path, "shell-was-executed")
      const literal = `$(touch ${unwantedFile}); echo unsafe`
      vi.stubEnv("PARATIX_SIGNER_TEST_CREDENTIAL", MARKER)
      vi.stubEnv("SSH_AUTH_SOCK", "/tmp/personal-agent")
      vi.stubEnv("STEPPATH", "/tmp/personal-step-context")
      const value = await signerProcess(
        process.execPath,
        [
          "-e",
          'process.stdin.resume();process.stdin.on("end",()=>console.log(JSON.stringify({arg:process.argv[1],home:process.env.HOME,step:process.env.STEPPATH,ask:process.env.SSH_ASKPASS_REQUIRE,secret:process.env.PARATIX_SIGNER_TEST_CREDENTIAL,agent:process.env.SSH_AUTH_SOCK})))',
          literal,
        ],
        options(path)
      )
      expect(JSON.parse(value)).toStrictEqual({
        arg: literal,
        ask: "never",
        home: path,
        step: path,
      })
      await expect(access(unwantedFile)).rejects.toThrow("ENOENT")
    })

    it("discards controller stderr/stdout, start errors and raw causes on failure", async () => {
      const path = await directory()
      await writeFile(join(path, "credential"), MARKER, { mode: 0o600 })
      const error = await signerProcess(
        process.execPath,
        [
          "-e",
          'const value=require("node:fs").readFileSync("credential");process.stdout.write(value);process.stderr.write(value);process.exit(9)',
        ],
        options(path)
      ).catch((error: unknown) => error)
      assert(error)
      const missing = await signerProcess(
        join(path, "missing-tool"),
        [MARKER],
        options(path)
      ).catch((error: unknown) => error)
      assert(missing)
    })

    it.each(["stdout", "stderr", "combined"])(
      "bounds %s output and kills the request rather than returning partial output",
      async (stream) => {
        let temporary = ""
        const error = await withSignerDirectory(async (path) => {
          temporary = path
          const code =
            stream === "combined"
              ? "process.stdout.write(Buffer.alloc(600000,65));process.stderr.write(Buffer.alloc(600000,66));setInterval(()=>{},1000)"
              : `process.${stream}.write(Buffer.alloc(1048577,65));setInterval(()=>{},1000)`
          return signerProcess(process.execPath, ["-e", code], options(path))
        }).catch((error: unknown) => error)
        expect(error).toBeInstanceOf(HostCertificateError)
        expect(error).toHaveProperty("message", expect.stringContaining("output exceeded limit"))
        await expect(access(temporary)).rejects.toThrow("ENOENT")
      }
    )

    it("does not launch an already aborted request", async () => {
      const path = await directory()
      const controller = new AbortController()
      controller.abort()
      await expect(
        signerProcess(
          process.execPath,
          ["-e", 'require("node:fs").writeFileSync("started","yes")'],
          options(path, controller.signal)
        )
      ).rejects.toThrow("aborted")
      await expect(access(join(path, "started"))).rejects.toThrow("ENOENT")
    })

    it.each(["abort", "timeout"])(
      "terminates an uncooperative process group on %s and cleans all temporary state without retry",
      async (cause) => {
        const observation = await directory()
        const ready = join(observation, "ready.json")
        const attempts = join(observation, "attempts")
        const childCode = `process.on("SIGTERM",()=>{});require("node:fs").writeFileSync(${JSON.stringify(ready)},JSON.stringify([process.ppid,process.pid]));setInterval(()=>{},1000)`
        const code = `require("node:fs").appendFileSync(${JSON.stringify(attempts)},"one-request\\n");process.on("SIGTERM",()=>{});require("node:child_process").spawn(process.execPath,["-e",${JSON.stringify(childCode)}],{stdio:"ignore"});setInterval(()=>{},1000)`
        const controller = new AbortController()
        let temporary = ""
        let timersActive = cause === "timeout"
        // eslint-disable-next-line vitest/no-conditional-in-test -- Only the timeout case advances the controller clock; cancellation uses real timers.
        if (timersActive) vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] })
        const result = withSignerDirectory(async (path) => {
          temporary = path
          await writeFile(join(path, "password"), MARKER, { mode: 0o600 })
          return signerProcess(process.execPath, ["-e", code], options(path, controller.signal))
        }).catch((error: unknown) => error)
        let processIds: number[] = []
        try {
          await vi.waitFor(
            async () => {
              processIds = JSON.parse(await readFile(ready, "utf8"))
              expect(processIds).toHaveLength(2)
            },
            { interval: 20, timeout: 5000 }
          )
          if (cause === "timeout") await vi.advanceTimersByTimeAsync(60_250)
          else controller.abort()
          const error = await result
          assert(error)
          expect(error).toHaveProperty(
            "message",
            expect.stringContaining(
              cause === "timeout" ? "timed out; request outcome may be unknown" : "aborted"
            )
          )
          vi.useRealTimers()
          timersActive = false
          await vi.waitFor(
            () => {
              for (const pid of processIds) expect(() => process.kill(pid, 0)).toThrow("ESRCH")
            },
            { interval: 20, timeout: 5000 }
          )
          expect(await readFile(attempts, "utf8")).toBe("one-request\n")
          await expect(access(temporary)).rejects.toThrow("ENOENT")
        } finally {
          controller.abort()
          if (timersActive) await vi.advanceTimersByTimeAsync(250)
          for (const pid of processIds) {
            try {
              process.kill(pid, "SIGKILL")
            } catch {
              /* Process already ended. */
            }
          }
          await result
        }
      }
    )
  })

  describe("bounded signer output files", () => {
    it("accepts the exact byte limit and rejects oversized or missing files without reading raw diagnostics", async () => {
      const path = await directory()
      const certificate = join(path, "host-cert.pub")
      await writeFile(certificate, "A".repeat(65_536))
      expect(await readSignerCertificate(certificate)).toHaveLength(65_536)
      await writeFile(certificate, MARKER + "A".repeat(65_537))
      const error = await readSignerCertificate(certificate).catch((error: unknown) => error)
      assert(error)
      expect(error).toHaveProperty(
        "message",
        "Controller signer did not produce one readable certificate"
      )
      await expect(readSignerCertificate(join(path, "missing"))).rejects.toThrow(
        "one readable certificate"
      )
    })
  })
})
