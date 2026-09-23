import {
  execFile,
  type ExecFileOptionsWithStringEncoding,
  execFileSync,
  spawnSync,
} from "node:child_process"
import { generateKeyPairSync } from "node:crypto"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { Server, type ServerChannel } from "ssh2"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

const packageRootDirectory = resolve(import.meta.dirname, "../..")
const CLI_COMMAND_TIMEOUT_MS = 30_000
const CLI_COMMAND_MAX_BUFFER = 10 * 1024 * 1024
const PACKAGE_COMMAND_TIMEOUT_MS = 60_000

const EXPECTED_PACKAGE_EXPORTS = [
  "NEEDS_APPLY",
  "apt",
  "archive",
  "assert",
  "assertValidModuleMetaEntries",
  "assertValidModuleMetaEntry",
  "buildKeyValueDiff",
  "buildUnifiedDiff",
  "command",
  "compose",
  "cron",
  "debug",
  "diffEnvironmentToMetaEntries",
  "download",
  "environmentMeta",
  "environmentToMetaEntries",
  "fail",
  "failed",
  "failedCommand",
  "failedCommandWithDiagnostic",
  "file",
  "firstRun",
  "git",
  "group",
  "hostname",
  "isBooleanEnvironmentMetaEntry",
  "isEnvironmentMetaEntry",
  "isFirstRun",
  "isLazyEnvironmentMetaEntry",
  "isNumberEnvironmentMetaEntry",
  "isSshdPortMetaEntry",
  "isStringEnvironmentMetaEntry",
  "isSystemHostMetaEntry",
  "isSystemRebootMetaEntry",
  "mergeEnvironmentFromMeta",
  "meta",
  "mount",
  "net",
  "op",
  "package",
  "pause",
  "quadlet",
  "recipe",
  "releaseUpgrade",
  "resolveEnvironment",
  "restartSystemdUnit",
  "rsync",
  "script",
  "server",
  "service",
  "shellQuote",
  "signals",
  "ssh",
  "sshd",
  "sshdPortMeta",
  "swap",
  "sysctl",
  "system",
  "systemHostMeta",
  "systemRebootMeta",
  "systemd",
  "timer",
  "ufw",
  "user",
  "when",
] as const

const EXPECTED_MODULE_EXPORTS = [
  "apt",
  "archive",
  "buildKeyValueDiff",
  "buildUnifiedDiff",
  "command",
  "compose",
  "cron",
  "download",
  "file",
  "git",
  "group",
  "hostname",
  "mount",
  "net",
  "op",
  "package",
  "quadlet",
  "releaseUpgrade",
  "restartSystemdUnit",
  "rsync",
  "script",
  "service",
  "ssh",
  "sshd",
  "swap",
  "sysctl",
  "system",
  "systemd",
  "timer",
  "ufw",
  "user",
] as const

const PUBLIC_API_IMPORTS_START = "<!-- public-api-imports:start -->"
const PUBLIC_API_IMPORTS_END = "<!-- public-api-imports:end -->"

type CommandResponse = {
  code: number
  stderr?: string
  stdout?: string
}

type CommandHandler = () => CommandResponse

type TestSshServer = {
  close: () => Promise<void>
  port: number
  privateKey: string
}

function extractPublicApiImports(markdown: string): string {
  const startMarkerOffsets = [...markdown.matchAll(/<!-- public-api-imports:start -->/gv)].map(
    (match) => match.index
  )
  const endMarkerCount = markdown.split(PUBLIC_API_IMPORTS_END).length - 1
  if (startMarkerOffsets.length !== 1 || endMarkerCount !== 1) {
    throw new Error(
      `Expected exactly one public API import marker pair, got ${startMarkerOffsets.length} start and ${endMarkerCount} end markers`
    )
  }

  const startOffset = startMarkerOffsets[0]
  const endOffset = markdown.indexOf(PUBLIC_API_IMPORTS_END)
  if (endOffset <= startOffset) {
    throw new Error("Public API import markers are out of order")
  }

  const markedContent = markdown
    .slice(startOffset + PUBLIC_API_IMPORTS_START.length, endOffset)
    .trim()
  const openingFence = "```typescript\n"
  const closingFence = "\n```"
  if (!markedContent.startsWith(openingFence) || !markedContent.endsWith(closingFence)) {
    throw new Error("Public API import markers must contain exactly one TypeScript block")
  }
  const source = markedContent.slice(openingFence.length, -closingFence.length)
  if (source.includes("```")) {
    throw new Error("Public API import markers contain more than one fenced block")
  }
  return source
}

function endExecStream(stream: ServerChannel, response: CommandResponse): void {
  if (response.stdout != null) stream.write(response.stdout)
  if (response.stderr != null) stream.stderr.write(response.stderr)
  stream.exit(response.code)
  stream.end()
}

function handlePostbuildCommand(input: {
  command: string
  commandHandlers: Map<string, CommandHandler>
  unexpectedCommands: string[]
}): CommandResponse {
  const handler = input.commandHandlers.get(input.command)
  if (handler != null) return handler()
  input.unexpectedCommands.push(input.command)
  return {
    code: 127,
    stderr: `unexpected postbuild SSH command: ${input.command}\n`,
  }
}

async function execFileBuffered(
  file: string,
  args: string[],
  options: ExecFileOptionsWithStringEncoding
): Promise<string> {
  return new Promise<string>((resolveExec, rejectExec) => {
    execFile(file, args, options, (error, stdout) => {
      if (error == null) resolveExec(stdout)
      else rejectExec(new Error(error.message, { cause: error }))
    })
  })
}

async function startTestSshServer(
  handleCommand: (command: string) => CommandResponse
): Promise<TestSshServer> {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    client.on("authentication", (context) => {
      if (context.method === "publickey") context.accept()
      else context.reject()
    })
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept()
        session.on("exec", (acceptExec, _rejectExec, info) => {
          endExecStream(acceptExec(), handleCommand(info.command))
        })
      })
    })
  })

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen)
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen)
      resolveListen()
    })
  })

  const address = server.address()
  if (address == null || typeof address === "string") {
    throw new Error("test SSH server did not expose a TCP address")
  }

  return {
    async close() {
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => {
          if (error == null) resolveClose()
          else rejectClose(error)
        })
      })
    },
    port: address.port,
    privateKey,
  }
}

describe("dist CLI", () => {
  let packedPackageRootDirectory: string
  let packedTempDirectory: string
  let packedTarballEntries: string[]

  beforeAll(() => {
    packedTempDirectory = mkdtempSync(join(tmpdir(), "paratix-packed-package-"))
    packedPackageRootDirectory = join(packedTempDirectory, "node_modules", "paratix")
    mkdirSync(packedPackageRootDirectory, { recursive: true })
    linkRuntimeDependencies(packedTempDirectory)

    const packResult = spawnSync(
      "pnpm",
      ["pack", "--pack-destination", packedTempDirectory, "--json"],
      {
        cwd: packageRootDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      }
    )
    if (packResult.status !== 0) {
      throw new Error(`pnpm pack failed:\n${packResult.stderr}`)
    }

    const packOutput = JSON.parse(packResult.stdout) as
      { filename: string } | Array<{ filename: string }>
    const packEntries = Array.isArray(packOutput) ? packOutput : [packOutput]
    if (packEntries.length !== 1) {
      throw new Error(`Expected pnpm pack to produce one tarball, got ${packEntries.length}`)
    }
    const packedTarballPath = resolve(packedTempDirectory, packEntries[0].filename)

    const listResult = spawnSync("tar", ["-tzf", packedTarballPath], {
      cwd: packedTempDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      maxBuffer: CLI_COMMAND_MAX_BUFFER,
      timeout: PACKAGE_COMMAND_TIMEOUT_MS,
    })
    if (listResult.status !== 0) {
      throw new Error(`tar listing failed:\n${listResult.stderr}`)
    }
    packedTarballEntries = listResult.stdout.trim().split("\n").sort()

    const extractResult = spawnSync(
      "tar",
      ["-xzf", packedTarballPath, "--strip-components", "1", "-C", packedPackageRootDirectory],
      {
        cwd: packedTempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      }
    )
    if (extractResult.status !== 0) {
      throw new Error(`tar extraction failed:\n${extractResult.stderr}`)
    }
  })

  afterAll(() => {
    rmSync(packedTempDirectory, { force: true, recursive: true })
  })

  it("packs the required published CLI files and excludes source-only files", () => {
    expect(packedTarballEntries).toStrictEqual(
      expect.arrayContaining([
        "package/dist/cli.js",
        "package/dist/index.js",
        "package/package.json",
      ])
    )
    expect(packedTarballEntries.some((entry) => entry.startsWith("package/src/"))).toBe(false)
    expect(packedTarballEntries.some((entry) => entry.startsWith("package/test/"))).toBe(false)
  })

  it("publishes exactly the two supported package entry points", () => {
    const packageJson = JSON.parse(
      readFileSync(join(packedPackageRootDirectory, "package.json"), "utf8")
    ) as {
      exports: Record<string, string>
    }

    expect(packageJson.exports).toStrictEqual({
      ".": "./dist/index.js",
      "./modules": "./dist/modules/index.js",
    })
  })

  it("runs the published CLI for version and apply validation errors", () => {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
      version: string
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin.paratix)
    const firstLine = readFileSync(distCliPath, "utf8").split("\n")[0]
    expect(firstLine).toBe("#!/usr/bin/env node")

    const versionOutput = execFileSync(process.execPath, [distCliPath, "--version"], {
      cwd: packageRootDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      maxBuffer: CLI_COMMAND_MAX_BUFFER,
      timeout: CLI_COMMAND_TIMEOUT_MS,
    }).trim()
    // eslint-disable-next-line security/detect-non-literal-regexp -- package version comes from local package.json
    expect(versionOutput).toMatch(new RegExp(`^${packageJson.version}(?:-[0-9a-f]{7,})?$`, "v"))

    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-dist-"))
    const invalidPlaybookPath = join(tempDirectory, "invalid.mjs")
    try {
      writeFileSync(invalidPlaybookPath, "export default {}\n")
      expect(() =>
        execFileSync(process.execPath, [distCliPath, "apply", invalidPlaybookPath, "--dry-run"], {
          cwd: packageRootDirectory,
          encoding: "utf8",
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          stdio: "pipe",
          timeout: CLI_COMMAND_TIMEOUT_MS,
        })
      ).toThrow(/does not export a valid ServerDefinition[\s\S]*Missing property 'name'/v)
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("surfaces every apply option in the top-level --help output", () => {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin.paratix)

    const helpOutput = execFileSync(process.execPath, [distCliPath, "--help"], {
      cwd: packageRootDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      maxBuffer: CLI_COMMAND_MAX_BUFFER,
      timeout: CLI_COMMAND_TIMEOUT_MS,
    })

    expect(helpOutput).toContain('Options for "paratix apply <file>":')
    for (const flag of [
      "--diff",
      "--dry-run",
      "--env <key=value...>",
      "--env-file <path>",
      "--filter <names>",
      "--first-run",
      "--reconnect-timeout <seconds>",
      "--verbose",
    ]) {
      expect(helpOutput).toContain(flag)
    }
  })

  it("reports authentication errors for a valid playbook before apply can run", () => {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin.paratix)
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-apply-dist-"))
    const playbookPath = join(tempDirectory, "valid-playbook.mjs")

    try {
      writeFileSync(
        playbookPath,
        `
export default {
  name: "dist-apply-smoke",
  host: "127.0.0.1",
  ssh: {
    ports: [65535],
    strictHostKeyChecking: "no",
    user: "root",
  },
  run: [
    {
      name: "dist local apply module",
      local: true,
      async check(ssh) {
        if (ssh !== null) throw new Error("local check received an SSH connection")
        return "needs-apply"
      },
      async apply(ssh) {
        if (ssh !== null) throw new Error("local apply received an SSH connection")
        return { status: "changed", detail: "local smoke" }
      },
    },
  ],
}
`
      )

      expect(() =>
        execFileSync(process.execPath, [distCliPath, "apply", playbookPath], {
          cwd: packageRootDirectory,
          encoding: "utf8",
          env: { ...process.env, SSH_AUTH_SOCK: "" },
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          stdio: "pipe",
          timeout: CLI_COMMAND_TIMEOUT_MS,
        })
      ).toThrow(/No privateKey configured and SSH_AUTH_SOCK is not set/v)
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("applies a valid playbook through the published apply CLI", async () => {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin.paratix)
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-apply-dist-"))
    const privateKeyPath = join(tempDirectory, "id_rsa")
    const playbookPath = join(tempDirectory, "valid-playbook.mjs")
    const markerPath = join(tempDirectory, "remote-marker.txt")
    const seenCommands: string[] = []
    const unexpectedCommands: string[] = []
    const checkCommand = `test -f ${JSON.stringify(markerPath)}`
    const applyCommand = `printf 'changed\\n' > ${JSON.stringify(markerPath)}`
    const commandHandlers = new Map<string, CommandHandler>([
      [
        applyCommand,
        () => {
          writeFileSync(markerPath, "changed\n")
          return { code: 0 }
        },
      ],
      [checkCommand, () => ({ code: 1 })],
    ])

    const testServer = await startTestSshServer((command) => {
      seenCommands.push(command)
      return handlePostbuildCommand({ command, commandHandlers, unexpectedCommands })
    })

    try {
      writeFileSync(privateKeyPath, testServer.privateKey, { mode: 0o600 })
      writeFileSync(
        playbookPath,
        `
export default {
  name: "dist-apply-success",
  host: "127.0.0.1",
  ssh: {
    ports: [${String(testServer.port)}],
    privateKey: ${JSON.stringify(privateKeyPath)},
    strictHostKeyChecking: "no",
    user: "root",
  },
  run: [
    {
      name: "dist remote apply module",
      async check(ssh) {
        const result = await ssh.exec(${JSON.stringify(checkCommand)}, { ignoreExitCode: true, silent: true })
        return result.code === 0 ? "ok" : "needs-apply"
      },
      async apply(ssh) {
        await ssh.exec(${JSON.stringify(applyCommand)}, { silent: true })
        return { status: "changed", detail: "remote smoke" }
      },
    },
  ],
}
`
      )

      const stdout = await execFileBuffered(
        process.execPath,
        [distCliPath, "apply", playbookPath],
        {
          cwd: packageRootDirectory,
          encoding: "utf8",
          env: { ...process.env, SSH_AUTH_SOCK: "" },
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          timeout: CLI_COMMAND_TIMEOUT_MS,
        }
      )

      expect(stdout).toContain("dist remote apply module")
      expect(stdout).toContain("changed")
      expect(readFileSync(markerPath, "utf8")).toBe("changed\n")
      expect(seenCommands).toStrictEqual([checkCommand, applyCommand])
      expect(unexpectedCommands).toStrictEqual([])
    } finally {
      await testServer.close()
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("loads a TypeScript playbook through the published apply CLI in dry-run mode", async () => {
    const packageJson = JSON.parse(
      readFileSync(join(packedPackageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
    }
    const packedCliPath = resolve(packedPackageRootDirectory, packageJson.bin.paratix)
    const firstLine = readFileSync(packedCliPath, "utf8").split("\n")[0]
    expect(firstLine).toBe("#!/usr/bin/env node")

    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-ts-dist-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    const privateKeyPath = join(tempDirectory, "id_rsa")
    const playbookPath = join(tempDirectory, "valid-playbook.ts")
    const markerPath = join(tempDirectory, "remote-marker.txt")
    const seenCommands: string[] = []
    const unexpectedCommands: string[] = []
    const checkCommand = `test -f ${JSON.stringify(markerPath)}`
    const applyCommand = `printf 'changed\\n' > ${JSON.stringify(markerPath)}`
    const commandHandlers = new Map<string, CommandHandler>([
      [
        applyCommand,
        () => {
          writeFileSync(markerPath, "changed\n")
          return { code: 0 }
        },
      ],
      [checkCommand, () => ({ code: 1 })],
    ])

    const testServer = await startTestSshServer((command) => {
      seenCommands.push(command)
      return handlePostbuildCommand({ command, commandHandlers, unexpectedCommands })
    })

    try {
      mkdirSync(nodeModulesDirectory)
      symlinkSync(packedPackageRootDirectory, join(nodeModulesDirectory, "paratix"))
      writeFileSync(privateKeyPath, testServer.privateKey, { mode: 0o600 })
      writeFileSync(join(tempDirectory, "package.json"), `${JSON.stringify({ type: "module" })}\n`)
      writeFileSync(
        playbookPath,
        `
import { server } from "paratix"
import { command } from "paratix/modules"

export default server({
  name: "dist-ts-dry-run",
  host: "127.0.0.1",
  ssh: {
    ports: [${String(testServer.port)}],
    privateKey: ${JSON.stringify(privateKeyPath)},
    strictHostKeyChecking: "no",
    user: "root",
  },
  run: [
    command.shell(${JSON.stringify(applyCommand)}, {
      check: ${JSON.stringify(checkCommand)},
      name: "dist TypeScript dry-run module",
    }),
  ],
})
`
      )

      const stdout = await execFileBuffered(packedCliPath, ["apply", playbookPath, "--dry-run"], {
        cwd: tempDirectory,
        encoding: "utf8",
        env: { ...process.env, SSH_AUTH_SOCK: "" },
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: CLI_COMMAND_TIMEOUT_MS,
      })

      expect(stdout).toContain("dist TypeScript dry-run module")
      expect(stdout).toContain("(dry-run)")
      expect(existsSync(markerPath)).toBe(false)
      expect(seenCommands).toStrictEqual([checkCommand])
      expect(unexpectedCommands).toStrictEqual([])
    } finally {
      await testServer.close()
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("exports resolveEnvironment from the published package entry point", async () => {
    const distIndexUrl = pathToFileURL(resolve(packageRootDirectory, "dist/index.js")).href
    const { resolveEnvironment } = (await import(distIndexUrl)) as {
      resolveEnvironment: (environment: Record<string, unknown>, key: string) => Promise<unknown>
    }

    await expect(
      resolveEnvironment(
        {
          async SECRET() {
            await Promise.resolve()
            return "resolved-secret"
          },
        },
        "SECRET"
      )
    ).resolves.toBe("resolved-secret")
  })

  it("publishes the complete runtime APIs with identical module re-exports", async () => {
    const distIndexUrl = pathToFileURL(resolve(packedPackageRootDirectory, "dist/index.js")).href
    const distModulesUrl = pathToFileURL(
      resolve(packedPackageRootDirectory, "dist/modules/index.js")
    ).href
    const packageApi = (await import(distIndexUrl)) as Record<string, unknown>
    const moduleApi = (await import(distModulesUrl)) as Record<string, unknown>

    expect(Object.keys(packageApi).sort()).toStrictEqual(EXPECTED_PACKAGE_EXPORTS)
    expect(Object.keys(moduleApi).sort()).toStrictEqual(EXPECTED_MODULE_EXPORTS)

    for (const exportName of EXPECTED_MODULE_EXPORTS) {
      expect(packageApi, `missing dist root built-in export: ${exportName}`).toHaveProperty(
        exportName
      )
      expect(packageApi[exportName]).toBe(moduleApi[exportName])
    }
  })

  it("type-checks the marked guide imports unchanged in an isolated NodeNext consumer", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-guide-imports-dist-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    const emptyTypeRootsDirectory = join(tempDirectory, "empty-types")
    const consumerSourcePath = join(tempDirectory, "consumer.ts")

    try {
      mkdirSync(nodeModulesDirectory)
      mkdirSync(emptyTypeRootsDirectory)
      symlinkSync(packedPackageRootDirectory, join(nodeModulesDirectory, "paratix"))
      writeFileSync(join(tempDirectory, "package.json"), '{ "type": "module" }\n')
      writeFileSync(
        join(tempDirectory, "tsconfig.json"),
        `${JSON.stringify(
          {
            compilerOptions: {
              module: "NodeNext",
              moduleResolution: "NodeNext",
              noEmit: true,
              skipLibCheck: false,
              strict: true,
              target: "ES2022",
              typeRoots: ["./empty-types"],
              types: [],
            },
            include: ["consumer.ts"],
          },
          null,
          2
        )}\n`
      )

      const packedGuide = readFileSync(join(packedPackageRootDirectory, "llm-guide.md"), "utf8")
      const publicApiImports = extractPublicApiImports(packedGuide)
      writeFileSync(consumerSourcePath, publicApiImports)
      expect(readFileSync(consumerSourcePath, "utf8")).toBe(publicApiImports)

      execFileSync(resolve(packageRootDirectory, "../../node_modules/.bin/tsc"), ["-p", "."], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      })
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("supports package specifier imports from a consumer project", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-consumer-dist-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    const consumerPackageDirectory = join(nodeModulesDirectory, "paratix")
    const consumerScriptPath = join(tempDirectory, "consumer.mjs")

    try {
      execFileSync("pnpm", ["pack", "--pack-destination", tempDirectory], {
        cwd: packageRootDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      })

      const packageTarball = readdirSync(tempDirectory).find((entry) => entry.endsWith(".tgz"))
      expect(packageTarball).toBeDefined()

      mkdirSync(consumerPackageDirectory, { recursive: true })
      execFileSync(
        "tar",
        [
          "-xzf",
          join(tempDirectory, packageTarball!),
          "-C",
          consumerPackageDirectory,
          "--strip-components=1",
        ],
        {
          cwd: tempDirectory,
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          timeout: PACKAGE_COMMAND_TIMEOUT_MS,
        }
      )

      const packedPackageJson = JSON.parse(
        readFileSync(join(consumerPackageDirectory, "package.json"), "utf8")
      ) as {
        bin: { paratix: string }
        dependencies: Record<string, string>
        version: string
      }
      for (const dependencyName of Object.keys(packedPackageJson.dependencies)) {
        const dependencyTarget = join(packageRootDirectory, "node_modules", dependencyName)
        const dependencyLink = join(nodeModulesDirectory, dependencyName)
        mkdirSync(dirname(dependencyLink), { recursive: true })
        symlinkSync(dependencyTarget, dependencyLink)
      }

      const packedBinaryPath = join(consumerPackageDirectory, packedPackageJson.bin.paratix)
      const packedBinaryVersion = execFileSync(packedBinaryPath, ["--version"], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: CLI_COMMAND_TIMEOUT_MS,
      }).trim()
      expect(packedBinaryVersion).toMatch(
        // eslint-disable-next-line security/detect-non-literal-regexp -- packed package version comes from local package.json
        new RegExp(`^${packedPackageJson.version}(?:-[0-9a-f]{7,})?$`, "v")
      )

      writeFileSync(join(tempDirectory, "package.json"), '{ "type": "module" }\n')
      writeFileSync(
        consumerScriptPath,
        `
import { resolveEnvironment } from "paratix"
import { file, package as pkg, service, swap, timer } from "paratix/modules"
import { swap as rootSwap, timer as rootTimer } from "paratix"

if (typeof resolveEnvironment !== "function") {
  throw new Error("paratix did not export resolveEnvironment")
}
if (typeof file?.directory !== "function") {
  throw new Error("paratix/modules did not export file.directory")
}
if (typeof pkg?.installed !== "function") {
  throw new Error("paratix/modules did not export package.installed")
}
if (typeof service?.enabled !== "function") {
  throw new Error("paratix/modules did not export service.enabled")
}
if (rootSwap !== swap || typeof rootSwap?.file !== "function") {
  throw new Error("paratix did not re-export swap from paratix/modules")
}
if (rootTimer !== timer || typeof rootTimer?.scheduled !== "function") {
  throw new Error("paratix did not re-export timer from paratix/modules")
}

const resolved = await resolveEnvironment({ async SECRET() { return "resolved-secret" } }, "SECRET")
if (resolved !== "resolved-secret") {
  throw new Error("resolveEnvironment did not resolve lazy consumer values")
}

const modules = [
  file.directory("/tmp/paratix-consumer-test"),
  pkg.installed("curl"),
  service.enabled("ssh"),
]
for (const module of modules) {
  if (typeof module.name !== "string" || typeof module.check !== "function" || typeof module.apply !== "function") {
    throw new Error("module export did not create a valid runtime module")
  }
}

console.log("consumer imports ok")
`
      )

      const output = execFileSync(process.execPath, [consumerScriptPath], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: CLI_COMMAND_TIMEOUT_MS,
      }).trim()

      expect(output).toBe("consumer imports ok")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("type-checks public declarations in an isolated NodeNext consumer without NodeJS globals", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-consumer-types-dist-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    const consumerPackageDirectory = join(nodeModulesDirectory, "paratix")
    const emptyTypeRootsDirectory = join(tempDirectory, "empty-types")
    const consumerSourcePath = join(tempDirectory, "consumer.ts")

    try {
      execFileSync("pnpm", ["pack", "--pack-destination", tempDirectory], {
        cwd: packageRootDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      })

      const packageTarball = readdirSync(tempDirectory).find((entry) => entry.endsWith(".tgz"))
      expect(packageTarball).toBeDefined()

      mkdirSync(consumerPackageDirectory, { recursive: true })
      mkdirSync(emptyTypeRootsDirectory)
      execFileSync(
        "tar",
        [
          "-xzf",
          join(tempDirectory, packageTarball!),
          "-C",
          consumerPackageDirectory,
          "--strip-components=1",
        ],
        {
          cwd: tempDirectory,
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          timeout: PACKAGE_COMMAND_TIMEOUT_MS,
        }
      )

      const packedPackageJson = JSON.parse(
        readFileSync(join(consumerPackageDirectory, "package.json"), "utf8")
      ) as {
        dependencies: Record<string, string>
      }
      for (const dependencyName of Object.keys(packedPackageJson.dependencies)) {
        const dependencyTarget = join(packageRootDirectory, "node_modules", dependencyName)
        const dependencyLink = join(nodeModulesDirectory, dependencyName)
        mkdirSync(dirname(dependencyLink), { recursive: true })
        symlinkSync(dependencyTarget, dependencyLink)
      }

      writeFileSync(join(tempDirectory, "package.json"), '{ "type": "module" }\n')
      writeFileSync(
        join(tempDirectory, "tsconfig.json"),
        `${JSON.stringify(
          {
            compilerOptions: {
              module: "NodeNext",
              moduleResolution: "NodeNext",
              noEmit: true,
              skipLibCheck: false,
              strict: true,
              target: "ES2022",
              typeRoots: ["./empty-types"],
              types: [],
            },
            include: ["consumer.ts"],
          },
          null,
          2
        )}\n`
      )
      writeFileSync(
        consumerSourcePath,
        `
import {
  assertValidModuleMetaEntries,
  assertValidModuleMetaEntry,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  failedCommandWithDiagnostic,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isFirstRun,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
  recipe,
  sshdPortMeta,
  systemHostMeta,
  systemRebootMeta,
  type Environment,
  type EnvironmentMetaEntry,
  type EnvironmentValue,
  type ExecOptions,
  type ExecResult,
  type MetaEnvironmentValue,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  type ServerDefinition,
  type ShutdownSignal,
  type SshConfig,
  type SshConnection,
  type SshdPortMetaEntry,
  type SystemHostMetaEntry,
  type SystemRebootMetaEntry,
  type UnifiedDiffOptions,
} from "paratix"
import {
  apt,
  archive,
  buildKeyValueDiff,
  buildUnifiedDiff,
  command,
  compose,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  net,
  op,
  package as pkg,
  quadlet,
  releaseUpgrade,
  restartSystemdUnit,
  rsync,
  script,
  service,
  ssh,
  sshd,
  swap,
  sysctl,
  system,
  systemd,
  timer,
  ufw,
  user,
  type PackageSpec,
  type UnifiedDiffOptions as ModulesUnifiedDiffOptions,
  type UpgradeOptions,
} from "paratix/modules"

const failedCommandWithDiagnosticSignature: (parameters: {
  diagnostic: null | string
  message: string
  result: ExecResult
  secrets?: string[]
}) => ModuleResult = failedCommandWithDiagnostic
const buildUnifiedDiffSignature: (
  current: string,
  desired: string,
  options?: UnifiedDiffOptions
) => string = buildUnifiedDiff
const buildKeyValueDiffSignature: (
  key: string,
  currentValue: null | string,
  desiredValue: string
) => string = buildKeyValueDiff
const restartSystemdUnitSignature: (parameters: {
  failureMessage: string
  secrets?: string[]
  ssh: SshConnection
  unit: string
}) => Promise<ModuleResult | null> = restartSystemdUnit

const rootDiffOptions: UnifiedDiffOptions = {
  contextLines: 2,
  currentLabel: "current",
  desiredLabel: "desired",
}
const modulesDiffOptions: ModulesUnifiedDiffOptions = rootDiffOptions
const roundTrippedDiffOptions: UnifiedDiffOptions = modulesDiffOptions
void [
  failedCommandWithDiagnosticSignature,
  buildUnifiedDiffSignature,
  buildKeyValueDiffSignature,
  restartSystemdUnitSignature,
  roundTrippedDiffOptions,
]

type IsExact<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? (<Value>() => Value extends Right ? 1 : 2) extends
        (<Value>() => Value extends Left ? 1 : 2)
      ? true
      : false
    : false
type Expect<Condition extends true> = Condition

type PublicTypeContract = {
  environment: Environment
  environmentMetaEntry: EnvironmentMetaEntry
  environmentValue: EnvironmentValue
  execOptions: ExecOptions
  execResult: ExecResult
  metaEnvironmentValue: MetaEnvironmentValue
  module: Module
  moduleMetaEntry: ModuleMetaEntry
  moduleResult: ModuleResult
  serverDefinition: ServerDefinition
  shutdownSignal: ShutdownSignal
  sshConfig: SshConfig
  sshConnection: SshConnection
  sshdPortMetaEntry: SshdPortMetaEntry
  systemHostMetaEntry: SystemHostMetaEntry
  systemRebootMetaEntry: SystemRebootMetaEntry
}

type ExpectedConnectionInfo = {
  agentSocket?: string
  authMethod?: "agent" | "password" | "privateKey"
  configuredPorts: number[]
  host: string
  port: number
  privateKeyPath?: string
  user: string
  verifiedHostPublicKey?: string
}

type AddPortContract = Expect<IsExact<SshConnection["addPort"], (port: number) => boolean>>
type ReconnectContract = Expect<
  IsExact<
    SshConnection["reconnect"],
    (options?: { defaultTimeout?: number }) => Promise<void>
  >
>
type RemovePortContract = Expect<IsExact<SshConnection["removePort"], (port: number) => void>>
type ConnectionInfoContract = Expect<
  IsExact<ReturnType<SshConnection["getConnectionInfo"]>, ExpectedConnectionInfo>
>

declare const publicTypes: PublicTypeContract
declare const sshContracts: [
  AddPortContract,
  ConnectionInfoContract,
  ReconnectContract,
  RemovePortContract,
]
void publicTypes
void sshContracts

const packageSpec: PackageSpec = { name: "curl", version: "8.0.0" }
const upgradeOptions: UpgradeOptions = { timeout: 30_000 }
void packageSpec
void upgradeOptions

const builtInModules = [
  apt,
  archive,
  command,
  compose,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  net,
  op,
  pkg,
  quadlet,
  releaseUpgrade,
  rsync,
  script,
  service,
  ssh,
  sshd,
  swap,
  sysctl,
  system,
  systemd,
  timer,
  ufw,
  user,
] as const
void builtInModules

const publicMetaApi = [
  assertValidModuleMetaEntries,
  assertValidModuleMetaEntry,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
  sshdPortMeta,
  systemHostMeta,
  systemRebootMeta,
] as const
const firstRunFlag: boolean = isFirstRun()
void publicMetaApi
void firstRunFlag

const moduleWithOptions: Module = {
  name: "typed public module",
  async check() {
    return "ok"
  },
  async apply(_ssh, _environment, options) {
    const signal: ShutdownSignal | null = options?.shutdownSignal?.() ?? null
    return { status: signal === "SIGTERM" ? "skipped" : "ok" }
  },
}

const grouped = recipe("typed public recipe", [moduleWithOptions])
void grouped
`
      )

      execFileSync(resolve(packageRootDirectory, "../../node_modules/.bin/tsc"), ["-p", "."], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      })
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })
})

function linkRuntimeDependencies(tempDirectory: string): void {
  const packageJson = JSON.parse(
    readFileSync(join(packageRootDirectory, "package.json"), "utf8")
  ) as {
    dependencies: Record<string, string>
  }

  for (const dependencyName of Object.keys(packageJson.dependencies)) {
    const dependencyRootDirectory = join(packageRootDirectory, "node_modules", dependencyName)
    const dependencyLink = join(tempDirectory, "node_modules", dependencyName)
    mkdirSync(dirname(dependencyLink), { recursive: true })
    symlinkSync(dependencyRootDirectory, dependencyLink)
  }
}
