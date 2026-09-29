import { spawnSync } from "node:child_process"

import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { InvalidUtf8OutputError } from "../../src/sshHelpers.js"

/**
 * Issue #219: decode a local command's stdout the way the SSH layer does:
 * leniently by default, and with a fatal UTF-8 decoder when the exec asked for
 * `strictUtf8Stdout`, so a smoke test sees the same rejection production
 * would.
 *
 * @param stdout - The raw stdout bytes.
 * @param parameters - Decoding inputs.
 * @param parameters.code - The exit code, for the error message.
 * @param parameters.command - The command, for the error message.
 * @param parameters.strict - Whether stdout must be valid UTF-8.
 * @returns The decoded text.
 * @throws {InvalidUtf8OutputError} When `strict` is set and stdout is not valid UTF-8.
 */
function decodeStdout(
  stdout: Buffer,
  parameters: { code: number; command: string; strict: boolean }
): string {
  if (!parameters.strict) return stdout.toString("utf8")
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(stdout)
  } catch {
    throw new InvalidUtf8OutputError(
      `Command stdout is not valid UTF-8 (exit code ${String(parameters.code)}): ${parameters.command}`
    )
  }
}

/**
 * Issue #219: an `SshConnection` whose `exec` runs the command on the local
 * `/bin/sh`, with `input` on stdin, so a production function can drive its
 * real remote scripts against a temporary directory. It honours
 * `strictUtf8Stdout` like the SSH layer.
 *
 * @param options - Optional settings.
 * @param options.env - The environment of the shell; the test runner's
 *   environment when omitted.
 * @returns The connection and the commands it executed.
 */
export function localShellConnection(options: { env?: NodeJS.ProcessEnv } = {}): {
  commands: string[]
  conn: SshConnection
} {
  const commands: string[] = []
  const conn = {
    async exec(command: string, execOptions?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      commands.push(command)
      const result = spawnSync("/bin/sh", ["-c", command], {
        env: options.env,
        input: execOptions?.input ?? "",
        timeout: 10_000,
      })
      const code = result.status ?? -1
      const stdout = decodeStdout(result.stdout, {
        code,
        command,
        strict: execOptions?.strictUtf8Stdout === true,
      })
      return { code, stderr: result.stderr.toString("utf8"), stdout }
    },
  } as unknown as SshConnection
  return { commands, conn }
}
