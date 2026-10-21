import { describe, expect, it, vi } from "vitest"

import { podman } from "../../src/modules/podman.js"
import { PODMAN_STATUSES, type PodmanStatus } from "../../src/modules/podmanHelpers.js"
import { NEEDS_APPLY } from "../../src/types.js"
import { createMockSsh } from "../helpers/mockSsh.js"

function remote(status: PodmanStatus = "OK") {
  const ssh = createMockSsh()
  vi.spyOn(ssh, "exec").mockResolvedValue({
    code: 80 + PODMAN_STATUSES.indexOf(status),
    stderr: "",
    stdout: "",
  })
  return ssh
}
const options = { passwordEnv: "TOKEN", registry: "registry.example", usernameEnv: "USER" } as const

describe("podman module", () => {
  it("does not resolve credentials without SSH and never exposes them in its name", async () => {
    const user = vi.fn(() => "short")
    const module = podman.login(options)
    expect(module.name).toBe("podman.login")
    await expect(module.check(null, { USER: user })).resolves.toBe(NEEDS_APPLY)
    // eslint-disable-next-line prefer-spread -- Module.apply is the public lifecycle method.
    const result = await module.apply(null, {})
    expect(result.status).toBe("failed")
    expect(user).not.toHaveBeenCalled()
  })

  it("transports credentials only through framed stdin with explicit masks", async () => {
    const ssh = remote("NEEDS_APPLY")
    const module = podman.login(options)
    await expect(module.check(ssh, { TOKEN: "synthetic-token", USER: "u" })).resolves.toBe(
      NEEDS_APPLY
    )
    const [command, execOptions] = vi.mocked(ssh.exec).mock.calls[0]
    expect(command).not.toContain("synthetic-token")
    expect(command).not.toContain('"username":"u"')
    expect(execOptions).toMatchObject({
      ignoreExitCode: true,
      silent: true,
      strictUtf8Stdout: true,
    })
    expect(JSON.parse(String(execOptions?.input))).toStrictEqual({
      password: "synthetic-token",
      username: "u",
      version: 1,
    })
    expect(execOptions?.secrets).toStrictEqual([
      "synthetic-token",
      "u",
      Buffer.from("u:synthetic-token").toString("base64"),
    ])
  })

  it("resolves username before token and refreshes both between check and apply", async () => {
    const chronology: string[] = []
    let token = "first-token"
    const env = {
      TOKEN() {
        chronology.push("token")
        return token
      },
      USER() {
        chronology.push("user")
        return "u"
      },
    }
    const ssh = remote()
    const module = podman.login(options)
    await expect(module.check(ssh, env)).resolves.toBe("ok")
    token = "rotated-token"
    await expect(module.apply(ssh, env)).resolves.toStrictEqual({ status: "ok" })
    expect(chronology).toStrictEqual(["user", "token", "user", "token"])
    expect(vi.mocked(ssh.exec).mock.calls[1][1]?.input).toContain("rotated-token")
  })

  it("maps mutation and logout without requiring credentials", async () => {
    const ssh = remote("CHANGED")
    await expect(podman.logout("docker.io").apply(ssh, {})).resolves.toStrictEqual({
      status: "changed",
    })
    expect(vi.mocked(ssh.exec).mock.calls[0][1]?.input).toBeUndefined()
  })

  it("discards hostile output and exception causes, including short secrets", async () => {
    const ssh = remote()
    vi.spyOn(ssh, "exec").mockRejectedValue(new Error("u synthetic-token"))
    const module = podman.login(options)
    const result = await module.apply(ssh, { TOKEN: "synthetic-token", USER: "u" })
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe("podman: completion is unknown; remote output was discarded")
    expect(result.error?.cause).toBeUndefined()
    await expect(module.check(ssh, { TOKEN: "synthetic-token", USER: "u" })).rejects.toThrow(
      "remote output was discarded"
    )
  })

  it.each([
    "IMAGE_MISSING",
    "UNSAFE_PATH",
    "SELINUX",
    "HELPER_FAILED",
    "HOST_FAILED",
    "CONFLICT",
    "UNKNOWN",
  ] as const)("fails safely for %s", async (status) => {
    const result = await podman
      .login(options)
      .apply(remote(status), { TOKEN: "synthetic-token", USER: "u" })
    expect(result.status).toBe("failed")
    expect(result.error?.cause).toBeUndefined()
  })

  it("rejects successful status values from the wrong phase", async () => {
    await expect(podman.logout("localhost").check(remote("CHANGED"), {})).rejects.toThrow(
      "invalid remote phase"
    )
    const result = await podman.logout("localhost").apply(remote("NEEDS_APPLY"), {})
    expect(result.status).toBe("failed")
  })
})
