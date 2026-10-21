import { describe, expect, it } from "vitest"

import { buildPodmanCommand } from "../../src/modules/podmanContainer.js"
import { configuration } from "../../src/modules/podmanHelpers.js"

const source = {
  authFile: "/root/auth-private/auth.json",
  passwordFile: "/root/token-private/pat",
  passwordFileLocation: "target",
  registry: "localhost:5000",
  username: "u",
} as const

describe("podman container boundary", () => {
  it("restricts helper starts and maps distinct directory mounts without secrets", () => {
    const command = buildPodmanCommand(configuration(source.registry, source, source), "apply")
    for (const option of [
      "--pull=never",
      "--user 0:0",
      "--userns=host",
      "--network=none",
      "--read-only",
      "--read-only-tmpfs=false",
      "--cap-drop=all",
      "no-new-privileges",
      "label=disable",
      "--log-driver=none",
      "/root/token-private:/pat:ro",
      "--compat-auth-file",
      "--password-stdin",
      "--tls-verify=true",
      "O_NOFOLLOW",
      "fsync",
    ])
      expect(command).toContain(option)
    expect(command).not.toContain("--privileged")
    expect(command).not.toContain("--all")
    expect(command).not.toContain("--authfile")
    expect(command).not.toContain(":Z")
    expect(command).not.toContain(":U")
    expect(command).toContain(">/dev/null 2>&1")
    expect(command).toContain("CONFLICT")
  })
  it("check uses read-only auth and no auth-parent creation, host login or snapshot", () => {
    const command = buildPodmanCommand(configuration(source.registry, source, source), "check")
    expect(command).not.toContain("podman login ")
    expect(command).not.toContain("mkdir -m 0700")
    expect(command).not.toContain("work:/work:rw")
    expect(command).toContain("/run/.paratix-auth.")
  })
  it("logout never requests username, password, all-registry deletion or interactive stdin", () => {
    const command = buildPodmanCommand(configuration("docker.io", {}), "apply")
    expect(command).toContain("podman logout --compat-auth-file")
    expect(command).not.toContain("--username")
    expect(command).not.toContain("--password-stdin")
    expect(command).not.toContain("--interactive")
  })
})
