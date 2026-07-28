import { describe, expect, it, vi } from "vitest"

import type { Environment } from "../../src/types.js"

import { quadlet } from "../../src/modules/quadlet.js"
import {
  buildQuadletConflictInspectCommand,
  resolveQuadletContainerName,
} from "../../src/modules/quadletConflictGuard.js"
import { createQuadletMockSsh } from "../helpers/mockQuadletSsh.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv: Environment = {}
const NAME = "dependency-track-postgres"
const CONTAINER = `systemd-${NAME}`
const INSPECT = buildQuadletConflictInspectCommand(CONTAINER)
const SEPARATOR = "@@PARATIX-ENV@@"

function inspectOutput(parameters: { environment?: string[]; labels?: string[] }): string {
  return [...(parameters.labels ?? []), SEPARATOR, ...(parameters.environment ?? [])].join("\n")
}

function updateImageModule(): ReturnType<typeof quadlet.updateImage> {
  return quadlet.updateImage({ image: "docker.io/library/postgres:17", name: NAME })
}

function containerModule(): ReturnType<typeof quadlet.container> {
  return quadlet.container({ image: "docker.io/library/postgres:17", name: NAME })
}

describe("resolveQuadletContainerName", () => {
  it("mirrors Quadlet's systemd- prefix default", () => {
    expect(resolveQuadletContainerName({ name: "web" })).toBe("systemd-web")
  })

  it("prefers an explicit container name", () => {
    expect(resolveQuadletContainerName({ containerName: "legacy-web", name: "web" })).toBe(
      "legacy-web"
    )
  })
})

describe("quadlet.updateImage conflict guard", () => {
  it("fails before any pull when a Compose project label owns the container", async () => {
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ labels: ["com.docker.compose.project=dependency-track"] }),
      },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`container '${CONTAINER}' already exists`)
    expect(result.error?.message).toContain("com.docker.compose.project=dependency-track")
    // The guard must run before the pull, so no image work happens at all.
    expect(ssh.calls).toStrictEqual([INSPECT])
  })

  it("detects the podman-compose label variant", async () => {
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ labels: ["io.podman.compose.project=dependency-track"] }),
      },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("io.podman.compose.project=dependency-track")
  })

  it("fails when PODMAN_SYSTEMD_UNIT names a different unit", async () => {
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ environment: ["PODMAN_SYSTEMD_UNIT=other-stack.service"] }),
      },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("PODMAN_SYSTEMD_UNIT=other-stack.service")
  })

  it("does not flag the unit's own container despite the .service suffix", async () => {
    // Regression guard: PODMAN_SYSTEMD_UNIT carries `%n`, the full unit name,
    // while the module holds the bare name. A naive comparison would classify
    // the unit's own container as foreign and block every apply.
    const ssh = createQuadletMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ environment: [`PODMAN_SYSTEMD_UNIT=${NAME}.service`] }),
      },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/postgres:17'":
        { code: 0, stdout: "sha256:same\n" },
      "podman pull -- 'docker.io/library/postgres:17'": { code: 0, stdout: "up to date" },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
  })

  it("treats a container without ownership metadata as no conflict", async () => {
    const ssh = createQuadletMockSsh({
      [INSPECT]: { code: 0, stdout: inspectOutput({ labels: ["maintainer=someone"] }) },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/postgres:17'":
        { code: 0, stdout: "sha256:same\n" },
      "podman pull -- 'docker.io/library/postgres:17'": { code: 0, stdout: "up to date" },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    // Fail open: an unrecognized owner never blocks the apply.
    expect(result.status).toBe("ok")
  })

  it("treats an absent container as no conflict", async () => {
    const ssh = createMockSsh({
      [INSPECT]: { code: 1, stderr: "no such container" },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/postgres:17'":
        { code: 0, stdout: "sha256:same\n" },
      "podman pull -- 'docker.io/library/postgres:17'": { code: 0, stdout: "up to date" },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
  })

  it("leaves the apply unchanged when the probe itself fails", async () => {
    const ssh = createMockSsh({
      [INSPECT]: { code: 125, stderr: "permission denied" },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/postgres:17'":
        { code: 0, stdout: "sha256:same\n" },
      "podman pull -- 'docker.io/library/postgres:17'": { code: 0, stdout: "up to date" },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    // A probe problem must never turn into a rollout failure.
    expect(result.status).toBe("ok")
  })

  it("ignores an unparseable inspect projection", async () => {
    const ssh = createQuadletMockSsh({
      [INSPECT]: { code: 0, stdout: "totally unexpected output" },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/postgres:17'":
        { code: 0, stdout: "sha256:same\n" },
      "podman pull -- 'docker.io/library/postgres:17'": { code: 0, stdout: "up to date" },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
  })

  it("guards a conflict even when the image did not change", async () => {
    // Before the guard this path returned `ok` while a foreign container was the
    // one actually running — the state a re-run does not heal.
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ labels: ["com.docker.compose.project=dependency-track"] }),
      },
    })

    const result = await updateImageModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain("podman pull -- 'docker.io/library/postgres:17'")
  })

  it("inspects the explicit container name when one is configured", async () => {
    const explicitInspect = buildQuadletConflictInspectCommand("legacy-postgres")
    const ssh = createMockSsh({
      [explicitInspect]: {
        code: 0,
        stdout: inspectOutput({ labels: ["com.docker.compose.project=dependency-track"] }),
      },
    })

    const result = await quadlet
      .updateImage({ containerName: "legacy-postgres", image: "x:1", name: NAME })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("legacy-postgres")
  })
})

describe("quadlet.container conflict guard", () => {
  it("fails before writing the unit file when a foreign container holds the name", async () => {
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ labels: ["com.docker.compose.project=dependency-track"] }),
      },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await containerModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`[quadlet.container: ${NAME}]`)
    expect(writeFile).not.toHaveBeenCalled()
    expect(ssh.calls).toStrictEqual([INSPECT])
  })

  it("runs the guard in a plain dry run without --diff", async () => {
    const ssh = createMockSsh({
      [INSPECT]: {
        code: 0,
        stdout: inspectOutput({ environment: ["PODMAN_SYSTEMD_UNIT=other-stack.service"] }),
      },
    })

    const module = containerModule()
    const result = await module._applyDryRun!(ssh, emptyEnv)

    expect(module._dryRunBlocker).toBe(true)
    expect(result.status).toBe("failed")
    // No diff round-trips and no mutation without `--diff`.
    expect(ssh.calls).toStrictEqual([INSPECT])
  })

  it("does not produce a diff without --diff", async () => {
    const ssh = createQuadletMockSsh({}, { allowUnstubbedDefaults: true, defaultTestResult: true })

    const result = await containerModule()._applyDryRun!(ssh, emptyEnv)

    expect(result.diff).toBeUndefined()
    expect(ssh.calls).not.toContain(`cat '/etc/containers/systemd/${NAME}.container'`)
  })
})
