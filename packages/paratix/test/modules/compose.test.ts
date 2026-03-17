import type * as NodeFsPromises from "node:fs/promises"

import { describe, expect, it, vi } from "vitest"

import { compose } from "../../src/modules/compose.js"
import { createMockSsh } from "../helpers/mockSsh.js"

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeFsPromises>()
  return { ...actual, readFile: vi.fn(actual.readFile) }
})

const emptyEnv = {}

const projectDirectory = "/opt/app"

// cspell:ignore podman

// Helper: build the compose command prefix for a given runtime
function composeCmd(runtime: "docker" | "podman"): string {
  return `${runtime} compose --project-directory '${projectDirectory}'`
}

// ─── compose.up ──────────────────────────────────────────────────────────────

describe("compose.up — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ps returns empty stdout", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "" },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when all containers are running (array JSON)", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: {
        code: 0,
        stdout: JSON.stringify([{ State: "running" }, { State: "running" }]),
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when all containers are running (newline-delimited JSON)", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: {
        code: 0,
        stdout: `{"State":"running"}\n{"State":"running"}`,
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when some containers are not running", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: {
        code: 0,
        stdout: JSON.stringify([{ State: "running" }, { State: "exited" }]),
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ps command fails (non-zero exit code)", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("compose.up — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed on successful up", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} up -d`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("includes services in command when services list is provided", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} up -d 'web' 'db'`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory, services: ["web", "db"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} up -d 'web' 'db'`)
  })

  it("uses docker when only docker is available", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("docker")} up -d`]: { code: 0 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("docker")} up -d`)
  })

  it("returns failed when up command fails", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} up -d`]: { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("compose.up — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.up({ projectDirectory })
    expect(mod.name).toBe(`compose.up: ${projectDirectory}`)
  })
})

// ─── compose.pull ─────────────────────────────────────────────────────────────

describe("compose.pull — check", () => {
  it("always returns needs-apply regardless of state", async () => {
    const mod = compose.pull({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("always returns needs-apply even with a valid connection", async () => {
    const mockSsh = createMockSsh({})
    const mod = compose.pull({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("compose.pull — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when output contains Pulling", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} pull 2>&1`]: {
        code: 0,
        stdout: "Pulling from registry...",
      },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns changed when output contains Downloaded", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} pull 2>&1`]: {
        code: 0,
        stdout: "Downloaded newer image for nginx:latest",
      },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok when output contains no change indicators", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} pull 2>&1`]: {
        code: 0,
        stdout: "Image is up to date",
      },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns failed when pull command fails", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} pull 2>&1`]: { code: 1 },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("compose.pull — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.pull({ projectDirectory })
    expect(mod.name).toBe(`compose.pull: ${projectDirectory}`)
  })
})

// ─── compose.down ─────────────────────────────────────────────────────────────

describe("compose.down — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when ps returns empty stdout (no containers running)", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "" },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when ps command fails (treats as already down)", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when containers are running", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} ps --format json`]: {
        code: 0,
        stdout: JSON.stringify([{ State: "running" }]),
      },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("compose.down — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed on successful down", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} down`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("includes --volumes flag when volumes option is true", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} down --volumes`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} down --volumes`)
  })

  it("does not include --volumes flag when volumes option is false", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} down`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory, volumes: false })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(`${composeCmd("podman")} down --volumes`)
  })

  it("returns failed when down command fails", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} down`]: { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("compose.down — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.down({ projectDirectory })
    expect(mod.name).toBe(`compose.down: ${projectDirectory}`)
  })
})

// ─── compose.config ───────────────────────────────────────────────────────────

const remotePath = `${projectDirectory}/compose.yml`
const sampleContent = "services:\n  web:\n    image: nginx\n"

describe("compose.config — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the remote file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when remote content matches desired content", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: sampleContent },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when remote content differs", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: "different content" },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when neither src nor content is provided", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
    })
    const mod = compose.config({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("reads local src file to compare content", async () => {
    const localContent = "services:\n  web:\n    image: nginx\n"
    const { readFile } = await import("node:fs/promises")
    vi.mocked(readFile).mockResolvedValue(localContent)

    const mockSsh = createMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: localContent },
    })
    const mod = compose.config({ projectDirectory, src: "/local/compose.yml" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")

    vi.mocked(readFile).mockRestore()
  })
})

describe("compose.config — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("writes content and validates with config --quiet", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} config --quiet`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.path).toBe(remotePath)
    expect(writtenFiles[0]?.content).toBe(sampleContent)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} config --quiet`)
  })

  it("uploads src file and validates", async () => {
    const uploadedFiles: Array<{ dest: string; src: string }> = []
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} config --quiet`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.uploadFile = async (src: string, dest: string): Promise<void> => {
      uploadedFiles.push({ dest, src })
    }

    const mod = compose.config({ projectDirectory, src: "/local/compose.yml" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(uploadedFiles[0]?.src).toBe("/local/compose.yml")
    expect(uploadedFiles[0]?.dest).toBe(remotePath)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} config --quiet`)
  })

  it("returns failed when validation fails", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} config --quiet`]: { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when neither src nor content is provided", async () => {
    const mockSsh = createMockSsh({})
    const mod = compose.config({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("compose.config — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.config({ content: sampleContent, projectDirectory })
    expect(mod.name).toBe(`compose.config: ${projectDirectory}`)
  })
})

// ─── compose.restart ──────────────────────────────────────────────────────────

describe("compose.restart — check", () => {
  it("always returns needs-apply (signal-style)", async () => {
    const mod = compose.restart({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("always returns needs-apply even with a valid connection", async () => {
    const mockSsh = createMockSsh({})
    const mod = compose.restart({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("compose.restart — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed on successful restart and runs down && up -d", async () => {
    const cmd = composeCmd("podman")
    const mockSsh = createMockSsh({
      [`${cmd} down && ${cmd} up -d`]: { code: 0 },
    })
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${cmd} down && ${cmd} up -d`)
  })

  it("returns failed when restart command fails", async () => {
    const cmd = composeCmd("podman")
    const mockSsh = createMockSsh({
      [`${cmd} down && ${cmd} up -d`]: { code: 1 },
    })
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("compose.restart — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.restart({ projectDirectory })
    expect(mod.name).toBe(`compose.restart: ${projectDirectory}`)
  })
})

// ─── compose.systemd ──────────────────────────────────────────────────────────

function expectedDockerUnit(dir: string, name: string): string {
  return [
    "[Unit]",
    `Description=Compose stack: ${name}`,
    "After=network-online.target docker.service",
    "Requires=docker.service",
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${dir}`,
    "ExecStart=/usr/bin/env docker compose up -d",
    "ExecStop=/usr/bin/env docker compose down",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n")
}

function expectedPodmanUnit(dir: string, name: string): string {
  return [
    "[Unit]",
    `Description=Compose stack: ${name}`,
    "After=network-online.target",
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${dir}`,
    "ExecStart=/usr/bin/env podman compose up -d",
    "ExecStop=/usr/bin/env podman compose down",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n")
}

const defaultServiceName = "compose-app"
const unitFilePath = `/etc/systemd/system/${defaultServiceName}.service`

describe("compose.systemd — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when unit file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when unit file content matches expected content (podman)", async () => {
    const content = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when unit file content matches expected content (docker)", async () => {
    const content = expectedDockerUnit(projectDirectory, defaultServiceName)
    const mockSsh = createMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when unit file content differs", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: "outdated content" },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("compose.systemd — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("writes unit file and runs daemon-reload", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.path).toBe(unitFilePath)
    expect(mockSsh.calls).toContain("systemctl daemon-reload")
  })

  it("returns failed when daemon-reload fails", async () => {
    const mockSsh = createMockSsh({
      "systemctl daemon-reload": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("generates unit without docker.service dependency for podman runtime", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ projectDirectory })
    await mod.apply(mockSsh, emptyEnv)
    expect(writtenFiles[0]?.path).toBe(unitFilePath)
    expect(writtenFiles[0]?.content).not.toContain("Requires=docker.service")
    expect(writtenFiles[0]?.content).toContain("After=network-online.target")
  })

  it("generates unit with docker.service dependency for docker runtime", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "command -v podman": { code: 1 },
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ projectDirectory })
    await mod.apply(mockSsh, emptyEnv)
    expect(writtenFiles[0]?.content).toContain("Requires=docker.service")
    expect(writtenFiles[0]?.content).toContain("After=network-online.target docker.service")
  })
})

describe("compose.systemd — naming", () => {
  it("derives service name from projectDirectory basename by default", () => {
    const mod = compose.systemd({ projectDirectory })
    expect(mod.name).toBe(`compose.systemd: ${defaultServiceName}.service`)
  })

  it("uses explicit name when provided", () => {
    const mod = compose.systemd({ name: "my-stack", projectDirectory })
    expect(mod.name).toBe("compose.systemd: my-stack.service")
  })

  it("explicit name is used as unit file name", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ name: "my-stack", projectDirectory })
    await mod.apply(mockSsh, emptyEnv)
    expect(writtenFiles[0]?.path).toBe("/etc/systemd/system/my-stack.service")
    expect(writtenFiles[0]?.content).toContain("Description=Compose stack: my-stack")
  })
})

// ─── Runtime detection ────────────────────────────────────────────────────────

describe("Runtime detection", () => {
  it("prefers podman over docker when both are available", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("podman")} up -d`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} up -d`)
    expect(mockSsh.calls).not.toContain(`${composeCmd("docker")} up -d`)
  })

  it("uses explicit runtime override without detection", async () => {
    const mockSsh = createMockSsh({
      [`${composeCmd("docker")} up -d`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory, runtime: "docker" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`${composeCmd("docker")} up -d`)
    expect(mockSsh.calls).not.toContain("command -v docker")
    expect(mockSsh.calls).not.toContain("command -v podman")
  })
})
