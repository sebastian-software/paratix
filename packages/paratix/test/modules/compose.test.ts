import type * as NodeFsPromises from "node:fs/promises"

import { describe, expect, it, vi } from "vitest"

import { compose } from "../../src/index.js"
import { createStrictMockSsh } from "../helpers/mockSsh.js"

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeFsPromises>()
  return { ...actual, readFile: vi.fn(actual.readFile) }
})

const emptyEnv = {}

const projectDirectory = "/opt/app"
const remotePath = `${projectDirectory}/compose.yml`
const stagingPath = `${projectDirectory}/.compose.yml.paratix-staging.ABCDEF`
const secondStagingPath = `${projectDirectory}/.compose.yml.paratix-staging.SECOND`
const mktempCommand = `mktemp '${projectDirectory}/.compose.yml.paratix-staging.XXXXXX'`

// Helper: build the compose command prefix for a given runtime
function composeCmd(runtime: "docker" | "podman"): string {
  return `${runtime} compose --project-directory '${projectDirectory}'`
}

function createComposeMockSsh(
  responses?: Record<string, { code?: number; stderr?: string; stdout?: string }>
) {
  return createStrictMockSsh(
    {
      "[ -f '/etc/systemd/system/compose-app.service' ] && [ ! -L '/etc/systemd/system/compose-app.service' ]":
        { code: 0 },
      "[ -f '/opt/app/compose.yml' ] && [ ! -L '/opt/app/compose.yml' ]": { code: 0 },
      "command -v podman": { code: 0 },
      [mktempCommand]: { code: 0, stdout: `${stagingPath}\n` },
      ...responses,
    },
    {
      allowUploads: [
        {
          localPath: "/local/compose.yml",
          options: { mode: "0600" },
          remotePath: "/opt/app/compose.yml",
        },
        {
          // R-0000228: src is uploaded to the staging path, not directly to compose.yml.
          localPath: /.+/v,
          options: { mode: "0600" },
          remotePath: /^\/opt\/app\/\.compose\.yml\.paratix-staging\..+$/v,
        },
      ],
      allowWrites: [
        { options: { mode: "0600" }, remotePath: "/opt/app/compose.yml" },
        // R-0000228: validation runs against a staging file before atomic mv.
        {
          options: { mode: "0600" },
          remotePath: /^\/opt\/app\/\.compose\.yml\.paratix-staging\..+$/v,
        },
        { options: { mode: "0644" }, remotePath: /^\/etc\/systemd\/system\/.+$/v },
      ],
    }
  )
}

// ─── compose.up ──────────────────────────────────────────────────────────────

describe("compose.up — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when no runtime is found", async () => {
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ps returns empty stdout", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "" },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when all containers are running (array JSON)", async () => {
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    expect(result.error).toBeInstanceOf(Error)
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("no container runtime found")
  })

  it("returns changed on successful up that started a service", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 2>&1`]: {
        code: 0,
        stdout: "Creating web ... done\nCreating db ... done\n",
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("includes services in command when services list is provided", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 'web' 'db' 2>&1`]: {
        code: 0,
        stdout: "Starting web ... done\nStarting db ... done\n",
      },
    })
    const mod = compose.up({ projectDirectory, services: ["web", "db"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} up -d 'web' 'db' 2>&1`)
  })

  it("uses docker when only docker is available", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("docker")} up -d 2>&1`]: {
        code: 0,
        stdout: "Creating web ... done\n",
      },
      "command -v docker": { code: 0 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("docker")} up -d 2>&1`)
  })

  it("returns failed when up command fails", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 2>&1`]: { code: 1, stderr: "compose up failed" },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[compose.up] failed")
  })

  // R-0000078: when every service was already running, compose up emits
  // no action keywords (Creating/Recreating/Starting/Started/Pulling).
  // Treat that as a no-op so the run is not flagged as "changed".
  it("returns ok when no service had to be brought up", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 2>&1`]: {
        code: 0,
        stdout: "web is up-to-date\ndb is up-to-date\n",
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when compose recreates an existing service", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 2>&1`]: {
        code: 0,
        stdout: "Recreating web ... done\n",
      },
    })
    const mod = compose.up({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })
})

describe("compose.up — name", () => {
  it("exposes a descriptive name string", () => {
    const mod = compose.up({ projectDirectory })
    expect(mod.name).toBe(`compose.up: ${projectDirectory}`)
  })
})

describe("compose.up — service validation", () => {
  it("rejects empty service names", () => {
    expect(() => compose.up({ projectDirectory, services: ["web", ""] })).toThrow(
      "compose.up services must not contain empty service names"
    )
  })

  it("rejects service names that would be parsed as compose options", () => {
    expect(() => compose.up({ projectDirectory, services: ["--remove-orphans"] })).toThrow(
      'compose.up service names must not start with "-", got --remove-orphans'
    )
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
    const mockSsh = createComposeMockSsh({})
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
    expect(result.error).toBeInstanceOf(Error)
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when output contains Pulling", async () => {
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} pull 2>&1`]: { code: 1, stderr: "pull failed" },
    })
    const mod = compose.pull({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
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
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "" },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when Docker Compose reports no containers as an empty JSON array", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply for volumes when no containers remain but project volumes exist", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 0,
        stdout: JSON.stringify({ name: "app" }),
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
      "podman volume ls --filter 'label=com.docker.compose.project=app' -q": {
        code: 0,
        stdout: "app_data\n",
      },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok for volumes when no containers or project volumes remain", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 0,
        stdout: JSON.stringify({ name: "app" }),
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
      "podman volume ls --filter 'label=com.docker.compose.project=app' -q": {
        code: 0,
        stdout: "",
      },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply for volumes when volume inspection fails", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 0,
        stdout: JSON.stringify({ name: "app" }),
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
      "podman volume ls --filter 'label=com.docker.compose.project=app' -q": { code: 1 },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("uses the effective compose project name for volume checks", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 0,
        stdout: JSON.stringify({ name: "configured-stack" }),
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
      "podman volume ls --filter 'label=com.docker.compose.project=configured-stack' -q": {
        code: 0,
        stdout: "configured-stack_data\n",
      },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(
      "podman volume ls --filter 'label=com.docker.compose.project=configured-stack' -q"
    )
  })

  it("falls back to the project directory basename when compose config omits a name", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 0,
        stdout: JSON.stringify({ services: {} }),
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
      "podman volume ls --filter 'label=com.docker.compose.project=app' -q": {
        code: 0,
        stdout: "",
      },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when the compose project name cannot be resolved", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} config --format json`]: {
        code: 1,
        stderr: "invalid compose file",
      },
      [`${composeCmd("podman")} ps --format json`]: { code: 0, stdout: "[]" },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(
      "podman volume ls --filter 'label=com.docker.compose.project=app' -q"
    )
  })

  it("returns needs-apply when ps command fails", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} ps --format json`]: { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when containers are running", async () => {
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
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
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} down`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("includes --volumes flag when volumes option is true", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} down --volumes`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory, volumes: true })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} down --volumes`)
  })

  it("does not include --volumes flag when volumes option is false", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} down`]: { code: 0 },
    })
    const mod = compose.down({ projectDirectory, volumes: false })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(`${composeCmd("podman")} down --volumes`)
  })

  it("returns failed when down command fails", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} down`]: { code: 1 },
    })
    const mod = compose.down({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when no runtime is found", async () => {
    const mockSsh = createComposeMockSsh({
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

const sampleContent = "services:\n  web:\n    image: nginx\n"

describe("compose.config — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the remote file does not exist", async () => {
    const mockSsh = createComposeMockSsh({
      "[ -f '/opt/app/compose.yml' ] && [ ! -L '/opt/app/compose.yml' ]": { code: 1 },
      [`[ -e '${remotePath}' ]`]: { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the remote compose file is a symlink", async () => {
    const mockSsh = createComposeMockSsh({
      "[ -f '/opt/app/compose.yml' ] && [ ! -L '/opt/app/compose.yml' ]": { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when remote content and mode match the desired values", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: sampleContent },
      [`stat -c '%a' '${remotePath}'`]: { code: 0, stdout: "600" },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when remote content differs", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: "different content" },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression: returns needs-apply when remote mode has drifted from COMPOSE_CONFIG_MODE", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: sampleContent },
      // Operator manually ran `chmod 0644 compose.yml` — content matches, but mode does not.
      [`stat -c '%a' '${remotePath}'`]: { code: 0, stdout: "644" },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when neither src nor content is provided", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
    })
    const mod = compose.config({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("reads local src file to compare content and mode", async () => {
    const localContent = "services:\n  web:\n    image: nginx\n"
    const { readFile } = await import("node:fs/promises")
    vi.mocked(readFile).mockResolvedValue(localContent)

    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`cat '${remotePath}'`]: { code: 0, stdout: localContent },
      [`stat -c '%a' '${remotePath}'`]: { code: 0, stdout: "600" },
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
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000228: writes go to a staging file, validation reads the staging file
  // via -f, and an atomic mv -T flips compose.yml to the validated revision
  // so a parallel compose invocation never sees an unvalidated config.
  it("writes content into staging, validates with -f, and activates with mv -T", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 0 },
      [`mv -T '${stagingPath}' '${remotePath}'`]: { code: 0 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.path).toBe(stagingPath)
    expect(writtenFiles[0]?.content).toBe(sampleContent)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} -f '${stagingPath}' config --quiet`)
    expect(mockSsh.calls).toContain(`mv -T '${stagingPath}' '${remotePath}'`)
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
  })

  it("uses a distinct mktemp staging path for parallel applies", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
      [`${composeCmd("podman")} -f '${secondStagingPath}' config --quiet`]: { code: 0 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 0 },
      [`mv -T '${secondStagingPath}' '${remotePath}'`]: { code: 0 },
      [`mv -T '${stagingPath}' '${remotePath}'`]: { code: 0 },
      [`rm -f '${secondStagingPath}'`]: { code: 0 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    const outputMock = vi
      .spyOn(mockSsh, "output")
      .mockResolvedValueOnce(stagingPath)
      .mockResolvedValueOnce(secondStagingPath)

    const first = compose.config({ content: sampleContent, projectDirectory })
    const second = compose.config({
      content: "services:\n  api:\n    image: caddy\n",
      projectDirectory,
    })

    const results = await Promise.all([
      first.apply(mockSsh, emptyEnv),
      second.apply(mockSsh, emptyEnv),
    ])

    expect(results).toStrictEqual([{ status: "changed" }, { status: "changed" }])
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toStrictEqual([
      stagingPath,
      secondStagingPath,
    ])
    expect(outputMock).toHaveBeenNthCalledWith(1, mktempCommand)
    expect(outputMock).toHaveBeenNthCalledWith(2, mktempCommand)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} -f '${stagingPath}' config --quiet`)
    expect(mockSsh.calls).toContain(
      `${composeCmd("podman")} -f '${secondStagingPath}' config --quiet`
    )
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
    expect(mockSsh.calls).toContain(`rm -f '${secondStagingPath}'`)
  })

  it("uploads src file with the explicit COMPOSE_CONFIG_MODE and validates", async () => {
    const uploadedFiles: Array<{
      dest: string
      options: { mode?: string } | undefined
      src: string
    }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 0 },
      [`mv -T '${stagingPath}' '${remotePath}'`]: { code: 0 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    mockSsh.uploadFile = async (
      src: string,
      dest: string,
      options?: { mode?: string }
    ): Promise<void> => {
      await Promise.resolve()
      uploadedFiles.push({ dest, options, src })
    }

    const mod = compose.config({ projectDirectory, src: "/local/compose.yml" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(uploadedFiles[0]?.src).toBe("/local/compose.yml")
    // R-0000228: the src is uploaded to the staging path before validation.
    expect(uploadedFiles[0]?.dest).toBe(stagingPath)
    // The src branch must forward an explicit mode so the resulting file is not
    // produced as the silent uploadFile temp-mode default.
    expect(uploadedFiles[0]?.options).toStrictEqual({ mode: "0600" })
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} -f '${stagingPath}' config --quiet`)
    expect(mockSsh.calls).toContain(`mv -T '${stagingPath}' '${remotePath}'`)
  })

  it.each([
    {
      name: "content path rejects multiline mktemp output",
      options: { content: sampleContent, projectDirectory },
      stdout: `mktemp: warning: locale failed\n${stagingPath}\n`,
    },
    {
      name: "content path rejects mktemp output outside the project directory",
      options: {
        content: sampleContent,
        projectDirectory,
      },
      stdout: "/tmp/.compose.yml.paratix-staging.ABCDEF\n",
    },
    {
      name: "src path rejects multiline mktemp output",
      options: { projectDirectory, src: "/local/compose.yml" },
      stdout: `mktemp: warning: locale failed\n${stagingPath}\n`,
    },
    {
      name: "src path rejects mktemp output outside the project directory",
      options: { projectDirectory, src: "/local/compose.yml" },
      stdout: "/tmp/.compose.yml.paratix-staging.ABCDEF\n",
    },
  ])("$name", async ({ options, stdout }) => {
    const mockSsh = createComposeMockSsh({
      [mktempCommand]: { code: 0, stdout },
    })

    const mod = compose.config(options)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Unexpected mktemp output")

    expect(mockSsh.writeFileCalls).toHaveLength(0)
    expect(mockSsh.uploadFileCalls).toHaveLength(0)
    expect(mockSsh.calls).not.toContain(
      `${composeCmd("podman")} -f '${stagingPath}' config --quiet`
    )
    expect(mockSsh.calls).not.toContain(`mv -T '${stagingPath}' '${remotePath}'`)
  })

  it("returns failed when validation fails and never activates the staging file", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 1 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    const mod = compose.config({ content: sampleContent, projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    // R-0000228: the staging file is cleaned up but never moved over compose.yml.
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
    expect(mockSsh.calls).not.toContain(`mv -T '${stagingPath}' '${remotePath}'`)
  })

  it("returns failed when neither src nor content is provided", async () => {
    const mockSsh = createComposeMockSsh({})
    const mod = compose.config({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000228: validation runs against the staging file. When it fails, the
  // existing compose.yml is left completely untouched — the staging file is
  // simply removed. Confirm no write/rollback to the active file happened.
  it("R-0000228: leaves the active compose.yml untouched when validation fails", async () => {
    const priorContent = "services:\n  web:\n    image: nginx:1.0\n"
    const writtenFiles: Array<{
      content: string
      mode: string | undefined
      path: string
    }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 1 },
      [`cat '${remotePath}'`]: { code: 0, stdout: priorContent },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    mockSsh.writeFile = async (
      path: string,
      content: string,
      writeOptions: { mode: string }
    ): Promise<void> => {
      await Promise.resolve()
      writtenFiles.push({ content, mode: writeOptions.mode, path })
    }

    const mod = compose.config({ content: "broken: yaml: [\n", projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // Only the staging write happened; the active compose.yml never received
    // a writeFile (validation failed before the atomic mv).
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.path).toBe(stagingPath)
    expect(writtenFiles[0]?.content).toBe("broken: yaml: [\n")
    expect(mockSsh.calls).not.toContain(`mv -T '${stagingPath}' '${remotePath}'`)
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
  })

  // R-0000228: when validation throws (e.g. compose CLI itself crashes),
  // the staging file must still be removed via the finally block.
  it("R-0000228: cleans up the staging file when validation throws", async () => {
    const validationError = new Error("validation command timed out")
    const writtenFiles: Array<{
      content: string
      mode: string | undefined
      path: string
    }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    // The first exec call after writeFile is the compose validation; reject it.
    vi.spyOn(mockSsh, "exec").mockImplementationOnce(() => {
      throw validationError
    })
    mockSsh.writeFile = async (
      path: string,
      content: string,
      writeOptions: { mode: string }
    ): Promise<void> => {
      await Promise.resolve()
      writtenFiles.push({ content, mode: writeOptions.mode, path })
    }

    const mod = compose.config({ content: "broken: yaml: [\n", projectDirectory })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(validationError)

    // The staging write happened, validation threw, finally removed staging.
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.path).toBe(stagingPath)
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
    expect(mockSsh.calls).not.toContain(`mv -T '${stagingPath}' '${remotePath}'`)
  })

  // R-0000228: the src path uploads to the staging file, validates with -f,
  // and when validation fails the active compose.yml is never touched.
  it("R-0000228: leaves the active compose.yml untouched when validation fails (src path)", async () => {
    const { readFile: readFileMock } = await import("node:fs/promises")
    const priorContent = "services:\n  api:\n    image: alpine:3\n"
    const newContent = "broken-yaml: [\n"
    vi.mocked(readFileMock).mockImplementationOnce(async () => {
      await Promise.resolve()
      return newContent
    })

    const uploadedFiles: Array<{ dest: string; mode: string | undefined; src: string }> = []
    const writtenFiles: Array<{
      content: string
      mode: string | undefined
      path: string
    }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 0 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 1 },
      [`cat '${remotePath}'`]: { code: 0, stdout: priorContent },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    mockSsh.uploadFile = async (
      src: string,
      dest: string,
      uploadOptions?: { mode?: string }
    ): Promise<void> => {
      await Promise.resolve()
      uploadedFiles.push({ dest, mode: uploadOptions?.mode, src })
    }
    mockSsh.writeFile = async (
      path: string,
      content: string,
      writeOptions: { mode: string }
    ): Promise<void> => {
      await Promise.resolve()
      writtenFiles.push({ content, mode: writeOptions.mode, path })
    }

    const mod = compose.config({ projectDirectory, src: "/local/broken.yml" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // The src was uploaded to the staging path; the active compose.yml never
    // received a write or upload because validation failed before mv -T.
    expect(uploadedFiles).toHaveLength(1)
    expect(uploadedFiles[0]?.src).toBe("/local/broken.yml")
    expect(uploadedFiles[0]?.dest).toBe(stagingPath)
    expect(writtenFiles).toHaveLength(0)
    expect(mockSsh.calls).not.toContain(`mv -T '${stagingPath}' '${remotePath}'`)
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
  })

  it("removes the staging file on validation failure when no prior file existed", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      [`[ -e '${remotePath}' ]`]: { code: 1 },
      [`${composeCmd("podman")} -f '${stagingPath}' config --quiet`]: { code: 1 },
      [`rm -f '${stagingPath}'`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.config({ content: "broken: [", projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // Only the staging write happened; cleanup removed it.
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.path).toBe(stagingPath)
    expect(mockSsh.calls).toContain(`rm -f '${stagingPath}'`)
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
    const mockSsh = createComposeMockSsh({})
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
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed on successful restart and runs down && up -d", async () => {
    const cmd = composeCmd("podman")
    const mockSsh = createComposeMockSsh({
      [`${cmd} down && ${cmd} up -d`]: { code: 0 },
    })
    const mod = compose.restart({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`${cmd} down && ${cmd} up -d`)
  })

  it("returns failed when restart command fails", async () => {
    const cmd = composeCmd("podman")
    const mockSsh = createComposeMockSsh({
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
    "Wants=network-online.target",
    "After=network-online.target docker.service",
    "Requires=docker.service",
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${dir}`,
    "ExecStart=/usr/bin/env docker compose up --remove-orphans",
    "ExecStop=/usr/bin/env docker compose down",
    "TimeoutStartSec=0",
    "StandardOutput=journal",
    "StandardError=journal",
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
    "Wants=network-online.target",
    "After=network-online.target",
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${dir}`,
    "ExecStart=/usr/bin/env podman compose up --remove-orphans",
    "ExecStop=/usr/bin/env podman compose down",
    "TimeoutStartSec=0",
    "StandardOutput=journal",
    "StandardError=journal",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n")
}

function expectedDetachedDockerUnit(dir: string, name: string): string {
  return expectedDockerUnit(dir, name).replace(
    "ExecStart=/usr/bin/env docker compose up --remove-orphans",
    "ExecStart=/usr/bin/env docker compose up -d --remove-orphans"
  )
}

function expectedDetachedPodmanUnit(dir: string, name: string): string {
  return expectedPodmanUnit(dir, name).replace(
    "ExecStart=/usr/bin/env podman compose up --remove-orphans",
    "ExecStart=/usr/bin/env podman compose up -d --remove-orphans"
  )
}

const defaultServiceName = "compose-app"
const unitFilePath = `/etc/systemd/system/${defaultServiceName}.service`
const systemdUnitFallbackTempPath =
  "/etc/systemd/system/.compose-systemd-unit.paratix-staging.ABCDEF"
const systemdUnitFallbackMktempCommand =
  "mktemp '/etc/systemd/system/.compose-systemd-unit.paratix-staging.XXXXXX'"

function composeSystemdRecoveryResponses(
  serviceName = defaultServiceName,
  filePath = unitFilePath
): Record<string, { code: number; stdout?: string }> {
  return {
    [`[ -e '${filePath}' ]`]: { code: 0 },
    [`[ -L '${filePath}' ]`]: { code: 1 },
    [`cat '${filePath}'`]: { code: 0, stdout: "[Unit]\nDescription=previous\n" },
    [`chown 'root:root' '${filePath}'`]: { code: 0 },
    [`rm -f '${filePath}'`]: { code: 0 },
    [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644" },
    [`stat -c '%U:%G' '${filePath}'`]: { code: 0, stdout: "root:root" },
    [`systemctl is-enabled -- '${serviceName}.service'`]: { code: 0, stdout: "masked\n" },
    [`systemctl unmask -- '${serviceName}.service'`]: { code: 0 },
  }
}

function buildComposeSystemdShellFallbackCommand(
  filePath: string,
  content: string,
  temporaryPath = systemdUnitFallbackTempPath
): string {
  const encodedContent = Buffer.from(content, "utf8").toString("base64")
  return `{ printf '%s' '${encodedContent}' | base64 -d > '${temporaryPath}' && chmod '0644' '${temporaryPath}' && chown 'root:root' '${temporaryPath}' && if [ -L '${filePath}' ]; then rm -f '${temporaryPath}'; exit 73; fi && mv -f -T '${temporaryPath}' '${filePath}'; } || { status=$?; rm -f '${temporaryPath}'; exit "$status"; }`
}

describe("compose.systemd — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when no runtime is found", async () => {
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when unit file does not exist", async () => {
    const mockSsh = createComposeMockSsh({
      "[ -f '/etc/systemd/system/compose-app.service' ] && [ ! -L '/etc/systemd/system/compose-app.service' ]":
        { code: 1 },
      [`[ -e '${unitFilePath}' ]`]: { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the unit file is a symlink", async () => {
    const mockSsh = createComposeMockSsh({
      "[ -f '/etc/systemd/system/compose-app.service' ] && [ ! -L '/etc/systemd/system/compose-app.service' ]":
        { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when unit file content and mode match expected values (podman)", async () => {
    const content = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "644" },
      [`stat -c '%U %G' '${unitFilePath}'`]: { code: 0, stdout: "root root" },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when unit file content and mode match expected values (docker)", async () => {
    const content = expectedDockerUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "644" },
      [`stat -c '%U %G' '${unitFilePath}'`]: { code: 0, stdout: "root root" },
      "command -v docker": { code: 0 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when unit file content differs", async () => {
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: "outdated content" },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression: returns needs-apply when remote mode has drifted from SYSTEMD_UNIT_MODE", async () => {
    const content = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      // Operator manually ran `chmod 0600 compose-app.service` — content matches, but mode does not.
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "600" },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000164: detect manual owner/group drift on the system-wide unit file
  // (e.g. an operator ran `chown svc:svc compose-app.service`). The apply
  // path explicitly runs `chown root:root`, so check must report needs-apply
  // when the owner has drifted — otherwise apply silently rewrites the unit
  // on every run, and the hardening regression of a non-root-owned unit
  // goes undetected.
  it("R-0000164: returns needs-apply when remote owner has drifted from root:root", async () => {
    const content = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "644" },
      [`stat -c '%U %G' '${unitFilePath}'`]: { code: 0, stdout: "svc svc" },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000164: returns needs-apply when remote group has drifted from root", async () => {
    const content = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      [`[ -e '${unitFilePath}' ]`]: { code: 0 },
      [`cat '${unitFilePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "644" },
      [`stat -c '%U %G' '${unitFilePath}'`]: { code: 0, stdout: "root staff" },
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
    const mockSsh = createComposeMockSsh({
      "command -v docker": { code: 1 },
      "command -v podman": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("writes unit file and runs daemon-reload", async () => {
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedUnit,
      },
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(writtenFiles).toStrictEqual([{ content: expectedUnit, path: unitFilePath }])
    expect(mockSsh.calls).toContain("systemctl daemon-reload")
    // R-0000164: apply must run `chown root:root` on the unit after the
    // writeFile, because the writeFile path only sets the mode and would
    // otherwise leave any pre-existing owner drift in place.
    expect(mockSsh.calls).toContain(`chown 'root:root' '${unitFilePath}'`)
  })

  // R-0000164: when the explicit chown after writeFile fails (e.g. invalid
  // user/group on the host) apply must surface a failure rather than
  // silently continuing with a non-root-owned unit.
  it("R-0000164: returns failed when the explicit chown root:root fails", async () => {
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedPodmanUnit(projectDirectory, defaultServiceName),
      },
      [`chown 'root:root' '${unitFilePath}'`]: {
        code: 1,
        stderr: "chown: invalid user: 'root:root'",
      },
    })
    mockSsh.writeFile = async (): Promise<void> => {
      // accept the write
      await Promise.resolve()
    }

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to set owner root:root")
    // daemon-reload must not run when ownership could not be enforced.
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("returns failed when unmasking the unit fails", async () => {
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedUnit,
      },
      [`systemctl unmask -- '${defaultServiceName}.service'`]: {
        code: 1,
        stderr: "failed to unmask",
      },
      "systemctl daemon-reload": { code: 0 },
    })

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl unmask failed")
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("restores the previous masked state when writing the unit fails after unmask", async () => {
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`systemctl mask -- '${defaultServiceName}.service'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "writeFile")
      .mockRejectedValueOnce(new Error("disk full"))
      .mockResolvedValueOnce(undefined)

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).toContain(`systemctl mask -- '${defaultServiceName}.service'`)
    expect(mockSsh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(1)
  })

  it("restores the previous unit file and mask state when chown fails", async () => {
    const previousUnit = "[Unit]\nDescription=previous\n"
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const writtenFiles: Array<{ content: string; mode?: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`chown 'root:root' '${unitFilePath}'`]: {
        code: 1,
        stderr: "chown failed",
      },
      [`chown 'svc:svc' '${unitFilePath}'`]: { code: 0 },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "600" },
      [`stat -c '%U:%G' '${unitFilePath}'`]: { code: 0, stdout: "svc:svc" },
      [`systemctl mask -- '${defaultServiceName}.service'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(previousUnit)
      .mockResolvedValue(expectedUnit)
    vi.spyOn(mockSsh, "writeFile").mockImplementation(async (path, content, options) => {
      writtenFiles.push({ content, mode: options.mode, path })
      await Promise.resolve()
    })

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writtenFiles).toContainEqual({
      content: previousUnit,
      mode: "600",
      path: unitFilePath,
    })
    expect(mockSsh.calls).toContain(`chown 'svc:svc' '${unitFilePath}'`)
    expect(mockSsh.calls).toContain(`systemctl mask -- '${defaultServiceName}.service'`)
    expect(mockSsh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(1)
  })

  it("restores the previous unit file and mask state when daemon-reload fails", async () => {
    const previousUnit = "[Unit]\nDescription=previous\n"
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const writtenFiles: Array<{ content: string; mode?: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`chown 'svc:svc' '${unitFilePath}'`]: { code: 0 },
      [`stat -c '%a' '${unitFilePath}'`]: { code: 0, stdout: "600" },
      [`stat -c '%U:%G' '${unitFilePath}'`]: { code: 0, stdout: "svc:svc" },
      [`systemctl mask -- '${defaultServiceName}.service'`]: { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(previousUnit)
      .mockResolvedValue(expectedUnit)
    vi.spyOn(mockSsh, "writeFile").mockImplementation(async (path, content, options) => {
      writtenFiles.push({ content, mode: options.mode, path })
      await Promise.resolve()
    })

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writtenFiles).toContainEqual({
      content: previousUnit,
      mode: "600",
      path: unitFilePath,
    })
    expect(mockSsh.calls).toContain(`chown 'svc:svc' '${unitFilePath}'`)
    expect(mockSsh.calls).toContain(`systemctl mask -- '${defaultServiceName}.service'`)
    expect(mockSsh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(2)
  })

  it("returns failed when daemon-reload fails", async () => {
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedPodmanUnit(projectDirectory, defaultServiceName),
      },
      "systemctl daemon-reload": { code: 1 },
    })
    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000192: refuse to write through a symlink at the unit path. The
  // check path already rejects symlinks via isRegularFileWithoutSymlink;
  // the apply path must mirror that guard so writeFile + chown root:root
  // cannot be redirected to an attacker-controlled target.
  it("R-0000192: returns failed when the unit path is a symlink", async () => {
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`[ -L '${unitFilePath}' ]`]: { code: 0 },
    })
    let writeFileCalled = false
    mockSsh.writeFile = async (): Promise<void> => {
      writeFileCalled = true
      await Promise.resolve()
    }

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("refuses to write through symlink")
    expect(writeFileCalled).toBe(false)
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("keeps an existing unit file when atomic write fails", async () => {
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
    })
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.reject(new Error("disk full"))
    }

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("atomic write failed")
    expect(mockSsh.calls).toContain("systemctl unmask -- 'compose-app.service'")
    expect(mockSsh.calls).not.toContain("rm -f '/etc/systemd/system/compose-app.service'")
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("generates unit without docker.service dependency for podman runtime", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedPodmanUnit(projectDirectory, defaultServiceName),
      },
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
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedDockerUnit(projectDirectory, defaultServiceName),
      },
      "command -v docker": { code: 0 },
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

  it("uses detached compose up when detached is enabled", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`cat '${unitFilePath}'`]: {
        code: 0,
        stdout: expectedDetachedPodmanUnit(projectDirectory, defaultServiceName),
      },
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({ detached: true, projectDirectory })
    await mod.apply(mockSsh, emptyEnv)

    expect(writtenFiles[0]?.content).toContain("compose up -d --remove-orphans")
  })

  it("recovers with a shell fallback when the atomic write leaves an empty unit file", async () => {
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [buildComposeSystemdShellFallbackCommand(unitFilePath, expectedUnit)]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
      [systemdUnitFallbackMktempCommand]: { code: 0, stdout: `${systemdUnitFallbackTempPath}\n` },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce("[Unit]\nDescription=previous\n")
      .mockResolvedValueOnce("")
      .mockResolvedValueOnce(expectedUnit)

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain("rm -f '/etc/systemd/system/compose-app.service'")
    expect(mockSsh.calls).toContain(systemdUnitFallbackMktempCommand)
    expect(mockSsh.calls).toContain(
      buildComposeSystemdShellFallbackCommand(unitFilePath, expectedUnit)
    )
    expect(mockSsh.calls).toContain("systemctl daemon-reload")
  })

  it("returns failed when the unit is still empty after the shell fallback", async () => {
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [buildComposeSystemdShellFallbackCommand(unitFilePath, expectedUnit)]: { code: 0 },
      [systemdUnitFallbackMktempCommand]: { code: 0, stdout: `${systemdUnitFallbackTempPath}\n` },
    })
    vi.spyOn(mockSsh, "readFile").mockResolvedValue("")

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("even after shell fallback")
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("returns failed when the unit path becomes a symlink before the shell fallback move", async () => {
    const expectedUnit = expectedPodmanUnit(projectDirectory, defaultServiceName)
    const fallbackCommand = buildComposeSystemdShellFallbackCommand(unitFilePath, expectedUnit)
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(),
      [`rm -f '${systemdUnitFallbackTempPath}'`]: { code: 0 },
      [fallbackCommand]: { code: 73, stderr: "unit path became a symlink" },
      [systemdUnitFallbackMktempCommand]: { code: 0, stdout: `${systemdUnitFallbackTempPath}\n` },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce("[Unit]\nDescription=previous\n")
      .mockResolvedValueOnce("")

    const mod = compose.systemd({ projectDirectory })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("shell fallback write failed")
    expect(mockSsh.calls).toContain(fallbackCommand)
    expect(mockSsh.calls).not.toContain(
      `printf '%s' '${Buffer.from(expectedUnit, "utf8").toString("base64")}' | base64 -d > '${unitFilePath}' && chmod '0644' '${unitFilePath}' && chown 'root:root' '${unitFilePath}'`
    )
    expect(mockSsh.calls).not.toContain("systemctl daemon-reload")
  })

  it("unmasks stale masked unit state before rewriting the compose systemd unit", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const serviceName = "mailcow"
    const serviceUnitPath = "/etc/systemd/system/mailcow.service"
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses(serviceName, serviceUnitPath),
      [`cat '${serviceUnitPath}'`]: {
        code: 0,
        stdout: expectedDetachedDockerUnit("/opt/mailcow-dockerized", serviceName),
      },
      "command -v docker": { code: 0 },
      "command -v podman": { code: 1 },
      "systemctl daemon-reload": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = compose.systemd({
      detached: true,
      name: serviceName,
      projectDirectory: "/opt/mailcow-dockerized",
      runtime: "docker",
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writtenFiles).toStrictEqual([
      {
        content: expectedDetachedDockerUnit("/opt/mailcow-dockerized", serviceName),
        path: serviceUnitPath,
      },
    ])
    expect(mockSsh.calls).toContain("systemctl unmask -- 'mailcow.service'")
    expect(mockSsh.calls).not.toContain("rm -f '/etc/systemd/system/mailcow.service'")
    expect(mockSsh.calls).toContain("systemctl daemon-reload")
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

  it("throws when explicit name looks like a systemctl option", () => {
    expect(() => compose.systemd({ name: "--user", projectDirectory })).toThrow(
      /name must not start with '-'/v
    )
  })

  it("explicit name is used as unit file name", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createComposeMockSsh({
      ...composeSystemdRecoveryResponses("my-stack", "/etc/systemd/system/my-stack.service"),
      "cat '/etc/systemd/system/my-stack.service'": {
        code: 0,
        stdout: expectedPodmanUnit(projectDirectory, "my-stack"),
      },
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
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("podman")} up -d 2>&1`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`${composeCmd("podman")} up -d 2>&1`)
    expect(mockSsh.calls).not.toContain(`${composeCmd("docker")} up -d 2>&1`)
  })

  it("uses explicit runtime override without detection", async () => {
    const mockSsh = createComposeMockSsh({
      [`${composeCmd("docker")} up -d 2>&1`]: { code: 0 },
    })
    const mod = compose.up({ projectDirectory, runtime: "docker" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`${composeCmd("docker")} up -d 2>&1`)
    expect(mockSsh.calls).not.toContain("command -v docker")
    expect(mockSsh.calls).not.toContain("command -v podman")
  })
})
