import { describe, expect, it, vi } from "vitest"

import { quadlet } from "../../src/modules/quadlet.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const quadletFilePath = "/etc/containers/systemd/traefik.container"

function expectedQuadletContent(): string {
  return [
    "[Unit]",
    "Description=Edge proxy",
    "Wants=network-online.target",
    "After=network-online.target",
    "",
    "[Container]",
    "Image=docker.io/library/traefik:v3.3",
    "ContainerName=traefik",
    "AutoUpdate=registry",
    "Exec=--configFile /etc/traefik/traefik.yml",
    "Restart=always",
    "Network=proxy",
    "PodmanArgs=--log-driver journald",
    "PublishPort=80:80",
    "PublishPort=443:443",
    "Volume=/etc/traefik:/etc/traefik:Z",
    "Volume=/var/log/traefik:/var/log/traefik:Z",
    "Environment=DOMAIN=example.com",
    "Environment=TZ=Europe/Berlin",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
  ].join("\n")
}

function createQuadletModule() {
  return quadlet.container({
    autoUpdate: "registry",
    containerName: "traefik",
    description: "Edge proxy",
    environment: {
      DOMAIN: "example.com",
      TZ: "Europe/Berlin",
    },
    exec: ["--configFile", "/etc/traefik/traefik.yml"],
    image: "docker.io/library/traefik:v3.3",
    name: "traefik",
    networks: ["proxy"],
    podmanArgs: ["--log-driver journald"],
    publishPorts: ["80:80", "443:443"],
    restart: "always",
    volumes: ["/etc/traefik:/etc/traefik:Z", "/var/log/traefik:/var/log/traefik:Z"],
  })
}

describe("quadlet.container", () => {
  it("check returns ok when the remote quadlet matches", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the quadlet is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 1 },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the quadlet content differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: "[Unit]\nDescription=Old\n" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("apply creates the quadlet directory, writes the file, and reloads systemd", async () => {
    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("mkdir -p '/etc/containers/systemd'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(writeFile).toHaveBeenCalledWith(quadletFilePath, expectedQuadletContent(), {
      mode: "0644",
    })
  })

  it("apply returns failed when creating the quadlet directory fails", async () => {
    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 1, stderr: "mkdir failed" },
    })

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("apply returns failed when systemctl daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })
    vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("generates EnvironmentFile and Healthcheck directives", async () => {
    const mod = quadlet.container({
      environmentFiles: ["/opt/pocket-id/pocket-id.env"],
      healthCmd: "/app/pocket-id healthcheck",
      healthInterval: "1m30s",
      healthRetries: 2,
      healthStartPeriod: "10s",
      healthTimeout: "5s",
      image: "ghcr.io/pocket-id/pocket-id:v2",
      name: "pocket-id",
      publishPorts: ["127.0.0.1:1411:1411"],
      volumes: ["/opt/pocket-id/data:/app/data"],
    })

    const expectedContent = [
      "[Unit]",
      "Description=Podman container: pocket-id",
      "Wants=network-online.target",
      "After=network-online.target",
      "",
      "[Container]",
      "Image=ghcr.io/pocket-id/pocket-id:v2",
      "PublishPort=127.0.0.1:1411:1411",
      "Volume=/opt/pocket-id/data:/app/data",
      "EnvironmentFile=/opt/pocket-id/pocket-id.env",
      "HealthCmd=/app/pocket-id healthcheck",
      "HealthInterval=1m30s",
      "HealthTimeout=5s",
      "HealthRetries=2",
      "HealthStartPeriod=10s",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
    ].join("\n")

    const filePath = "/etc/containers/systemd/pocket-id.container"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: expectedContent },
    })

    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("generates multiple EnvironmentFile directives", async () => {
    const mod = quadlet.container({
      environmentFiles: ["/opt/app/base.env", "/opt/app/secrets.env"],
      image: "docker.io/library/nginx:latest",
      name: "nginx",
    })

    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const writtenContent = writeFile.mock.calls[0][1]
    expect(writtenContent).toContain("EnvironmentFile=/opt/app/base.env")
    expect(writtenContent).toContain("EnvironmentFile=/opt/app/secrets.env")
  })

  it("omits healthcheck directives when healthCmd is not set", async () => {
    const mod = quadlet.container({
      healthInterval: "30s",
      healthRetries: 3,
      image: "docker.io/library/nginx:latest",
      name: "nginx-no-health",
    })

    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const writtenContent = writeFile.mock.calls[0][1]
    expect(writtenContent).not.toContain("HealthCmd")
    expect(writtenContent).not.toContain("HealthInterval")
    expect(writtenContent).not.toContain("HealthRetries")
  })

  it("throws when the quadlet name is invalid", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest",
        name: "../mailcow",
      })
    }).toThrow(/name must match/v)
  })
})
