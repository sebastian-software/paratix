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

  it("throws when the quadlet name is invalid", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest",
        name: "../mailcow",
      })
    }).toThrow(/name must match/v)
  })
})
