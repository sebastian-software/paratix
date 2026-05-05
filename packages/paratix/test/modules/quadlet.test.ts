import { describe, expect, it, vi } from "vitest"

import { sha256String } from "../../src/modules/fileHelpers.js"
import { quadlet } from "../../src/modules/quadlet.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const quadletFilePath = "/etc/containers/systemd/traefik.container"
const traefikReloadFlagPrefix = `quadlet-container-${sha256String("traefik").slice(0, 16)}-`

function buildReloadFlag(name: string, content: string): string {
  return `quadlet-container-${sha256String(name).slice(0, 16)}-${sha256String(content).slice(0, 16)}`
}

function buildReloadFlagCheck(name: string, content: string): string {
  return `[ -f /var/lib/paratix/flags/'${buildReloadFlag(name, content)}' ]`
}

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
    "Network=proxy",
    "PodmanArgs=--log-driver journald",
    "PublishPort=80:80",
    "PublishPort=443:443",
    "Volume=/etc/traefik:/etc/traefik:Z",
    "Volume=/var/log/traefik:/var/log/traefik:Z",
    "Environment=DOMAIN=example.com",
    "Environment=TZ=Europe/Berlin",
    "",
    "[Service]",
    "Restart=always",
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

function createSuccessfulApplySsh() {
  return createMockSsh(
    {
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    },
    { defaultExecResult: { code: 0 } }
  )
}

describe("quadlet.container", () => {
  it("check returns ok when the remote quadlet matches", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "644\n" },
      [buildReloadFlagCheck("traefik", expectedQuadletContent())]: { code: 0 },
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

  it("check returns needs-apply when content matches but mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when stat for the quadlet file mode fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 1, stdout: "" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when daemon-reload marker is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "644\n" },
      [buildReloadFlagCheck("traefik", expectedQuadletContent())]: { code: 1 },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("apply creates the quadlet directory, writes the file, and reloads systemd", async () => {
    const ssh = createMockSsh({
      [`find /var/lib/paratix/flags -maxdepth 1 -name '${traefikReloadFlagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${buildReloadFlag("traefik", expectedQuadletContent())}'`]:
        { code: 0 },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("mkdir -p '/etc/containers/systemd'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain(
      `find /var/lib/paratix/flags -maxdepth 1 -name '${traefikReloadFlagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${buildReloadFlag("traefik", expectedQuadletContent())}'`
    )
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
    expect(ssh.calls).not.toContain(
      `find /var/lib/paratix/flags -maxdepth 1 -name '${traefikReloadFlagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${buildReloadFlag("traefik", expectedQuadletContent())}'`
    )
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
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644\n" },
      [buildReloadFlagCheck("pocket-id", expectedContent)]: { code: 0 },
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

    const ssh = createSuccessfulApplySsh()
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

    const ssh = createSuccessfulApplySsh()
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

  it("throws when the quadlet name looks like a systemctl option", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest",
        name: "--user",
      })
    }).toThrow(/name must not start with '-'/v)
  })

  it("throws when the image value looks like a podman option", () => {
    expect(() => {
      quadlet.container({
        image: "--tls-verify=false",
        name: "nginx",
      })
    }).toThrow(/image must not start with '-'/v)
  })

  it("generates all container section fields in correct order", async () => {
    const mod = quadlet.container({
      addCapability: ["NET_ADMIN"],
      addDevice: ["/dev/net/tun"],
      annotation: { "io.containers.autoupdate": "registry" },
      dns: ["1.1.1.1"],
      dnsOption: ["ndots:5"],
      dnsSearch: ["example.com"],
      dropCapability: ["ALL"],
      entrypoint: ["/entrypoint.sh"],
      environment: { APP: "test" },
      exposeHostPort: ["9090"],
      groupAdd: ["audio"],
      hostName: "myhost",
      image: "docker.io/library/nginx:latest",
      ip: "10.88.0.10",
      ip6: "fd00::10",
      label: { "app.version": "1.0" },
      logDriver: "journald",
      mask: ["/proc/acpi"],
      mount: ["type=tmpfs,tmpfs-size=512M,destination=/tmp"],
      name: "full-container",
      networks: ["backend"],
      noNewPrivileges: true,
      notify: true,
      podmanArgs: ["--cgroups=split"],
      publishPorts: ["8080:80"],
      pull: "always",
      readOnly: true,
      runInit: true,
      seccompProfile: "/etc/seccomp.json",
      secret: ["db-password"],
      securityLabelDisable: true,
      securityLabelType: "spc_t",
      stopTimeout: 30,
      sysctl: { "net.core.somaxconn": "1024" },
      timezone: "Europe/Berlin",
      tmpfs: ["/run"],
      ulimit: ["nofile=1024:2048"],
      unmask: ["/proc/latency_stats"],
      user: "1000:1000",
      userNs: "keep-id",
      volumes: ["/data:/data:Z"],
      workingDir: "/app",
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]

    // Verify all fields are present
    expect(content).toContain("Image=docker.io/library/nginx:latest")
    expect(content).toContain("Pull=always")
    expect(content).toContain("Entrypoint=/entrypoint.sh")
    expect(content).toContain("WorkingDir=/app")
    expect(content).toContain("User=1000:1000")
    expect(content).toContain("UserNS=keep-id")
    expect(content).toContain("GroupAdd=audio")
    expect(content).toContain("HostName=myhost")
    expect(content).toContain("Network=backend")
    expect(content).toContain("DNS=1.1.1.1")
    expect(content).toContain("DNSOption=ndots:5")
    expect(content).toContain("DNSSearch=example.com")
    expect(content).toContain("IP=10.88.0.10")
    expect(content).toContain("IP6=fd00::10")
    expect(content).toContain("AddCapability=NET_ADMIN")
    expect(content).toContain("DropCapability=ALL")
    expect(content).toContain("SecurityLabelDisable=true")
    expect(content).toContain("SecurityLabelType=spc_t")
    expect(content).toContain("SeccompProfile=/etc/seccomp.json")
    expect(content).toContain("NoNewPrivileges=true")
    expect(content).toContain("ReadOnly=true")
    expect(content).toContain("Notify=true")
    expect(content).toContain("RunInit=true")
    expect(content).toContain("LogDriver=journald")
    expect(content).toContain("Timezone=Europe/Berlin")
    expect(content).toContain("StopTimeout=30")
    expect(content).toContain("PodmanArgs=--cgroups=split")
    expect(content).toContain("PublishPort=8080:80")
    expect(content).toContain("ExposeHostPort=9090")
    expect(content).toContain("Volume=/data:/data:Z")
    expect(content).toContain("Mount=type=tmpfs,tmpfs-size=512M,destination=/tmp")
    expect(content).toContain("Tmpfs=/run")
    expect(content).toContain("AddDevice=/dev/net/tun")
    expect(content).toContain("Secret=db-password")
    expect(content).toContain("Environment=APP=test")
    expect(content).toContain("Label=app.version=1.0")
    expect(content).toContain("Annotation=io.containers.autoupdate=registry")
    expect(content).toContain("Sysctl=net.core.somaxconn=1024")
    expect(content).toContain("Ulimit=nofile=1024:2048")
    expect(content).toContain("Mask=/proc/acpi")
    expect(content).toContain("Unmask=/proc/latency_stats")
  })

  it("renders Restart in [Service] section, not [Container]", async () => {
    const mod = quadlet.container({
      image: "docker.io/library/nginx:latest",
      name: "svc-test",
      restart: "on-failure",
      timeoutStartSec: 90,
      timeoutStopSec: 30,
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    const containerSection = content.split("[Service]")[0]
    const serviceSection = content.split("[Service]")[1]?.split("[Install]")[0]

    expect(containerSection).not.toContain("Restart=")
    expect(serviceSection).toContain("Restart=on-failure")
    expect(serviceSection).toContain("TimeoutStartSec=90")
    expect(serviceSection).toContain("TimeoutStopSec=30")
  })

  it("omits [Service] section when no service fields are set", async () => {
    const mod = quadlet.container({
      image: "docker.io/library/nginx:latest",
      name: "no-svc",
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    expect(content).not.toContain("[Service]")
  })

  it("renders HealthOnFailure when healthCmd is set", async () => {
    const mod = quadlet.container({
      healthCmd: "curl -f http://localhost",
      healthOnFailure: "restart",
      image: "docker.io/library/nginx:latest",
      name: "health-on-fail",
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    expect(content).toContain("HealthOnFailure=restart")
  })

  it("renders boolean fields as true/false strings", async () => {
    const mod = quadlet.container({
      image: "docker.io/library/nginx:latest",
      name: "bool-test",
      noNewPrivileges: false,
      readOnly: false,
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    expect(content).toContain("NoNewPrivileges=false")
    expect(content).toContain("ReadOnly=false")
  })
})

describe("quadlet.updateImage", () => {
  it("always returns needs-apply from check", async () => {
    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .check(null, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("returns failed when no SSH connection is available", async () => {
    const mod = quadlet.updateImage({
      image: "docker.io/library/traefik:v3.3",
      name: "traefik",
    })
    const { apply } = mod
    const result = await apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("pulls the image and restarts the service when a newer image was downloaded", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'docker.io/library/traefik:v3.3'": {
        code: 0,
        stdout: JSON.stringify([
          {
            Id: "sha256:local-image-id",
            RepoDigests: ["docker.io/library/traefik@sha256:registry-digest"],
          },
        ]),
      },
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Copying blob sha256:123\nWriting manifest to image destination\n",
      },
      "systemctl restart -- 'traefik'": { code: 0 },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result).toMatchObject({
      detail: "(sha256:registry-digest)",
      status: "changed",
    })
    expect(ssh.calls).toContain("podman image inspect -- 'docker.io/library/traefik:v3.3'")
    expect(ssh.calls).toContain("podman pull -- 'docker.io/library/traefik:v3.3' 2>&1")
    expect(ssh.calls).toContain("systemctl restart -- 'traefik'")
  })

  it("returns ok and skips restart when the image is already up to date", async () => {
    const ssh = createMockSsh({
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Image is up to date",
      },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("systemctl restart -- 'traefik'")
  })

  it("passes authFile to podman pull for private registries", async () => {
    const authFilePullCommand =
      "podman pull --authfile '/run/containers/auth.json' -- 'ghcr.io/acme/private-app:latest' 2>&1"
    const ssh = createMockSsh({
      [authFilePullCommand]: {
        code: 0,
        stdout: "Downloaded newer image for ghcr.io/acme/private-app:latest",
      },
      "podman image inspect -- 'ghcr.io/acme/private-app:latest'": {
        code: 0,
        stdout: JSON.stringify([
          {
            Id: "sha256:private-local-id",
            RepoDigests: ["ghcr.io/acme/private-app@sha256:private-registry-digest"],
          },
        ]),
      },
      "systemctl restart -- 'private-app'": { code: 0 },
    })

    const result = await quadlet
      .updateImage({
        authFile: "/run/containers/auth.json",
        image: "ghcr.io/acme/private-app:latest",
        name: "private-app",
      })
      .apply(ssh, emptyEnv)

    expect(result).toMatchObject({
      detail: "(sha256:private-registry-digest)",
      status: "changed",
    })
    expect(ssh.calls).toContain(authFilePullCommand)
  })

  it("throws when the update image value looks like a podman option", () => {
    expect(() => {
      quadlet.updateImage({
        image: "--authfile=/tmp/evil",
        name: "private-app",
      })
    }).toThrow(/image must not start with '-'/v)
  })

  it("throws when the authFile value looks like a podman option", () => {
    expect(() => {
      quadlet.updateImage({
        authFile: "--creds=attacker",
        image: "ghcr.io/acme/private-app:latest",
        name: "private-app",
      })
    }).toThrow(/authFile must not start with '-'/v)
  })

  it("throws when the overridden service name looks like a systemctl option", () => {
    expect(() => {
      quadlet.updateImage({
        image: "ghcr.io/acme/private-app:latest",
        name: "private-app",
        serviceName: "--user",
      })
    }).toThrow(/name must not start with '-'/v)
  })

  it("restarts the overridden service name when provided", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'ghcr.io/acme/private-app:latest'": {
        code: 0,
        stdout: JSON.stringify([
          {
            Id: "sha256:canary-local-id",
            RepoDigests: ["ghcr.io/acme/private-app@sha256:canary-registry-digest"],
          },
        ]),
      },
      "podman pull -- 'ghcr.io/acme/private-app:latest' 2>&1": {
        code: 0,
        stdout: "Storing signatures\n",
      },
      "systemctl restart -- 'private-app-canary'": { code: 0 },
    })

    const result = await quadlet
      .updateImage({
        image: "ghcr.io/acme/private-app:latest",
        name: "private-app",
        serviceName: "private-app-canary",
      })
      .apply(ssh, emptyEnv)

    expect(result).toMatchObject({
      detail: "(sha256:canary-registry-digest)",
      status: "changed",
    })
    expect(ssh.calls).toContain("systemctl restart -- 'private-app-canary'")
  })

  it("returns failed when image inspection fails after a changed pull", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'docker.io/library/traefik:v3.3'": {
        code: 125,
        stderr: "inspect failed",
      },
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Copying config sha256:abc\n",
      },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain("systemctl restart -- 'traefik'")
  })

  it("returns failed when image inspection returns no ID", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'docker.io/library/traefik:v3.3'": {
        code: 0,
        stdout: JSON.stringify([{ Id: null, RepoDigests: [] }]),
      },
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Copying config sha256:abc\n",
      },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("falls back to the local image ID when no repo digest is available", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'docker.io/library/traefik:v3.3'": {
        code: 0,
        stdout: JSON.stringify([{ Id: "sha256:local-only-id", RepoDigests: [] }]),
      },
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Copying config sha256:abc\n",
      },
      "systemctl restart -- 'traefik'": { code: 0 },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result).toMatchObject({
      detail: "(sha256:local-only-id)",
      status: "changed",
    })
  })

  it("returns failed when podman pull exits non-zero", async () => {
    const ssh = createMockSsh({
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 125,
        stderr: "pull failed",
      },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns failed when restarting the service fails after a changed pull", async () => {
    const ssh = createMockSsh({
      "podman image inspect -- 'docker.io/library/traefik:v3.3'": {
        code: 0,
        stdout: JSON.stringify([
          {
            Id: "sha256:restart-local-id",
            RepoDigests: ["docker.io/library/traefik@sha256:restart-registry-digest"],
          },
        ]),
      },
      "podman pull -- 'docker.io/library/traefik:v3.3' 2>&1": {
        code: 0,
        stdout: "Copying config sha256:abc\n",
      },
      "systemctl restart -- 'traefik'": {
        code: 1,
        stderr: "restart failed",
      },
    })

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
  })
})
