import { describe, expect, it, vi } from "vitest"

import { sha256String } from "../../src/modules/fileHelpers.js"
import { quadlet } from "../../src/modules/quadlet.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const quadletFilePath = "/etc/containers/systemd/traefik.container"

function buildReloadFlag(name: string, content: string): string {
  return `quadlet-container-${sha256String(name).slice(0, 16)}-${sha256String(content).slice(0, 16)}`
}

function buildReloadFlagCheck(name: string, content: string): string {
  return `[ -f /var/lib/paratix/flags/'${buildReloadFlag(name, content)}' ]`
}

function buildReloadFlagPersistCommand(name: string, content: string): string {
  const flagPrefix = `quadlet-container-${sha256String(name).slice(0, 16)}-`
  return `find /var/lib/paratix/flags -maxdepth 1 -type f -name '${flagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${buildReloadFlag(name, content)}'`
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
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    },
    {
      responseStubs: [
        {
          command: /^\[ -e '\/etc\/containers\/systemd\/[^']+\.container' \]$/v,
          result: { code: 1 },
        },
        // R-0000603: `applyQuadletFile` checks `isSymlink` before snapshot
        // and writeFile to refuse following a planted symlink. The default
        // for these tests is "not a symlink".
        {
          command: /^\[ -L '\/etc\/containers\/systemd\/[^']+\.container' \]$/v,
          result: { code: 1 },
        },
        {
          command:
            /^find \/var\/lib\/paratix\/flags -maxdepth 1 -type f -name 'quadlet-container-[0-9a-f]{16}-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'quadlet-container-[0-9a-f]{16}-[0-9a-f]{16}'$/v,
          result: { code: 0 },
        },
      ],
    }
  )
}

function overrideExecForCommand(
  ssh: ReturnType<typeof createMockSsh>,
  command: string,
  stdouts: string[]
): void {
  const originalExec = ssh.exec.bind(ssh)
  let callIndex = 0
  vi.spyOn(ssh, "exec").mockImplementation(async (target, options) => {
    const matches = target === command
    const next = matches ? Math.min(callIndex, stdouts.length - 1) : -1
    if (matches) {
      callIndex += 1
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: stdouts[next] ?? "" }
    }
    return originalExec(target, options)
  })
}

describe("quadlet.container", () => {
  it("check returns ok when the remote quadlet matches", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      // R-0000762: pin the symlink probe to "not a symlink".
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
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
      // R-0000762: the symlink probe runs before the existence probe.
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the quadlet content differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      // R-0000762: check refuses symlinks up front; pin to non-symlink so
      // the content-drift assertion still exercises the real codepath.
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: "[Unit]\nDescription=Old\n" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when content matches but mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      // R-0000762: pin the symlink probe to "not a symlink" so the mode
      // drift branch is the assertion under test.
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when stat for the quadlet file mode fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      // R-0000762: pin the symlink probe to "not a symlink".
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 1, stdout: "" },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when daemon-reload marker is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      // R-0000762: pin the symlink probe to "not a symlink".
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { code: 0, stdout: expectedQuadletContent() },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "644\n" },
      [buildReloadFlagCheck("traefik", expectedQuadletContent())]: { code: 1 },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("R-0000762: check returns needs-apply when the quadlet file is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ -L '${quadletFilePath}' ]`]: { code: 0 },
    })

    const result = await createQuadletModule().check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("apply creates the quadlet directory, writes the file, and reloads systemd", async () => {
    const flagCommand = buildReloadFlagPersistCommand("traefik", expectedQuadletContent())
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 1 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [flagCommand]: { code: 0 },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("mkdir -p '/etc/containers/systemd'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain(flagCommand)
    expect(writeFile).toHaveBeenCalledWith(quadletFilePath, expectedQuadletContent(), {
      mode: "0644",
    })
  })

  it("apply rejects an unstubbed apply exec", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 1 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
    })
    vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await expect(createQuadletModule().apply(ssh, emptyEnv)).rejects.toThrow(
      "createMockSsh: unstubbed exec call: systemctl daemon-reload"
    )
  })

  it("apply returns failed when creating the quadlet directory fails", async () => {
    const ssh = createMockSsh({
      "mkdir -p '/etc/containers/systemd'": { code: 1, stderr: "mkdir failed" },
    })

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain(
      buildReloadFlagPersistCommand("traefik", expectedQuadletContent())
    )
  })

  it("apply returns failed when systemctl daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 1 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`rm -f '${quadletFilePath}'`]: { code: 0 },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })
    vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain(`rm -f '${quadletFilePath}'`)
  })

  it("apply returns failed without rollback when persisting the reload flag fails", async () => {
    const flagCommand = buildReloadFlagPersistCommand("traefik", expectedQuadletContent())
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 1 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [flagCommand]: { code: 1, stderr: "read-only file system" },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const order: string[] = []
    const originalExec = ssh.exec.bind(ssh)
    vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
      order.push(command)
      return originalExec(command, options)
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockImplementation(async () => {
      await Promise.resolve()
      order.push("writeFile")
    })

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to persist versioned flag")
    expect(writeFile).toHaveBeenCalledWith(quadletFilePath, expectedQuadletContent(), {
      mode: "0644",
    })
    expect(order).toContain("writeFile")
    expect(order).toContain("systemctl daemon-reload")
    expect(order).toContain(flagCommand)
    expect(order.indexOf("writeFile")).toBeLessThan(order.indexOf("systemctl daemon-reload"))
    expect(order.indexOf("systemctl daemon-reload")).toBeLessThan(order.indexOf(flagCommand))
    expect(ssh.calls).not.toContain(`rm -f '${quadletFilePath}'`)
  })

  it("R-0000182: restores snapshot and returns failed when writeFile throws", async () => {
    const previousContent = "[Container]\nImage=docker.io/library/traefik:v3.2\n"
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP partial write"))
      .mockResolvedValueOnce()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("SFTP partial write")
    // First call: the new content; second: the restore from snapshot.
    // R-0000604: snapshot mode is normalized to the canonical 4-digit form
    // (`"600"` -> `"0600"`) before it is handed to `ssh.writeFile`.
    expect(writeFile).toHaveBeenNthCalledWith(1, quadletFilePath, expectedQuadletContent(), {
      mode: "0644",
    })
    expect(writeFile).toHaveBeenNthCalledWith(2, quadletFilePath, previousContent, {
      mode: "0600",
    })
  })

  it("reports write and rollback failures when writeFile and restore both fail", async () => {
    const previousContent = "[Container]\nImage=docker.io/library/traefik:v3.2\n"
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
    })
    vi.spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP partial write"))
      .mockRejectedValueOnce(new Error("rollback write failed: ENOSPC"))

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to write quadlet file")
    expect(result.error?.message).toContain("SFTP partial write")
    expect(result.error?.message).toContain("rollback failed")
    expect(result.error?.message).toContain("rollback write failed: ENOSPC")
  })

  it("restores an existing quadlet when systemctl daemon-reload fails", async () => {
    const previousContent = "[Container]\nImage=docker.io/library/traefik:v3.2\n"
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writeFile).toHaveBeenNthCalledWith(1, quadletFilePath, expectedQuadletContent(), {
      mode: "0644",
    })
    // R-0000604: snapshot mode is normalized to the canonical 4-digit form
    // (`"600"` -> `"0600"`) before it is handed to `ssh.writeFile`.
    expect(writeFile).toHaveBeenNthCalledWith(2, quadletFilePath, previousContent, {
      mode: "0600",
    })
  })

  it("reports daemon-reload and rollback failures when both fail", async () => {
    const previousContent = "[Container]\nImage=docker.io/library/traefik:v3.2\n"
    const ssh = createMockSsh({
      [`[ -e '${quadletFilePath}' ]`]: { code: 0 },
      [`[ -L '${quadletFilePath}' ]`]: { code: 1 },
      [`cat '${quadletFilePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${quadletFilePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "systemctl daemon-reload": { code: 1, stderr: "reload failed" },
    })
    vi.spyOn(ssh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("rollback write failed: ENOSPC"))

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("systemctl daemon-reload failed")
    expect(result.error?.message).toContain("reload failed")
    expect(result.error?.message).toContain("rollback failed")
    expect(result.error?.message).toContain("rollback write failed: ENOSPC")
  })

  it("R-0000603: refuses to apply when the quadlet path is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ -L '${quadletFilePath}' ]`]: { code: 0 },
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
    })
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await createQuadletModule().apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to write through symlink")
    expect(result.error?.message).toContain(quadletFilePath)
    expect(writeFile).not.toHaveBeenCalled()
    expect(ssh.calls).not.toContain(`cat '${quadletFilePath}'`)
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
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
      // R-0000762: pin the symlink probe to "not a symlink".
      [`[ -L '${filePath}' ]`]: { code: 1 },
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

  it("throws when the image contains a newline", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest\ninjected",
        name: "nginx",
      })
    }).toThrow(/image must match/v)
  })

  it("throws when the image contains a NUL byte", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest\0",
        name: "nginx",
      })
    }).toThrow(/image must match/v)
  })

  it("throws when the image contains whitespace", () => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx :latest",
        name: "nginx",
      })
    }).toThrow(/image must match/v)
  })

  it("throws when the image is empty", () => {
    expect(() => {
      quadlet.container({
        image: "",
        name: "nginx",
      })
    }).toThrow(/image must not be empty/v)
  })

  it("throws when the image exceeds the length limit", () => {
    const overlyLong = `docker.io/library/${"a".repeat(600)}:latest`
    expect(() => {
      quadlet.container({
        image: overlyLong,
        name: "nginx",
      })
    }).toThrow(/image must not exceed/v)
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

  it("quotes Environment values that contain systemd token separators", async () => {
    const mod = quadlet.container({
      environment: {
        APP_GREETING: 'hello "world"',
        APP_PATH: String.raw`C:\Program Files\App`,
        APP_TOKEN: "abc-123_./:@%+=",
      },
      image: "docker.io/library/nginx:latest",
      name: "quoted-env",
    })

    const ssh = createSuccessfulApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    expect(content).toContain('Environment=APP_GREETING="hello \\"world\\""')
    expect(content).toContain('Environment=APP_PATH="C:\\\\Program Files\\\\App"')
    // R-0000562: literal `%` now triggers the safe-quoting path (so an
    // attacker-controlled value cannot smuggle a systemd specifier like
    // `%n`/`%t`/`%h`/`%i` past the value parser), and the doubled `%%`
    // tells systemd to render a literal `%` instead of expanding it.
    expect(content).toContain('Environment=APP_TOKEN="abc-123_./:@%%+="')
  })

  it("rejects invalid Environment keys", () => {
    expect(() => {
      quadlet.container({
        environment: { "APP-NAME": "nginx" },
        image: "docker.io/library/nginx:latest",
        name: "invalid-env-key",
      })
    }).toThrow("environment key is invalid")
  })

  it("rejects Environment values with newlines", () => {
    expect(() => {
      quadlet.container({
        environment: { APP_CONFIG: "line-one\nline-two" },
        image: "docker.io/library/nginx:latest",
        name: "invalid-env-value",
      })
    }).toThrow("environment values must not contain newlines")
  })

  it.each([
    ["WorkingDir", { workingDir: "/srv/app\nprod" }],
    ["Volume", { volumes: ["/srv/app:/app\nro"] }],
    ["Label", { label: { "com.example.role": "web\nadmin" } }],
    ["Label key", { label: { "com.example.\nrole": "web" } }],
    ["PodmanArgs", { podmanArgs: ["--log-driver\njournald"] }],
    ["HealthCmd", { healthCmd: "curl -f http://localhost/\nstatus" }],
  ])("rejects control characters in %s", (_field, options) => {
    expect(() => {
      quadlet.container({
        image: "docker.io/library/nginx:latest",
        name: "invalid-control-character",
        ...options,
      })
    }).toThrow("values must not contain control characters")
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        {
          code: 0,
          stdout: "sha256:local-image-id\ndocker.io/library/traefik@sha256:registry-digest\n",
        },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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
    expect(ssh.calls).toContain(
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'"
    )
    expect(ssh.calls).toContain("podman pull -- 'docker.io/library/traefik:v3.3'")
    expect(ssh.calls).toContain("systemctl restart -- 'traefik'")
  })

  it("returns ok and skips restart when the image is already up to date", async () => {
    // R-0000183: pre-pull and post-pull inspects must return identical IDs
    // for the "no change" branch.
    const inspectStdout = "sha256:stable-local-id\ndocker.io/library/traefik@sha256:stable-digest\n"
    const ssh = createMockSsh({
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        { code: 0, stdout: inspectStdout },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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

  it("R-0000183: detects change when image ID differs even if pull output is non-English", async () => {
    // Simulate a localised podman that prints German strings: the previous
    // English-only heuristic would miss the change. The fixed implementation
    // still detects it because the local image ID changed.
    const inspectCommand =
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'"
    const inspectStdouts = [
      "sha256:old-local-id\ndocker.io/library/traefik@sha256:old-digest\n",
      "sha256:new-local-id\ndocker.io/library/traefik@sha256:new-digest\n",
    ]
    const ssh = createMockSsh({
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
        code: 0,
        stdout: "Lade BLOB sha256:abc\nManifest wird gespeichert\n",
      },
      "systemctl restart -- 'traefik'": { code: 0 },
    })
    overrideExecForCommand(ssh, inspectCommand, inspectStdouts)

    const result = await quadlet
      .updateImage({
        image: "docker.io/library/traefik:v3.3",
        name: "traefik",
      })
      .apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl restart -- 'traefik'")
  })

  it("passes authFile to podman pull for private registries", async () => {
    const authFilePullCommand =
      "podman pull --authfile '/run/containers/auth.json' -- 'ghcr.io/acme/private-app:latest'"
    const ssh = createMockSsh({
      [authFilePullCommand]: {
        code: 0,
        stdout: "Downloaded newer image for ghcr.io/acme/private-app:latest",
      },
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'ghcr.io/acme/private-app:latest'":
        {
          code: 0,
          stdout:
            "sha256:private-local-id\nghcr.io/acme/private-app@sha256:private-registry-digest\n",
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'ghcr.io/acme/private-app:latest'":
        {
          code: 0,
          stdout:
            "sha256:canary-local-id\nghcr.io/acme/private-app@sha256:canary-registry-digest\n",
        },
      "podman pull -- 'ghcr.io/acme/private-app:latest'": {
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        {
          code: 125,
          stderr: "inspect failed",
        },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        {
          code: 0,
          stdout: "",
        },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        {
          code: 0,
          stdout: "sha256:local-only-id\n",
        },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        { code: 1, stderr: "no such image" },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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
      "podman image inspect --format '{{.Id}}\\n{{range .RepoDigests}}{{.}}\\n{{end}}' -- 'docker.io/library/traefik:v3.3'":
        {
          code: 0,
          stdout:
            "sha256:restart-local-id\ndocker.io/library/traefik@sha256:restart-registry-digest\n",
        },
      "podman pull -- 'docker.io/library/traefik:v3.3'": {
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

function networkFilePath(name: string): string {
  return `/etc/containers/systemd/${name}.network`
}

function buildNetworkReloadFlag(name: string, content: string): string {
  return `quadlet-network-${sha256String(name).slice(0, 16)}-${sha256String(content).slice(0, 16)}`
}

function buildNetworkReloadFlagCheck(name: string, content: string): string {
  return `[ -f /var/lib/paratix/flags/'${buildNetworkReloadFlag(name, content)}' ]`
}

function createNetworkApplySsh(options: { networkExists?: boolean } = {}) {
  return createMockSsh(
    {
      "mkdir -p '/etc/containers/systemd'": { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    },
    {
      responseStubs: [
        {
          command: /^\[ -e '\/etc\/containers\/systemd\/[^']+\.network' \]$/v,
          result: { code: 1 },
        },
        {
          command: /^\[ -L '\/etc\/containers\/systemd\/[^']+\.network' \]$/v,
          result: { code: 1 },
        },
        {
          command:
            /^find \/var\/lib\/paratix\/flags -maxdepth 1 -type f -name 'quadlet-network-[0-9a-f]{16}-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'quadlet-network-[0-9a-f]{16}-[0-9a-f]{16}'$/v,
          result: { code: 0 },
        },
        {
          command: /^podman network exists -- '[^']+'$/v,
          result: { code: options.networkExists === true ? 0 : 1 },
        },
      ],
    }
  )
}

describe("quadlet.network", () => {
  it("generates the full [Network] section in the documented order", async () => {
    const mod = quadlet.network({
      description: "App backend network",
      disableDns: false,
      dns: ["10.89.0.1", "10.89.0.2"],
      driver: "bridge",
      gateway: "10.89.0.1",
      internal: true,
      ipamDriver: "host-local",
      ipRange: "10.89.0.128/25",
      ipv6: true,
      label: { env: "prod", tier: "backend" },
      name: "app",
      options: { isolate: "true", mtu: "1500" },
      podmanArgs: ["--opt vlan=100"],
      subnet: "10.89.0.0/24",
    })

    const ssh = createNetworkApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writeFile).toHaveBeenCalledWith(
      networkFilePath("app"),
      [
        "[Unit]",
        "Description=App backend network",
        "",
        "[Network]",
        "NetworkName=app",
        "Driver=bridge",
        "IPAMDriver=host-local",
        "Internal=true",
        "IPv6=true",
        "DisableDNS=false",
        "Subnet=10.89.0.0/24",
        "Gateway=10.89.0.1",
        "IPRange=10.89.0.128/25",
        "DNS=10.89.0.1",
        "DNS=10.89.0.2",
        "Options=isolate=true",
        "Options=mtu=1500",
        "Label=env=prod",
        "Label=tier=backend",
        "PodmanArgs=--opt vlan=100",
      ].join("\n"),
      { mode: "0644" }
    )
  })

  it("generates a minimal unit with only name set", async () => {
    const mod = quadlet.network({ name: "app" })

    const ssh = createNetworkApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    expect(writeFile.mock.calls[0][1]).toBe(
      ["[Unit]", "Description=Podman network: app", "", "[Network]", "NetworkName=app"].join("\n")
    )
  })

  it("apply writes the .network file, reloads systemd, and persists the flag", async () => {
    const mod = quadlet.network({ internal: true, name: "app" })
    const ssh = createNetworkApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.detail).toBeUndefined()
    expect(ssh.calls).toContain("mkdir -p '/etc/containers/systemd'")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(writeFile).toHaveBeenCalledWith(networkFilePath("app"), expect.any(String), {
      mode: "0644",
    })
  })

  it("appends an advisory detail when the live network already exists", async () => {
    const mod = quadlet.network({ name: "app", subnet: "10.89.0.0/24" })
    const ssh = createNetworkApplySsh({ networkExists: true })
    vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.detail).toContain("already exists")
    expect(result.detail).toContain("app")
    expect(ssh.calls).toContain("podman network exists -- 'app'")
  })

  it("omits the advisory detail when podman network exists cannot confirm the network", async () => {
    const mod = quadlet.network({ name: "app" })
    const ssh = createNetworkApplySsh({ networkExists: false })
    vi.spyOn(ssh, "writeFile").mockResolvedValue()

    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.detail).toBeUndefined()
  })

  it("returns failed when no SSH connection is available", async () => {
    const { apply } = quadlet.network({ name: "app" })
    const result = await apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("check returns ok when the remote unit matches and the flag is present", async () => {
    const content = [
      "[Unit]",
      "Description=Podman network: app",
      "",
      "[Network]",
      "NetworkName=app",
    ].join("\n")
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644\n" },
      [buildNetworkReloadFlagCheck("app", content)]: { code: 0 },
    })

    const result = await quadlet.network({ name: "app" }).check(ssh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the daemon-reload flag is missing", async () => {
    const content = [
      "[Unit]",
      "Description=Podman network: app",
      "",
      "[Network]",
      "NetworkName=app",
    ].join("\n")
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { code: 0, stdout: content },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644\n" },
      [buildNetworkReloadFlagCheck("app", content)]: { code: 1 },
    })

    const result = await quadlet.network({ name: "app" }).check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the unit file is missing", async () => {
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
    })

    const result = await quadlet.network({ name: "app" }).check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the on-disk unit content differs", async () => {
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`cat '${filePath}'`]: { code: 0, stdout: "[Network]\nNetworkName=stale\n" },
    })

    const result = await quadlet.network({ name: "app" }).check(ssh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("uses a reload-flag namespace distinct from quadlet.container for the same name", () => {
    const content = [
      "[Unit]",
      "Description=Podman network: app",
      "",
      "[Network]",
      "NetworkName=app",
    ].join("\n")
    expect(buildNetworkReloadFlag("app", content)).toContain("quadlet-network-")
    expect(buildNetworkReloadFlag("app", content)).not.toBe(buildReloadFlag("app", content))
  })

  it("_applyDryRun returns a diff when the on-disk unit differs", async () => {
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: "[Network]\nNetworkName=old\n" },
      "podman network exists -- 'app'": { code: 1 },
    })

    const mod = quadlet.network({ name: "app" })
    const result = await mod._applyDryRun?.(ssh, emptyEnv)

    expect(result?.status).toBe("changed")
    expect(result?.diff).toContain("NetworkName=app")
    expect(result?._dryRunDetail).toBeUndefined()
  })

  it("_applyDryRun surfaces the advisory detail when the live network exists", async () => {
    const filePath = networkFilePath("app")
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: "[Network]\nNetworkName=old\n" },
      "podman network exists -- 'app'": { code: 0 },
    })

    const mod = quadlet.network({ name: "app" })
    const result = await mod._applyDryRun?.(ssh, emptyEnv)

    expect(result?.diff).toContain("NetworkName=app")
    expect(result?._dryRunDetail).toContain("already exists")
  })

  it("throws when the network name is invalid", () => {
    expect(() => {
      quadlet.network({ name: "../evil" })
    }).toThrow(/name must match/v)
  })

  it("throws when the network name looks like a systemctl option", () => {
    expect(() => {
      quadlet.network({ name: "--internal" })
    }).toThrow(/name must not start with '-'/v)
  })

  it("throws when a value contains control characters", () => {
    expect(() => {
      quadlet.network({ name: "app", subnet: "10.0.0.0/24\ninjected" })
    }).toThrow("values must not contain control characters")
  })

  it("renders Label and Options as repeated key=value lines sorted by key", async () => {
    // Build the records with deliberately unsorted insertion order so the
    // assertion proves the module sorts, not the source literal.
    const label: Record<string, string> = {}
    label.beta = "b"
    label.alpha = "a"
    const networkOptions: Record<string, string> = {}
    networkOptions.mtu = "1500"
    networkOptions.isolate = "true"
    const mod = quadlet.network({ label, name: "sorted", options: networkOptions })
    const ssh = createNetworkApplySsh()
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()

    await mod.apply(ssh, emptyEnv)

    const content = writeFile.mock.calls[0][1]
    expect(content.indexOf("Label=alpha=a")).toBeLessThan(content.indexOf("Label=beta=b"))
    expect(content.indexOf("Options=isolate=true")).toBeLessThan(
      content.indexOf("Options=mtu=1500")
    )
  })
})
