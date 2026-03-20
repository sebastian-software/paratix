import { describe, expect, it } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { service } from "../../src/modules/service.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("service.running", () => {
  it("check returns ok when the service is active", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 0 },
    })
    const mod = service.running("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is inactive", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 1 },
    })
    const mod = service.running("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.running("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("service.enabled", () => {
  it("check returns ok when the service is enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 0 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is not enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 1 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.enabled("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when systemctl enable exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl enable 'nginx'": { code: 0 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl enable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl enable 'nginx'": { code: 1 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.enabled("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.running apply", () => {
  it("apply returns changed when systemctl start exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl start 'nginx'": { code: 0 },
    })
    const mod = service.running("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl start exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl start 'nginx'": { code: 1 },
    })
    const mod = service.running("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.running("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.stopped", () => {
  it("check returns ok when the service is inactive", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 1 },
    })
    const mod = service.stopped("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is active", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 0 },
    })
    const mod = service.stopped("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.stopped("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when systemctl stop exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl stop 'nginx'": { code: 0 },
    })
    const mod = service.stopped("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl stop exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl stop 'nginx'": { code: 1 },
    })
    const mod = service.stopped("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.stopped("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.disabled", () => {
  it("check returns ok when the service is not enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 1 },
    })
    const mod = service.disabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 0 },
    })
    const mod = service.disabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.disabled("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when systemctl disable exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl disable 'nginx'": { code: 0 },
    })
    const mod = service.disabled("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl disable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl disable 'nginx'": { code: 1 },
    })
    const mod = service.disabled("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.disabled("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.restart", () => {
  it("check always returns needs-apply", async () => {
    const mod = service.restart("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when systemctl restart exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl restart 'nginx'": { code: 0 },
    })
    const mod = service.restart("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl restart exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl restart 'nginx'": { code: 1 },
    })
    const mod = service.restart("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.restart("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.reload", () => {
  it("check always returns needs-apply", async () => {
    const mod = service.reload("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when systemctl reload exits with code 0", async () => {
    const ssh = createMockSsh({
      "systemctl reload 'nginx'": { code: 0 },
    })
    const mod = service.reload("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when systemctl reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl reload 'nginx'": { code: 1 },
    })
    const mod = service.reload("nginx")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.reload("nginx")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("service.facts", () => {
  it("check always returns ok", async () => {
    const mod = service.facts()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("apply parses systemctl list-units output and returns meta with service states", async () => {
    const ssh = createMockSsh({
      "systemctl list-units --type=service --all --no-pager --no-legend": {
        code: 0,
        stdout:
          "  nginx.service  loaded  active  running  A high performance web server\n  sshd.service   loaded  active  running  OpenBSD Secure Shell server\n",
      },
    })
    const mod = service.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    const environment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(environment, "service.nginx")).resolves.toBe("active")
    await expect(resolveEnvironment(environment, "service.sshd")).resolves.toBe("active")
  })

  it("apply handles inactive services correctly", async () => {
    const ssh = createMockSsh({
      "systemctl list-units --type=service --all --no-pager --no-legend": {
        code: 0,
        stdout: "  nginx.service  loaded  inactive  dead  A high performance web server\n",
      },
    })
    const mod = service.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    const environment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(environment, "service.nginx")).resolves.toBe("inactive")
  })

  it("apply returns empty meta when no services are listed", async () => {
    const ssh = createMockSsh({
      "systemctl list-units --type=service --all --no-pager --no-legend": {
        code: 0,
        stdout: "",
      },
    })
    const mod = service.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(await mergeEnvironmentFromMeta({}, result.meta)).toStrictEqual({})
  })

  it("apply returns failed when systemctl exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl list-units --type=service --all --no-pager --no-legend": {
        code: 1,
        stdout: "",
      },
    })
    const mod = service.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply strips leading Unicode bullet from failed units", async () => {
    const ssh = createMockSsh({
      "systemctl list-units --type=service --all --no-pager --no-legend": {
        code: 0,
        stdout:
          "\u25CF nginx.service  loaded  failed  failed  A high performance web server\n  sshd.service   loaded  active  running  OpenBSD Secure Shell server\n",
      },
    })
    const mod = service.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    const environment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(environment, "service.nginx")).resolves.toBe("failed")
    await expect(resolveEnvironment(environment, "service.sshd")).resolves.toBe("active")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = service.facts()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
