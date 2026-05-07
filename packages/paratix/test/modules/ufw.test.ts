import { describe, expect, it } from "vitest"

import { ufw } from "../../src/modules/ufw.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}
const DPKG_STATUS_LITERAL = ["${", "Status}"].join("")
const DPKG_UFW_INSTALLED = `dpkg-query -W -f='${DPKG_STATUS_LITERAL}' 'ufw' 2>/dev/null | grep -q 'install ok installed'`

function createMockSshOnPort(
  responses: Parameters<typeof createMockSsh>[0],
  port: number
): ReturnType<typeof createMockSsh> {
  const ssh = createMockSsh(responses)
  ssh.getConnectionInfo = () => ({
    authMethod: "privateKey",
    host: "1.2.3.4",
    port,
    privateKeyPath: "~/.ssh/id",
    user: "root",
  })
  return ssh
}

describe("ufw.enabled", () => {
  it("check returns ok when ufw is active and the current SSH port is allowed", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22                         ALLOW       Anywhere",
          ].join("\n"),
        },
      },
      22
    )
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when ufw is active and both SSH port address families are allowed", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22                         ALLOW       Anywhere",
            "22 (v6)                    ALLOW       Anywhere (v6)",
          ].join("\n"),
        },
      },
      22
    )
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when IPv6 is enabled but lacks the SSH allow rule", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22                         ALLOW       Anywhere",
            "80 (v6)                    ALLOW       Anywhere (v6)",
          ].join("\n"),
        },
      },
      22
    )
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ufw is active but the current SSH port is missing", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "80                         ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when ufw is active and custom SSH port 2222 is allowed", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "2222                       ALLOW       Anywhere",
          ].join("\n"),
        },
      },
      2222
    )

    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when only a protocol-specific SSH allow rule exists", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22/tcp                     ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when a similar port is allowed instead of the SSH port", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "5022                       ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the current SSH port has a deny rule", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ufw is inactive", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "Status: inactive" },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ufw.enabled()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000064 regression: the apply must use the officially supported
  // `--force` flag rather than the legacy `echo 'y' | ufw enable` pipe so
  // the call mirrors ufw.disabled and does not rely on the wording of the
  // interactive Y/N prompt.
  it("apply returns changed when ufw --force enable succeeds", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 0 },
      "ufw allow '22'": { code: 0 },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual(["ufw allow '22'", "ufw --force enable"])
    expect(ssh.calls).toContain("ufw --force enable")
    expect(ssh.calls).not.toContain("echo 'y' | ufw enable")
  })

  it("apply allows the active SSH port before enabling ufw", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '2222'": { code: 0 },
      },
      2222
    )

    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual(["ufw allow '2222'", "ufw --force enable"])
  })

  it("apply fails without enabling when allowing the active SSH port fails", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 0 },
      "ufw allow '22'": { code: 1, stderr: "bad port" },
    })

    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual(["ufw allow '22'"])
  })

  it("apply returns failed when ufw --force enable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 1 },
      "ufw allow '22'": { code: 0 },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ufw.enabled()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("ufw.disabled", () => {
  it("check returns ok when ufw is not installed", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 1 },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when ufw is inactive", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "ufw status": { stdout: "Status: inactive" },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when ufw is active", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "ufw status": { stdout: "Status: active" },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns ok when ufw is not installed", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 1 },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("ufw --force disable")
  })

  it("apply returns changed when ufw disable succeeds", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "ufw --force disable": { code: 0 },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("ufw --force disable")
  })

  it("apply returns failed when ufw disable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "ufw --force disable": { code: 1 },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("ufw.rule", () => {
  it("check returns ok for an allow rule on a single port", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "80                         ALLOW       Anywhere" },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok for a deny rule on a single port", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "22                         DENY        Anywhere" },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when IPv4 and IPv6 protocol-agnostic rules are both present", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
          "22 (v6)                    DENY        Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when IPv6 status is present but the matching v6 rule is missing", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
          "80 (v6)                    ALLOW       Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when one port in a multi-port rule is missing", async () => {
    const ssh = createMockSsh({
      "ufw status": { stdout: "80                         ALLOW       Anywhere" },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when a single-port allow rule succeeds", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '80'": { code: 0 },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("ufw 'allow' '80'")
  })

  it("apply runs all commands for a multi-port rule in order", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0 },
      "ufw 'allow' '80'": { code: 0 },
      "ufw 'allow' '8080'": { code: 0 },
    })
    const mod = ufw.rule("allow", [80, 443, 8080])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual(["ufw 'allow' '80'", "ufw 'allow' '443'", "ufw 'allow' '8080'"])
  })

  // R-0000076 regression: when ufw prints "Skipping adding existing rule"
  // for every port, apply must return ok rather than always claiming the
  // run changed something.
  it("apply returns ok when ufw skips every existing rule", async () => {
    const skipOutput = "Skipping adding existing rule\nSkipping adding existing rule (v6)\n"
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0, stdout: skipOutput },
      "ufw 'allow' '80'": { code: 0, stdout: skipOutput },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).toStrictEqual(["ufw 'allow' '80'", "ufw 'allow' '443'"])
  })

  it("apply returns changed when ufw adds every rule fresh", async () => {
    const addedOutput = "Rule added\nRule added (v6)\n"
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0, stdout: addedOutput },
      "ufw 'allow' '80'": { code: 0, stdout: addedOutput },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns changed when at least one port is new and others are skipped", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
      "ufw 'allow' '80'": {
        code: 0,
        stdout: "Skipping adding existing rule\nSkipping adding existing rule (v6)\n",
      },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns changed when only one address family is added", async () => {
    const ssh = createMockSsh({
      "ufw 'deny' '22'": {
        code: 0,
        stdout: "Skipping adding existing rule\nRule added (v6)\n",
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed and stops when one port command fails", async () => {
    const ssh = createMockSsh({
      "ufw 'deny' '22'": { code: 0 },
      "ufw 'deny' '25'": { code: 1 },
      "ufw 'deny' '465'": { code: 0 },
    })
    const mod = ufw.rule("deny", [22, 25, 465])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual(["ufw 'deny' '22'", "ufw 'deny' '25'"])
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ufw.rule("allow", [80, 443])
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("uses the expected module name for multiple ports", () => {
    const mod = ufw.rule("allow", [80, 443])
    expect(mod.name).toBe("ufw.rule: allow 80,443")
  })

  it("check returns needs-apply when only a port with the same suffix is configured (allow)", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "5022                       ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when only a port with the same suffix is configured (deny)", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "522                        DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when an unrelated multi-digit port shares the suffix", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "2222                       ALLOW       Anywhere",
          "1022                       ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000118 regression: the caller asked for `ufw allow 22` (no
  // protocol qualifier), but only a `22/tcp` rule is present on the host.
  // That is drift, not a satisfied rule, because apply would otherwise
  // add a second protocol-agnostic rule on top of the existing tcp-only
  // entry.
  it("check returns needs-apply when only a protocol-specific /tcp rule exists", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22/tcp                     ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when only a protocol-specific /udp rule exists", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "53/udp                     ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 53)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000118: invalid port values must be rejected at construction time
  // rather than first surfacing when ufw refuses the rule on the host.
  it("throws when constructed with a non-integer port", () => {
    expect(() => ufw.rule("allow", 22.5)).toThrow(
      "ufw.rule requires integer ports between 1 and 65535, got 22.5"
    )
  })

  it("throws when constructed with a port below 1", () => {
    expect(() => ufw.rule("allow", 0)).toThrow(
      "ufw.rule requires integer ports between 1 and 65535, got 0"
    )
  })

  it("throws when constructed with a port above 65535", () => {
    expect(() => ufw.rule("allow", 70_000)).toThrow(
      "ufw.rule requires integer ports between 1 and 65535, got 70000"
    )
  })

  it("throws when one port in a multi-port rule is invalid", () => {
    expect(() => ufw.rule("allow", [80, -1, 443])).toThrow(
      "ufw.rule requires integer ports between 1 and 65535, got -1"
    )
  })
})
