import { describe, expect, it } from "vitest"

import { ufw } from "../../src/modules/ufw.js"
import {
  hasProtocolAgnosticIpv6Rule,
  hasProtocolAgnosticRule,
  hasTcpIpv6Rule,
  hasTcpRule,
} from "../../src/modules/ufwStatus.js"
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
    configuredPorts: [port],
    host: "1.2.3.4",
    port,
    privateKeyPath: "~/.ssh/id",
    user: "root",
  })
  return ssh
}

// R-0000615: stub the live sshd listener probe `ss -H -ltnp 'sport = :PORT'`
// for the given ports. Tests that exercise `ufw.rule("deny", ports)` need to
// stub this call so the apply path can prove the port is not currently served
// by sshd before continuing. Empty stdout with code 1 mirrors the real ss
// output when there is no listener on the queried port.
function noLiveSshdProbe(...ports: number[]): Record<string, { code: number; stdout: string }> {
  const stubs: Record<string, { code: number; stdout: string }> = {}
  for (const port of ports) {
    stubs[`ss -H -ltnp 'sport = :${String(port)}'`] = { code: 1, stdout: "" }
  }
  return stubs
}

// R-0000653: `ufw.enabled.apply` now re-reads `ufw status` after the
// allow/delete-deny sequence to confirm the rule landed before flipping
// the firewall active. Tests that simulate "DENY was present, we delete
// it and then add ALLOW" therefore need the status output to differ
// between the first and second read. This helper threads a counter
// through a `responseStubs` entry so the initial read sees the original
// output and any subsequent read sees the cleaned status.
function ufwStatusSequenceStub(
  initial: string,
  afterAllow: string
): { command: RegExp; result: { stdout: string } } {
  let callCount = 0
  return {
    command: /^ufw status$/v,
    result: {
      get stdout(): string {
        callCount += 1
        return callCount === 1 ? initial : afterAllow
      },
    },
  }
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

  it("check returns needs-apply when the current SSH port has a TCP deny rule", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22/tcp                     DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the current SSH port has both allow and deny rules", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22                         DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when IPv6 has a deny rule for the current SSH port", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22 (v6)                    ALLOW       Anywhere (v6)",
          "22 (v6)                    DENY        Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when IPv6 has a TCP deny rule for the current SSH port", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22 (v6)                    ALLOW       Anywhere (v6)",
          "22/tcp (v6)                DENY        Anywhere (v6)",
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

  // R-0000251 regression: when `ufw status` exits non-zero (e.g. ufw not
  // installed yet on a fresh host), the check must not throw. `readUfwStatus`
  // returns `null`, which we treat as `needs-apply` so apply runs and
  // installs/enables ufw.
  it("R-0000251: check returns needs-apply when ufw status exits non-zero", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw status": { code: 1, stderr: "ufw: command not found" },
      },
      22
    )
    const mod = ufw.enabled()
    const result = await mod.check(ssh, emptyEnv)
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
      "ufw status": { stdout: "Status: inactive" },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    // R-0000653: the re-verification read between `ufw allow` and
    // `--force enable` adds a second `command -v ufw` / `ufw status` pair.
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw allow '22'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
    expect(ssh.calls).toContain("ufw --force enable")
    expect(ssh.calls).not.toContain("echo 'y' | ufw enable")
  })

  it("apply allows the active SSH port before enabling ufw", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '2222'": { code: 0 },
        "ufw status": { stdout: "Status: inactive" },
      },
      2222
    )

    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    // R-0000653: re-verification adds a second status read between allow and enable.
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw allow '2222'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
  })

  it("apply fails without enabling when allowing the active SSH port fails", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 0 },
      "ufw allow '22'": { code: 1, stderr: "bad port" },
      "ufw status": { stdout: "Status: inactive" },
    })

    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual(["command -v ufw", "ufw status", "ufw allow '22'"])
  })

  it("apply returns failed when ufw --force enable exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 1 },
      "ufw allow '22'": { code: 0 },
      // R-0000653: inactive on both reads -> re-verify accepts and enable is attempted.
      "ufw status": { stdout: "Status: inactive" },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply deletes a deny rule for the current SSH port before enabling", async () => {
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
        "ufw delete 'deny' '22'": { code: 0 },
      },
      {
        // R-0000653: stateful status — first read sees the lingering DENY,
        // second read (after delete + allow) sees only the ALLOW so the
        // re-verify guard accepts and apply proceeds to enable.
        responseStubs: [
          ufwStatusSequenceStub(
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22                         DENY        Anywhere",
            ].join("\n"),
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
            ].join("\n")
          ),
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '22'",
      "ufw allow '22'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
  })

  it("apply deletes a TCP deny rule for the current SSH port before enabling", async () => {
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
        "ufw delete 'deny' '22/tcp'": { code: 0 },
      },
      {
        responseStubs: [
          ufwStatusSequenceStub(
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22/tcp                     DENY        Anywhere",
            ].join("\n"),
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
            ].join("\n")
          ),
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '22/tcp'",
      "ufw allow '22'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
  })

  it("apply deletes an IPv6 deny rule for the current SSH port before enabling", async () => {
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
        "ufw delete 'deny' '22'": { code: 0 },
      },
      {
        responseStubs: [
          ufwStatusSequenceStub(
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22 (v6)                    ALLOW       Anywhere (v6)",
              "22 (v6)                    DENY        Anywhere (v6)",
            ].join("\n"),
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22 (v6)                    ALLOW       Anywhere (v6)",
            ].join("\n")
          ),
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '22'",
      "ufw allow '22'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
  })

  it("apply deletes an IPv6 TCP deny rule for the current SSH port before enabling", async () => {
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
        "ufw delete 'deny' '22/tcp'": { code: 0 },
      },
      {
        responseStubs: [
          ufwStatusSequenceStub(
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22 (v6)                    ALLOW       Anywhere (v6)",
              "22/tcp (v6)                DENY        Anywhere (v6)",
            ].join("\n"),
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22 (v6)                    ALLOW       Anywhere (v6)",
            ].join("\n")
          ),
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '22/tcp'",
      "ufw allow '22'",
      "command -v ufw",
      "ufw status",
      "ufw --force enable",
    ])
  })

  it("apply fails without enabling when deleting a current SSH port deny rule fails", async () => {
    const ssh = createMockSsh({
      "ufw --force enable": { code: 0 },
      "ufw allow '22'": { code: 0 },
      "ufw delete 'deny' '22'": { code: 1, stderr: "delete failed" },
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22                         DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw delete deny failed")
    expect(ssh.calls).toStrictEqual(["command -v ufw", "ufw status", "ufw delete 'deny' '22'"])
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = ufw.enabled()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000653: lockout guard. A concurrent process could insert a `deny`
  // rule for the active SSH port between our initial status read in
  // `allowCurrentSshPort` and the `ufw allow` that follows. ufw evaluates
  // rules in insertion order so such a deny would survive `--force enable`
  // and lock the runner out. Apply must re-read `ufw status` after the
  // allow, refuse to enable when the SSH port is not allowed in the
  // re-read, and never call `ufw --force enable` in that case.
  it("R-0000653: apply refuses to enable when a deny rule is observed in the re-read", async () => {
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
      },
      {
        // The first read shows a clean ALLOW (no deletes needed), but the
        // second read between allow and enable observes a freshly inserted
        // DENY -- simulating a concurrent admin or another worker.
        responseStubs: [
          ufwStatusSequenceStub(
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
            ].join("\n"),
            [
              "Status: active",
              "",
              "To                         Action      From",
              "--                         ------      ----",
              "22                         ALLOW       Anywhere",
              "22                         DENY        Anywhere",
            ].join("\n")
          ),
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("re-verification before enable")
    expect(result.error?.message).toContain("blocked")
    expect(ssh.calls).not.toContain("ufw --force enable")
  })

  // R-0000653: when the re-read cannot be obtained (transient `ufw status`
  // failure), fail closed -- we cannot prove the allow rule landed, so
  // enabling would risk locking the runner out.
  it("R-0000653: apply refuses to enable when the re-read of ufw status fails", async () => {
    let statusCallCount = 0
    const ssh = createMockSsh(
      {
        "ufw --force enable": { code: 0 },
        "ufw allow '22'": { code: 0 },
      },
      {
        responseStubs: [
          {
            command: /^ufw status$/v,
            result: {
              get code(): number {
                statusCallCount += 1
                // oxlint-disable-next-line no-conditional-in-test
                return statusCallCount === 1 ? 0 : 1
              },
              get stdout(): string {
                // oxlint-disable-next-line no-conditional-in-test
                return statusCallCount === 1 ? "Status: inactive" : ""
              },
            },
          },
        ],
      }
    )
    const mod = ufw.enabled()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("could not re-read ufw status")
    expect(ssh.calls).not.toContain("ufw --force enable")
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

  // R-0000251 regression: when `ufw status` exits non-zero (binary missing
  // between probes, kernel modules unloaded, etc.), the check must not
  // throw. `readUfwStatus` returns `null`, which we treat as "disabled".
  it("R-0000251: check returns ok when ufw status exits non-zero", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "ufw status": { code: 1, stderr: "ufw: command not found" },
      "which apt-get": { code: 0 },
    })
    const mod = ufw.disabled()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
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
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok for a deny rule on a single port", async () => {
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
      "ufw status": { stdout: "Status: active" },
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
      "ufw status": { stdout: "Status: active" },
    })
    const mod = ufw.rule("allow", [80, 443, 8080])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw 'allow' '80'",
      "ufw 'allow' '443'",
      "ufw 'allow' '8080'",
    ])
  })

  // R-0000076 regression: when ufw prints "Skipping adding existing rule"
  // for every port, apply must return ok rather than always claiming the
  // run changed something.
  it("apply returns ok when ufw skips every existing rule", async () => {
    const skipOutput = "Skipping adding existing rule\nSkipping adding existing rule (v6)\n"
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0, stdout: skipOutput },
      "ufw 'allow' '80'": { code: 0, stdout: skipOutput },
      "ufw status": { stdout: "Status: active" },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw 'allow' '80'",
      "ufw 'allow' '443'",
    ])
  })

  it("apply returns changed when ufw adds every rule fresh", async () => {
    const addedOutput = "Rule added\nRule added (v6)\n"
    const ssh = createMockSsh({
      "ufw 'allow' '443'": { code: 0, stdout: addedOutput },
      "ufw 'allow' '80'": { code: 0, stdout: addedOutput },
      "ufw status": { stdout: "Status: active" },
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
      "ufw status": { stdout: "Status: active" },
    })
    const mod = ufw.rule("allow", [80, 443])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns changed when only one address family is added", async () => {
    // R-0000282: connect on a non-22 SSH port so the deny-current-port lockout
    // guard does not fire for this fixture.
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": {
          code: 0,
          stdout: "Skipping adding existing rule\nRule added (v6)\n",
        },
        "ufw status": { stdout: "Status: active" },
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed and stops when one port command fails", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": { code: 0 },
        "ufw 'deny' '25'": { code: 1 },
        "ufw 'deny' '465'": { code: 0 },
        "ufw status": { stdout: "Status: active" },
        ...noLiveSshdProbe(22, 25, 465),
      },
      2222
    )
    const mod = ufw.rule("deny", [22, 25, 465])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "ss -H -ltnp 'sport = :25'",
      "ss -H -ltnp 'sport = :465'",
      "command -v ufw",
      "ufw status",
      "ufw 'deny' '22'",
      "ufw 'deny' '25'",
    ])
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

  // R-0000174 regression: switching from allow to deny (or vice versa)
  // must remove the contradictory predecessor rule before adding the new
  // one. ufw evaluates rules in order, so a stale opposite entry can
  // shadow the freshly added rule.
  it("check returns needs-apply when the contradictory allow rule still exists alongside the desired deny", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         ALLOW       Anywhere",
          "22                         DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the contradictory deny rule still exists alongside the desired allow", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "80                         DENY        Anywhere",
          "80                         ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when only the contradictory IPv6 opposite rule remains", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
          "22 (v6)                    DENY        Anywhere (v6)",
          "22 (v6)                    ALLOW       Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when a contradictory TCP allow rule remains alongside the desired deny", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
          "22 (v6)                    DENY        Anywhere (v6)",
          "22/tcp                     ALLOW       Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when a contradictory TCP deny rule remains alongside the desired allow", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "80                         ALLOW       Anywhere",
          "80 (v6)                    ALLOW       Anywhere (v6)",
          "80/tcp                     DENY        Anywhere",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when only the contradictory IPv6 TCP opposite rule remains", async () => {
    const ssh = createMockSsh({
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "22                         DENY        Anywhere",
          "22 (v6)                    DENY        Anywhere (v6)",
          "22/tcp (v6)                ALLOW       Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("deny", 22)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply deletes the contradictory allow rule before adding the deny rule", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
        "ufw delete 'allow' '22'": { code: 0, stdout: "Rule deleted\nRule deleted (v6)\n" },
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
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "command -v ufw",
      "ufw status",
      "ufw delete 'allow' '22'",
      "ufw 'deny' '22'",
    ])
  })

  it("apply deletes contradictory TCP and protocol-agnostic allow rules before adding the deny rule", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
        "ufw delete 'allow' '22'": { code: 0, stdout: "Rule deleted\nRule deleted (v6)\n" },
        "ufw delete 'allow' '22/tcp'": {
          code: 0,
          stdout: "Rule deleted\nRule deleted (v6)\n",
        },
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22                         ALLOW       Anywhere",
            "22 (v6)                    ALLOW       Anywhere (v6)",
            "22/tcp                     ALLOW       Anywhere",
            "22/tcp (v6)                ALLOW       Anywhere (v6)",
          ].join("\n"),
        },
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "command -v ufw",
      "ufw status",
      "ufw delete 'allow' '22'",
      "ufw delete 'allow' '22/tcp'",
      "ufw 'deny' '22'",
    ])
  })

  it("apply deletes a contradictory IPv6 TCP deny rule before adding the allow rule", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '80'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
      "ufw delete 'deny' '80/tcp'": { code: 0, stdout: "Rule deleted\n" },
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "80                         ALLOW       Anywhere",
          "80 (v6)                    ALLOW       Anywhere (v6)",
          "80/tcp (v6)                DENY        Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '80/tcp'",
      "ufw 'allow' '80'",
    ])
  })

  it("apply deletes the contradictory deny rule before adding the allow rule", async () => {
    const ssh = createMockSsh({
      "ufw 'allow' '80'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
      "ufw delete 'deny' '80'": { code: 0, stdout: "Rule deleted\nRule deleted (v6)\n" },
      "ufw status": {
        stdout: [
          "Status: active",
          "",
          "To                         Action      From",
          "--                         ------      ----",
          "80                         DENY        Anywhere",
          "80 (v6)                    DENY        Anywhere (v6)",
        ].join("\n"),
      },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "command -v ufw",
      "ufw status",
      "ufw delete 'deny' '80'",
      "ufw 'allow' '80'",
    ])
  })

  it("apply does not call delete when no contradictory rule exists", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": { code: 0 },
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "80                         ALLOW       Anywhere",
          ].join("\n"),
        },
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "command -v ufw",
      "ufw status",
      "ufw 'deny' '22'",
    ])
  })

  it("apply deletes the opposite IPv6 rule even when the IPv4 entry is already gone", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '22'": { code: 0, stdout: "Rule added\nRule added (v6)\n" },
        "ufw delete 'allow' '22'": { code: 0, stdout: "Rule deleted\n" },
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22 (v6)                    ALLOW       Anywhere (v6)",
          ].join("\n"),
        },
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "command -v ufw",
      "ufw status",
      "ufw delete 'allow' '22'",
      "ufw 'deny' '22'",
    ])
  })

  it("apply returns failed when the opposite rule delete exits with non-zero code", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw delete 'allow' '22'": { code: 1, stderr: "delete failed" },
        "ufw status": {
          stdout: [
            "Status: active",
            "",
            "To                         Action      From",
            "--                         ------      ----",
            "22                         ALLOW       Anywhere",
          ].join("\n"),
        },
        ...noLiveSshdProbe(22),
      },
      2222
    )
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).toStrictEqual([
      "ss -H -ltnp 'sport = :22'",
      "command -v ufw",
      "ufw status",
      "ufw delete 'allow' '22'",
    ])
  })

  // R-0000281: route the apply/check status read through `readUfwStatus` so a
  // missing/broken ufw binary surfaces as a structured failure instead of an
  // unstructured `ssh.output` rejection.
  it("R-0000281: apply returns failed when ufw status throws (ufw missing)", async () => {
    const ssh = createMockSsh({
      "command -v ufw": { code: 1 },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is not installed")
    expect(ssh.calls).toStrictEqual(["command -v ufw"])
  })

  it("R-0000281: check returns needs-apply when ufw status throws (ufw missing)", async () => {
    const ssh = createMockSsh({
      "ufw status": { code: 127, stderr: "ufw: not found" },
    })
    const mod = ufw.rule("allow", 80)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000282: denying the live SSH port would kill the runner session because
  // `applyUfwRulePort` deletes the matching `allow` rule first. Refuse the
  // operation up front and surface a structured failure analog to
  // `ufwBlocksPortFailure` in `sshd.port`.
  it("R-0000282: apply returns failed when denying the current SSH port", async () => {
    const ssh = createMockSshOnPort({}, 22)
    const mod = ufw.rule("deny", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to deny SSH reconnect port(s)")
    expect(ssh.calls).toStrictEqual([])
  })

  it("R-0000282: apply returns failed when a multi-port deny rule includes the current SSH port", async () => {
    const ssh = createMockSshOnPort({}, 2222)
    const mod = ufw.rule("deny", [25, 2222, 465])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to deny SSH reconnect port(s)")
    expect(result.error?.message).toContain("2222")
    expect(ssh.calls).toStrictEqual([])
  })

  it("R-0000282: apply still allows denying an unrelated port on the same connection", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'deny' '8080'": { code: 0 },
        "ufw status": { stdout: "Status: active" },
        ...noLiveSshdProbe(8080),
      },
      22
    )
    const mod = ufw.rule("deny", 8080)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("R-0000282: apply does not block allowing the current SSH port", async () => {
    const ssh = createMockSshOnPort(
      {
        "ufw 'allow' '22'": { code: 0 },
        "ufw status": { stdout: "Status: active" },
      },
      22
    )
    const mod = ufw.rule("allow", 22)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  // R-0000615: the static ssh.getConnectionInfo() check only covers the
  // SshConfig-declared ports. Probe `ss -ltn` for a live sshd listener on
  // each candidate port immediately before applying the deny so additional
  // active listeners (e.g. a previous sshd.port apply that has not yet been
  // picked up by SshConfig, or a socket-activated systemd listener) are also
  // rejected.
  it("R-0000615: apply returns failed when denying a port served by a live sshd listener", async () => {
    const ssh = createMockSshOnPort(
      {
        "ss -H -ltnp 'sport = :2222'": {
          code: 0,
          stdout: 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=123,fd=3))',
        },
      },
      22
    )
    const mod = ufw.rule("deny", 2222)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("live sshd listener")
    expect(result.error?.message).toContain("2222")
  })

  it("R-0000615: apply returns failed when a multi-port deny includes a live sshd port", async () => {
    const ssh = createMockSshOnPort(
      {
        "ss -H -ltnp 'sport = :2222'": {
          code: 0,
          stdout: 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=123,fd=3))',
        },
        "ss -H -ltnp 'sport = :25'": { code: 1, stdout: "" },
        "ss -H -ltnp 'sport = :465'": { code: 1, stdout: "" },
      },
      22
    )
    const mod = ufw.rule("deny", [25, 2222, 465])
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("live sshd listener")
    expect(result.error?.message).toContain("2222")
  })

  it("R-0000615: apply ignores non-sshd listeners on the queried port", async () => {
    const ssh = createMockSshOnPort(
      {
        "ss -H -ltnp 'sport = :8080'": {
          code: 0,
          stdout: 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=999,fd=6))',
        },
        "ufw 'deny' '8080'": { code: 0 },
        "ufw status": { stdout: "Status: active" },
      },
      22
    )
    const mod = ufw.rule("deny", 8080)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })
})

// R-0000654: defense-in-depth port validation before regex interpolation.
// Callers are expected to validate via `isValidTcpPort` first, but a future
// caller could still pass NaN, Infinity, a fractional or out-of-range
// value. The in-helper assertion rejects those before they reach
// `new RegExp(...)` and produce a broken or over-permissive pattern.
describe("R-0000654 port regex guards", () => {
  const STATUS = "Status: active\n22                         ALLOW       Anywhere\n"

  for (const helper of [
    { fn: hasProtocolAgnosticRule, name: "hasProtocolAgnosticRule" },
    { fn: hasProtocolAgnosticIpv6Rule, name: "hasProtocolAgnosticIpv6Rule" },
    { fn: hasTcpRule, name: "hasTcpRule" },
    { fn: hasTcpIpv6Rule, name: "hasTcpIpv6Rule" },
  ]) {
    it(`${helper.name} throws when port is NaN`, () => {
      expect(() => helper.fn(STATUS, Number.NaN, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} throws when port is Infinity`, () => {
      expect(() => helper.fn(STATUS, Number.POSITIVE_INFINITY, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} throws when port is fractional`, () => {
      expect(() => helper.fn(STATUS, 22.5, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} throws when port is below 1`, () => {
      expect(() => helper.fn(STATUS, 0, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} throws when port is above 65535`, () => {
      expect(() => helper.fn(STATUS, 65_536, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} throws when port is negative`, () => {
      expect(() => helper.fn(STATUS, -1, "ALLOW")).toThrow(/invalid/v)
    })

    it(`${helper.name} accepts valid TCP ports`, () => {
      expect(() => helper.fn(STATUS, 22, "ALLOW")).not.toThrow()
      expect(() => helper.fn(STATUS, 1, "ALLOW")).not.toThrow()
      expect(() => helper.fn(STATUS, 65_535, "ALLOW")).not.toThrow()
    })
  }
})
