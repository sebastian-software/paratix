import { afterEach, describe, expect, it, vi } from "vitest"

import * as providerProcess from "../src/modules/opSpawnRunner.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import * as nativeBinding from "../src/nativeBinding.js"
import { runPlaybook } from "../src/runner.js"

describe("native host certificate guard test context", () => {
  afterEach(() => {
    vi.restoreAllMocks()
    process.exitCode = 0
  })

  describe("host-certificate deferred secrets at the native runtime boundary", () => {
    it("rejects a missing native binding before any deferred provider or controller signer process can run", async () => {
      const provider = vi.spyOn(providerProcess, "spawnWithInput")
      const caPublicKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
      const descriptor = ssh.signer.stepCa({
        caPublicKey,
        caUrl: "https://ca.invalid",
        password: secret.provider("1password").deferred("op://private-test/item/password"),
        provisioner: "fixture",
        root: "/tmp/public-test-root.pem",
      })
      const sign = vi.fn(descriptor.sign)
      const module = ssh.hostCertificate({
        principals: ["host.test"],
        signer: { ...descriptor, sign },
      })
      const binding = vi
        .spyOn(nativeBinding, "assertNativeBindingAvailable")
        .mockRejectedValueOnce(new Error("Native SSH binding unavailable"))
      await expect(
        runPlaybook({
          host: "127.0.0.1",
          name: "native-host-certificate-guard",
          run: [module],
          ssh: { ports: [22], user: "root" },
        })
      ).rejects.toThrow("Native SSH binding unavailable")
      expect(binding).toHaveBeenCalledTimes(1)
      expect(provider).not.toHaveBeenCalled()
      expect(sign).not.toHaveBeenCalled()
    })
  })
})
