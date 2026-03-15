import { describe, expect, it } from "vitest"

import { FLAGS_DIRECTORY, setVersionedFlag } from "../../src/modules/moduleHelpers.js"
import { createMockSsh } from "../helpers/mockSsh.js"

describe("setVersionedFlag", () => {
  it("shell-quotes flagPrefix in the rm -f command to prevent glob injection", async () => {
    // A flagPrefix containing shell-special characters (spaces, parentheses).
    // Without quoting this would break or be exploitable via glob injection.
    const flagPrefix = "my prefix (v2)"
    const flagName = "my prefix (v2)1.0"

    const ssh = createMockSsh({
      // The command the implementation now generates (quoted prefix):
      [`rm -f ${FLAGS_DIRECTORY}/'${flagPrefix}'* && touch ${FLAGS_DIRECTORY}/'${flagName}'`]: {
        code: 0,
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await setVersionedFlag(ssh, flagName, flagPrefix)

    // The rm -f glob must quote the prefix so that shell-special characters
    // in flagPrefix are not interpreted by the shell.
    // Expected safe form: rm -f /var/lib/paratix/flags/'my prefix (v2)'*
    const expectedSafeCommand = `rm -f ${FLAGS_DIRECTORY}/'${flagPrefix}'* && touch ${FLAGS_DIRECTORY}/'${flagName}'`
    expect(ssh.calls).toContain(expectedSafeCommand)
  })

  it("prevents command injection via semicolon in flagPrefix", async () => {
    // An attacker-controlled flagPrefix that tries to inject a second command.
    // Without quoting: rm -f /var/lib/paratix/flags/safe; rm -rf /; #*
    // With quoting:    rm -f /var/lib/paratix/flags/'safe; rm -rf /; #'*
    const flagPrefix = "safe; rm -rf /; #"
    const flagName = "safe; rm -rf /; #1.0"

    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await setVersionedFlag(ssh, flagName, flagPrefix)

    const execCall = ssh.calls.find((c) => c.startsWith("rm -f"))
    expect(execCall).toBeDefined()

    // The safe quoted form must wrap the entire injection attempt in single quotes.
    // Expected: rm -f /var/lib/paratix/flags/'safe; rm -rf /; #'*
    const safePrefix = `'safe; rm -rf /; #'`
    expect(execCall).toContain(safePrefix)

    // The injected rm -rf must NOT appear as a standalone bare command outside quotes.
    // If injection succeeded the string would contain literal "; rm -rf " unquoted.
    // We verify this by checking the command does NOT match the unquoted injection pattern.
    expect(execCall).not.toContain(`${FLAGS_DIRECTORY}/safe; rm -rf`)
  })

  it("prevents command substitution injection via backticks in flagPrefix", async () => {
    // An attacker-controlled flagPrefix that tries to use backtick command substitution.
    // Without quoting: rm -f /var/lib/paratix/flags/`id`*  (executes `id`)
    // With quoting:    rm -f /var/lib/paratix/flags/'`id`'*
    const flagPrefix = "`id`"
    const flagName = "`id`1.0"

    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await setVersionedFlag(ssh, flagName, flagPrefix)

    const execCall = ssh.calls.find((c) => c.startsWith("rm -f"))
    expect(execCall).toBeDefined()

    // Backticks must not appear outside of single quotes.
    // Replace all content inside single quotes, then check no backticks remain.
    const outsideQuotes = execCall!.replaceAll(/'[^']*'/gv, "")
    expect(outsideQuotes).not.toContain("`")

    // The safe quoted form must be present.
    expect(execCall).toContain(`'\`id\`'`)
  })

  it("prevents command substitution injection via $() in flagPrefix", async () => {
    // An attacker-controlled flagPrefix using $() command substitution.
    // Without quoting: rm -f /var/lib/paratix/flags/$(id)*  (executes `id`)
    // With quoting:    rm -f /var/lib/paratix/flags/'$(id)'*
    const flagPrefix = "$(id)"
    const flagName = "$(id)1.0"

    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await setVersionedFlag(ssh, flagName, flagPrefix)

    const execCall = ssh.calls.find((c) => c.startsWith("rm -f"))
    expect(execCall).toBeDefined()

    // $() must not appear outside of single quotes.
    const outsideQuotes = execCall!.replaceAll(/'[^']*'/gv, "")
    expect(outsideQuotes).not.toContain("$(")

    // The safe quoted form must be present.
    expect(execCall).toContain(`'$(id)'`)
  })
})
