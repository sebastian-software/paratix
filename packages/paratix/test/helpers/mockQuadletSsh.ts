import type { MockCommandOptions, MockResponses } from "./mockSshCommandResponses.js"

import { createMockSsh } from "./mockSsh.js"

/**
 * Matches the conflict guard's `podman container inspect` projection, whatever
 * container name it targets.
 */
const CONFLICT_INSPECT_PATTERN = /^podman container inspect --format /v

/**
 * `createMockSsh` for the quadlet modules, defaulting the conflict-guard probe
 * to "container absent".
 *
 * `quadlet.container` and `quadlet.updateImage` inspect the managed container on
 * every apply and dry run to detect a foreign owner. The strict mock fails
 * closed on unstubbed commands, so without a default every existing quadlet test
 * would have to stub that probe just to reach the behavior it actually asserts.
 * A non-zero exit is the module's "container absent" idiom and therefore the
 * correct neutral default.
 *
 * The stub is a `responseStubs` entry, which is matched *after* exact responses.
 * A test that exercises a conflict simply stubs the concrete inspect command and
 * that exact entry wins.
 *
 * @param responses - Exact command stubs, as with {@link createMockSsh}.
 * @param options - Mock options; extra `responseStubs` are preserved.
 * @returns The mock SSH connection.
 */
export function createQuadletMockSsh(
  responses?: MockResponses,
  options?: MockCommandOptions
): ReturnType<typeof createMockSsh> {
  return createMockSsh(responses, {
    ...options,
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: CONFLICT_INSPECT_PATTERN, result: { code: 1 } },
    ],
  })
}
