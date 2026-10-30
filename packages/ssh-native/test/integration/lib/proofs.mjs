// Shared between the runner (run.mjs) and the tests: the hard proofs of
// ADR 0008 and the environment variables that connect both.

/**
 * The 15 hard proofs (ADR 0008, "Hard Proofs"). With CI=true the runner
 * requires every one of them to pass; a skipped hard proof fails the test
 * itself as well.
 */
export const HARD_PROOFS = Object.freeze([
  "H1-agent-user-certificate",
  "H2-async-verifier",
  "H2-verifier-error-identity",
  "H3-exec-streams-and-exit",
  "H4-sftp-mode-0600",
  "H4-sftp-bounded-in-flight",
  "H5-destroy-before-process-exit",
  "H5-destroy-before-exit-while-streaming",
  "H5-destroy-releases-event-loop",
  "H5-close-then-natural-exit",
  "H5-idle-connection-keeps-process-alive",
  "H6-agent-forward-remote-ssh-add",
  "H6-no-agent-forward-by-default",
  "H6-server-opened-channels-rejected",
  "H6-server-opened-agent-channel-bridged",
])

/** Path of the JSON run descriptor the runner writes for the tests. */
export const DESCRIPTOR_ENV = "SSH_NATIVE_IT_DESCRIPTOR"
/** Path of the file the tests append `pass <proof id>` lines to. */
export const RESULTS_ENV = "SSH_NATIVE_IT_RESULTS"

/** @returns whether this is a CI run (`CI=true`), where skips of hard proofs fail */
export function isCi() {
  return process.env.CI === "true"
}
