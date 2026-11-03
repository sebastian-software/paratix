/**
 * Inspect/inject the prepared command while executing the production kernel lock unchanged.
 * @param command - Full guarded command sent to the target process.
 * @returns The prepared body for observation, or the unchanged unwrapped command.
 */
export function sshdCommitBody(command: string): string {
  const marker = "# paratix-sshd-commit-body\n"
  const start = command.indexOf(marker)
  return start === -1 ? command : command.slice(start + marker.length)
}
