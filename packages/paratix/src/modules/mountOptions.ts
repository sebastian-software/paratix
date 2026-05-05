const IMPLICIT_MOUNT_OPTIONS = new Set(
  "async auto defaults dev exec nouser relatime rw suid".split(" ")
)

export function mountOptionsMatch(liveOptions: string, desiredOptions: string): boolean {
  const live = normalizeMountOptions(liveOptions)
  const desired = normalizeMountOptions(desiredOptions)
  if (live.size !== desired.size) return false
  for (const option of desired) {
    if (!live.has(option)) return false
  }
  return true
}

function normalizeMountOptions(options: string): Set<string> {
  return new Set(
    options
      .split(",")
      .map((option) => option.trim())
      .filter((option) => option.length > 0 && !IMPLICIT_MOUNT_OPTIONS.has(option))
  )
}
