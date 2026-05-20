const OPENSSH_KNOWN_HOSTS_PATTERN_METACHARACTER = /[*,?!]/v
const LAST_ASCII_CONTROL_CODE_POINT = 0x1f
const DELETE_CONTROL_CODE_POINT = 0x7f

export type HostValidationFailure = "control" | "empty" | "metacharacter" | "type" | "whitespace"

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)
    if (
      codePoint != null &&
      (codePoint <= LAST_ASCII_CONTROL_CODE_POINT || codePoint === DELETE_CONTROL_CODE_POINT)
    )
      return true
  }
  return false
}

export function validateHostLabel(value: unknown): HostValidationFailure | null {
  if (typeof value !== "string") return "type"
  if (value.length === 0) return "empty"
  if (containsControlCharacter(value)) return "control"
  if (/\s/v.test(value)) return "whitespace"
  if (OPENSSH_KNOWN_HOSTS_PATTERN_METACHARACTER.test(value)) return "metacharacter"
  return null
}

export function describeHostValidationFailure(failure: HostValidationFailure): string {
  switch (failure) {
    case "control": {
      return "must not contain control characters"
    }
    case "empty": {
      return "must be a non-empty string"
    }
    case "metacharacter": {
      return "must not contain OpenSSH known_hosts pattern metacharacters"
    }
    case "type": {
      return "must be a string"
    }
    case "whitespace": {
      return "must not contain whitespace"
    }
  }
}
