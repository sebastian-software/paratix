// R-0000742 / lint: extracted from publicKeySelection.ts to keep the
// caller's file under the 300-line lint budget. The helpers below
// validate that an OpenSSH public-key body is encoded as a canonical
// base64 string (no whitespace, padding only at the end, length
// divisible by 4 after re-encoding). The check is intentionally
// stricter than Node's tolerant `Buffer.from(value, "base64")` decoder
// so an attacker cannot smuggle a value that decodes the same way but
// renders differently in the generated server.ts.

function trimBase64Padding(value: string): string {
  let endIndex = value.length
  while (endIndex > 0 && value[endIndex - 1] === "=") {
    endIndex--
  }
  return value.slice(0, endIndex)
}

function isBase64AlphaNumeric(character: string): boolean {
  return (
    (character >= "A" && character <= "Z") ||
    (character >= "a" && character <= "z") ||
    (character >= "0" && character <= "9")
  )
}

function isBase64DataCharacter(character: string): boolean {
  return isBase64AlphaNumeric(character) || character === "+" || character === "/"
}

function updatePaddingState(
  character: string,
  state: { paddingCount: number; sawPadding: boolean }
): { paddingCount: number; sawPadding: boolean } | null {
  if (character !== "=") {
    return null
  }

  const nextState = {
    paddingCount: state.paddingCount + 1,
    sawPadding: true,
  }

  return nextState.paddingCount <= 2 ? nextState : null
}

function hasValidBase64Alphabet(value: string): boolean {
  if (value.length === 0) {
    return false
  }

  const state = { paddingCount: 0, sawPadding: false }

  for (const character of value) {
    if (isBase64DataCharacter(character)) {
      if (state.sawPadding) {
        return false
      }
      continue
    }

    const nextState = updatePaddingState(character, state)
    if (nextState != null) {
      state.paddingCount = nextState.paddingCount
      state.sawPadding = nextState.sawPadding
      continue
    }

    return false
  }

  return true
}

export function isCanonicalBase64(value: string): boolean {
  if (!hasValidBase64Alphabet(value)) {
    return false
  }

  try {
    const decoded = Buffer.from(value, "base64")
    if (decoded.length === 0) {
      return false
    }

    const normalizedValue = trimBase64Padding(value)
    const encodedAgain = trimBase64Padding(decoded.toString("base64"))
    return encodedAgain === normalizedValue
  } catch {
    return false
  }
}
