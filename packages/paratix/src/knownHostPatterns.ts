import { createHmac, timingSafeEqual } from "node:crypto"

const HASHED_HOST_PARTS = 4

type HostPatternMatchState = {
  needleIndex: number
  patternIndex: number
  starIndex: number
  starNeedleIndex: number
}

export function matchesKnownHostPatternList(patterns: string[], needle: string): boolean {
  let matchedPositivePattern = false
  for (const rawPattern of patterns) {
    const negated = rawPattern.startsWith("!")
    const pattern = negated ? rawPattern.slice(1) : rawPattern
    if (pattern.length === 0) continue
    const matched = matchesHashedHost(pattern, needle) || matchesHostPattern(pattern, needle)
    if (!matched) continue
    if (negated) return false
    matchedPositivePattern = true
  }
  return matchedPositivePattern
}

function matchesHashedHost(pattern: string, needle: string): boolean {
  if (!pattern.startsWith("|1|")) return false

  const parts = pattern.split("|")
  if (parts.length !== HASHED_HOST_PARTS || parts[1] !== "1") return false

  const salt = Buffer.from(parts[2] ?? "", "base64")
  const expectedHash = Buffer.from(parts[3] ?? "", "base64")
  if (salt.length === 0 || expectedHash.length === 0) return false

  const actualHash = createHmac("sha1", salt).update(needle).digest()
  return actualHash.length === expectedHash.length && timingSafeEqual(actualHash, expectedHash)
}

function matchesHostPattern(pattern: string, needle: string): boolean {
  let state = { needleIndex: 0, patternIndex: 0, starIndex: -1, starNeedleIndex: 0 }

  while (state.needleIndex < needle.length) {
    const nextState = advanceHostPatternMatch(pattern, needle, state)
    if (nextState === null) return false
    state = nextState
  }

  while (pattern[state.patternIndex] === "*") state.patternIndex += 1
  return state.patternIndex === pattern.length
}

function advanceHostPatternMatch(
  pattern: string,
  needle: string,
  state: HostPatternMatchState
): HostPatternMatchState | null {
  const patternCharacter = pattern[state.patternIndex]
  if (patternCharacter === "?" || patternCharacter === needle[state.needleIndex]) {
    return { ...state, needleIndex: state.needleIndex + 1, patternIndex: state.patternIndex + 1 }
  }
  if (patternCharacter === "*") {
    return {
      ...state,
      patternIndex: state.patternIndex + 1,
      starIndex: state.patternIndex,
      starNeedleIndex: state.needleIndex,
    }
  }
  if (state.starIndex === -1) return null
  const starNeedleIndex = state.starNeedleIndex + 1
  return {
    ...state,
    needleIndex: starNeedleIndex,
    patternIndex: state.starIndex + 1,
    starNeedleIndex,
  }
}
