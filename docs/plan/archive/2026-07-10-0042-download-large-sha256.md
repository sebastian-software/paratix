# 0042 — download.large SHA-256 Integrity Verification

## Requirement

Add an optional `sha256` parameter to `download.large()` so that large file downloads can be verified against an expected SHA-256 digest after transfer. On checksum mismatch: delete the downloaded file, do not set the flag file, and return `{ status: "failed" }`.

## Architecture Decisions

- **Reuse existing infrastructure:** `performDownload()` already calls `verifyChecksum()` internally. The sha256 value is simply passed through via `DownloadParameters`.
- **Enhanced check logic:** When sha256 is provided and the flag file exists, `check()` additionally verifies the remote file's digest. This catches cases where the file was corrupted after initial download.
- **Extracted `hashMatches()` helper:** Centralizes the `timingSafeEqual` comparison logic to eliminate duplication across `verifyChecksum`, `checkDownload`, and the new `download.large` check.
- **Extracted `validateGithubOptions()` helper:** Reduces statement count in `download.github()` to stay under the `max-statements: 15` lint limit after adding `validateSha256()`.
- **Input validation at construction time:** `validateSha256()` rejects invalid hex digests (non-64-char or non-lowercase-hex) immediately when the module is created, not at runtime during check/apply. Applied to all three download methods: `download.url`, `download.github`, `download.large`.

## Affected Files

| File                                             | Changes                                                                                                                                                                                                    |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/download.ts`       | `sha256` option added to `large()`, `hashMatches()` extracted, `validateSha256()` + `validateGithubOptions()` added, `verifyChecksum` and `checkDownload` refactored to use `hashMatches()`, JSDoc updated |
| `packages/paratix/test/modules/download.test.ts` | 5 new tests: check with sha256 match/mismatch/no-flag, apply with sha256 match/mismatch                                                                                                                    |
| `packages/paratix/llm-guide.md`                  | `sha256?: string` added to `download.large` signature table                                                                                                                                                |

## Test Results

- Before: 1201 tests passing
- After: 1206 tests passing (+5 new)
- 0 TypeScript errors, 0 lint errors, 7 lint warnings (unchanged)

## Review Findings

| #     | Severity  | Description                                             | Status          |
| ----- | --------- | ------------------------------------------------------- | --------------- |
| R-001 | Important | hashMatches() not used in verifyChecksum/checkDownload  | Fixed           |
| R-003 | Important | No sha256 input validation at construction time         | Fixed           |
| R-006 | Note      | Outdated JSDoc in download.large                        | Fixed           |
| R-007 | Note      | Missing edge-case test for conn.sha256() returning null | Open (optional) |
