# ADR-0002: Defer broad integration matrix expansion

**Status:** Accepted
**Date:** 2026-03-19
**Context:** /build-feature - review finding R-001 about a broader module integration matrix

## Context

Review report `review-report-2026-03-19.md` contains an important finding, R-001: real-server
coverage in `packages/paratix/test/integration/paratix.integration.test.ts` is deliberately
narrow and currently covers only basic SSH behavior and the `file`, `command`, and `download`
module families against a real host. Much of the public module surface remains validated only
with mocks.

The latest expansion of the integration strategy already established a reliable integration
path (`agent:check:integration`) and added real-server scenarios for the existing focus areas.
The broader request in R-001 to include modules such as `apt/package`, `service/systemd`, `cron`,
`sshd`, `net`, `mount`, `user/group`, `git`, or `rsync` in the real integration matrix would
expand the scope significantly.

## Decision

Defer R-001 for now. Keep the real integration matrix deliberately limited to basic SSH behavior
and the `file`, `command`, and `download` module families.

## Rationale

- **Deliberate scope limit:** The current integration path first needed to become stable,
  reproducible, and usable in reviews. A broad module integration matrix would have substantially
  exceeded the scope of the latest expansion.
- **High infrastructure cost:** Many modules named in R-001 require additional system services,
  network setup, or stateful operating-system environments for meaningful E2E tests. This would
  make the test container and test logic considerably more complex.
- **Fragility risk:** Rapidly expanding coverage to many modules that depend heavily on the
  operating system would make the integration suite slower and more failure-prone before the
  current core path has proved stable in use for long enough.
- **Prioritization:** The real paths prioritized so far (`file`, `command`, `download`,
  SSH/SFTP/reconnect) already address central risks involving shell quoting, file state,
  transfers, and communication with real hosts.
- **Follow-up rather than rejection:** The finding remains technically valid. It is not negated,
  but deliberately deferred as a later follow-up.

## Source

- **Finding:** R-001 - Real-server coverage ends at four module families; the remainder is still validated only with mocks
- **Severity:** Important
- **Files:** review-report-2026-03-19.md, packages/paratix/test/integration/paratix.integration.test.ts
