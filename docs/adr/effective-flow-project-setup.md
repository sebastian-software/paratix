# Effective Flow project setup

## Status

Active

## Context

This ADR holds this project's tracked Effective Flow configuration. `.effective-flow/` is a pure
runtime directory and completely gitignored.

The values were migrated from the former `.firmo/config.json`. The legacy key
`plan.markerLanguage: de` became `language.workflow: de`, which now governs the complete plan and
review artifact rather than only its status marker.

The worktree base directories moved to `.effective-flow/.worktrees` once the legacy `.firmo/`
directory was removed; leaving them behind would have recreated it on the next worktree run. The
`firmo` branch prefix is kept deliberately so it stays consistent with the existing branches.

## Configuration

| Key                                | Value                      |
| ---------------------------------- | -------------------------- |
| review.profile                     | focused                    |
| review.autoConfirmScope            | false                      |
| review.designDecisionSources       | standard                   |
| review.validation                  | full                       |
| applyReview.defaultCommitStrategy  | null                       |
| applyReview.finalValidation        | full                       |
| applyReview.stashPolicy            | interactive                |
| applyReview.worktree.baseDir       | .effective-flow/.worktrees |
| applyReview.worktree.setup         | auto                       |
| language.project                   | en                         |
| language.workflow                  | de                         |
| plan.dir                           | docs/plan                  |
| delivery.baseBranch                | origin/main                |
| delivery.branchPrefix              | firmo                      |
| delivery.completion                | pr                         |
| delivery.returnBranch              | auto                       |
| mergeGate.completion               | ask                        |
| mergeGate.conflictResolution       | auto                       |
| mergeGate.requireAllChecks         | true                       |
| mergeGate.checkWaitMinutes         | 20                         |
| mergeGate.maxRounds                | 10                         |
| mergeGate.botWaitMinutes           | 10                         |
| mergeGate.bots                     | recensor[bot]              |
| mergeGate.bots.recensor[bot].check | recensor/review            |
| worktree.enabled                   | true                       |
| worktree.setup                     | auto                       |
| worktree.baseDir                   | .effective-flow/.worktrees |
| tracker.mode                       | remote                     |
| tracker.remoteToolOverride         | auto                       |
