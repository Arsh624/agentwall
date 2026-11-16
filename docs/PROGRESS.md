# agentwall — Progress (handoff file)

Any model picking this up: read this file, then `docs/PLAN.md`, then `git log --oneline -20`.
Continue from **Next task**. Update this file and commit after every task.

## Status
- Current milestone: M1
- Next task: M1 — `internal/jsonrpc` frames (tests first), on branch `m1-jsonrpc-proxy`
- Last commit: M0 scaffold
- Model that last worked: Fable 5.2 (M0 implemented by a Haiku subagent, reviewed by Fable)

## Workflow (from M1 on)
- One GitHub issue per milestone (`M<n>: <name>`, PLAN tasks as checkboxes, label `milestone`).
- Branch `m<n>-<short-name>`, one small conventional commit per task (`feat:`, `test:`, `fix:`, `docs:`).
- Milestone done → push, `gh pr create` with `Closes #<issue>` + summary + test output, wait for CI,
  `gh pr merge --merge` (merge commit, never squash).
- Bugs/follow-ups get their own issue, closed from the fixing commit.
- Model tags: `[FABLE]` main session, `[SONNET]`/`[HAIKU]` subagents. Fable reviews all subagent work.

## Done
- M0 — scaffold: go module, cobra CLI stubs for every SPEC §6 command, package dirs, CI workflow,
  `.gitignore`, MIT `LICENSE`, README. `go vet`, `go build`, `go test ./...` pass locally.
  CI not yet seen green (repo not pushed yet).

## Decisions made (and why)
- Go, single binary: fast proxy, easy install, cross-platform.
- YAML policy, not OPA/Cedar: smallest thing that works for v0.1.
- Session-level taint + n-gram fingerprints: catches the trifecta without an ML model.
- Module path `github.com/agentwall/agentwall` is a PLACEHOLDER: the GitHub username was unknown at M0.
  Rename to `github.com/<login>/agentwall` (go.mod + imports) as soon as `gh` is signed in.
- Reviews: the lead (Fable) reviews each subagent's diff and reruns the checks itself instead of
  dispatching separate spec/quality reviewer subagents. Why: user asked to be frugal and to review personally.
- Subagents do not commit; the lead commits after review.
- CLI lives in one file (`cmd/agentwall/main.go`) until it gets too big to read.

## Known issues / notes for next session
- `gh` was installed with winget during M0 but is NOT signed in yet: the user must run `gh auth login`.
  Until then: no remote, no issues, no PRs. Work continues on local branches; open the issue/PR after sign-in.
- Git identity on this machine is "Saumya Singh" — user was asked whether that is the right author
  before the first public push. Check for an answer before pushing.
