# agentwall — Progress (handoff file)

Any model picking this up: read this file, then `docs/PLAN.md`, then `git log --oneline -20`.
Continue from **Next task**. Update this file and commit after every task.

## Status
- Repo: https://github.com/Arsh624/agentwall (public). Module `github.com/Arsh624/agentwall`. gh is signed in as Arsh624.
- Merged to `main` through PRs: M1 (#10), M2 (#11), M3 (#12). CI green on ubuntu/windows/macos (+ race detector on Linux).
- Current milestone: M4 code complete on `m4-tool-pinning`; PR open or about to be (check `gh pr list`). Merge it when CI is green.
- Next task: M5 — credential broker + redaction `[FABLE]`, branch `m5-credential-broker`, issue #5.
- Issues: milestone M<n> = issue #<n> (#1–#9). Follow-ups: #13 duplicate keys in arguments, #14 frame size cap,
  #15 pending map expiry, #16 server-initiated requests, #17 fingerprint vs read-edit-write-back, #18 session id on Windows.
- Model that last worked: Fable 5.2

## How to do a milestone PR
- `gh` lives in `C:/Program Files/GitHub CLI` (in Git Bash: `export PATH="$PATH:/c/Program Files/GitHub CLI"`).
- Branch from up-to-date `main`. When done: `git push -u origin <branch>`,
  `gh pr create --base main --title "M<n>: <name>" --body-file <file>` (first line `Closes #<n>`, summary, local test output),
  `gh pr checks <pr> --watch`, then `gh pr merge <pr> --merge`, then `git checkout main && git pull`.

## Workflow (from M1 on)
- One GitHub issue per milestone (`M<n>: <name>`, PLAN tasks as checkboxes, label `milestone`).
- Branch `m<n>-<short-name>`, one small conventional commit per task (`feat:`, `test:`, `fix:`, `docs:`).
- Milestone done → push, `gh pr create` with `Closes #<issue>` + summary + test output, wait for CI,
  `gh pr merge --merge` (merge commit, never squash).
- Bugs/follow-ups get their own issue, closed from the fixing commit.
- Model tags: `[FABLE]` main session, `[SONNET]`/`[HAIKU]` subagents. Fable reviews all subagent work.
- Commit author must be Archit Shukla (repo-local git config; history was rewritten once to fix this).

## Done
- M0 — scaffold: go module, cobra CLI stubs for every SPEC §6 command, package dirs, CI workflow,
  `.gitignore`, MIT `LICENSE`, README.
- M1 — JSON-RPC stdio proxy (branch `m1-jsonrpc-proxy`):
  - `internal/jsonrpc`: `Message`, `Reader` (newline frames, any size, `*ParseError` for bad lines), concurrency-safe `Writer`.
  - `internal/proxy`: `Run` (pipes both ways, pending-id map, `Hooks{OnRequest, OnResponse}`), `Wrap` (spawns upstream).
  - `internal/mockserver`: scripted MCP server (`Scenario{tools, calls}`; unscripted tool echoes its arguments).
  - `agentwall wrap -- <cmd>` works, transparent (no hooks yet).
  - Tests: unit + real-subprocess integration (round trip, 5 MB payload, 200 concurrent ids). All pass on Windows.
    CI (ubuntu/windows/macos, plus `-race` on Linux) has NOT run yet — nothing is pushed.
- M2 — policy + audit (branch `m2-policy-audit`):
  - `internal/policy` (Sonnet): `Parse`/`Load`/`Default`, `Decide(server, tool, args)`, `Tags(server, tool)`; strict YAML
    (unknown keys are errors); `"*"` wildcard tool entry; `deny_args` regex per top-level argument; embedded `default.yaml`
    with tags for github, filesystem, fetch, slack.
  - `internal/audit` (Sonnet): `Open`/`Append`/`Read`/`Verify`, per-process chains in one shared JSONL file.
  - `internal/firewall` (Fable): `Firewall.Hooks()` — the one place where policy, audit and later flow/pin/vault/detect
    plug into the proxy. Only `tools/call` is decided and audited. `ask` prompts on the controlling terminal
    (`/dev/tty` or `CONIN$`), no terminal → deny. A call that cannot be audited is denied.
  - CLI: `wrap` loads policy (`--policy`, else `<state>/policy.yaml`, else built-in), `--server`; `verify`; `log [--tail]`.
  - Verified: all package tests + CLI end-to-end test (blocked call returns `-32001` with reason, both calls logged,
    tampered log fails `verify`); real binary smoke run.
- M3 — flow control (branch `m3-flow-control`, all Fable):
  - `internal/session`: taint markers as files `<state>/sessions/<id>/{untrusted,private}`; add-only, so no locks;
    every wrap process of one agent sees the others' taint.
  - `internal/flow`: `Fingerprints` (Rabin-Karp rolling hash over 8 lowercased words), `Strings` (all string values
    in a JSON doc), `Store` (shared append-only file `<state>/fingerprints`, generation header, capped, oldest half dropped).
  - `internal/policy`: `on_trifecta` / `on_fingerprint` settings (`deny` default, or `ask`).
  - `internal/firewall`: response of a tagged tool taints the session (audited as `taint`) and fingerprints
    `private_source` output BEFORE the agent sees it; an `egress_sink` call is denied/asked when the session holds both
    taints (trifecta) or its arguments contain fingerprinted text. Policy `deny` still wins; stricter flow rule wins.
  - Verified: heist scenario blocked at step 3 (firewall test + CLI test with three real wrap processes for
    github/filesystem/fetch sharing one session), four benign sequences pass, fingerprint catches pasted text in a
    fresh session, another agent's session is unaffected.
- M4 — tool pinning (branch `m4-tool-pinning`):
  - `internal/pin` (Sonnet): one JSON file per server in `<state>/pins`, `Check` → `New` / `Same` / `Changed`, `Approve`.
  - `internal/firewall` (Fable): on a `tools/list` result, changed tools are removed, warned about on stderr and audited
    (`pin`); `tools/call` to a hidden tool is denied with the `agentwall approve` command in the reason. An unreadable
    tool list or pin store → the list is withheld.
  - CLI: `agentwall approve <server>/<tool>`.
  - Verified: rug-pull scenario end to end (`testdata/rugpull.json`): tool hidden on the second list, call blocked,
    visible again after approve.

## Decisions made (and why)
- Go, single binary: fast proxy, easy install, cross-platform.
- YAML policy, not OPA/Cedar: smallest thing that works for v0.1.
- Session-level taint + n-gram fingerprints: catches the trifecta without an ML model.
- Reviews: the lead (Fable) reviews each subagent's diff and reruns the checks itself instead of
  dispatching separate reviewer subagents. Why: user asked to be frugal and to review personally.
- Subagents do not commit; the lead commits after review.
- Proxy always re-encodes frames from the parsed `Message` instead of forwarding raw bytes: upstream sees
  exactly what the hooks inspected (no parser differential at the top level, hooks cannot be silently ignored).
  `params`/`result` bytes are kept as-is (compacted).
- Fail closed on odd traffic: bad frame from the agent → `-32700` reply; bad frame or a response with an
  unknown id from upstream → dropped and logged to stderr. JSON-RPC batches are rejected (MCP removed them).
- Denied request → JSON-RPC error `-32001` "agentwall blocked this call: <reason>". Denied notification → dropped.
- Mock server lives in `internal/mockserver` (importable, so `agentwall attack` can reuse it in M7), not
  `testdata/mockserver`. Tests get a real subprocess by re-executing the test binary
  (`mockserver.RunIfChild` + env `AGENTWALL_MOCK_SCENARIO`) — no second binary to build. Scenario files are in `testdata/`.
- `.gitattributes` forces LF so `gofmt -l` is clean on Windows checkouts.
- Design for M2/M3 (decided early because it shapes session ids and the audit log): Claude Code starts one
  `agentwall wrap` process PER MCP server. The trifecta usually spans servers (issue from github, file from
  filesystem, exfil via fetch), so taint and fingerprints must be shared between processes through files in
  `~/.agentwall/`. Session id = parent process id (all wraps of one agent share it), env `AGENTWALL_SESSION` overrides.
- Audit: one shared `audit.jsonl`, written with O_APPEND one line per write (no locks). Each process chains its
  own entries (`chain` field = random id per process; `prev_hash` points at the previous entry of the same chain).
  Why: several processes cannot share one linear chain without a cross-platform file lock.
- `wrap` gets a `--server NAME` flag (policy and pins are keyed by server). Default: text after `server-` in the
  wrapped command (`@modelcontextprotocol/server-github` → `github`), else the command's base name.
- State dir `~/.agentwall`, env `AGENTWALL_HOME` overrides (tests use it).
- Taint is recorded on the RESPONSE (that is when the agent learns the data), for errors too.
  If taint or fingerprints cannot be recorded, the result is withheld (error to the agent). Fail closed.
- Fingerprint store evicts oldest-first (FIFO), not true LRU: an append-only shared file gives insertion order for
  free; LRU would need cross-process bookkeeping. Cap 2^18 fingerprints (~1.5 MB of text).
- Fingerprint words are lowercased letters/digits only, so case/spacing/punctuation changes do not hide a copy.
  One matching 8-word window is enough to block.
- The trifecta rule lives in `internal/firewall` (it needs session + policy + audit together); `internal/flow` holds
  only fingerprinting.
- Pins hash the WHOLE tool definition, not only name+description+inputSchema (a rug pull can hide in `annotations`,
  `title` or `outputSchema`). One pin file per server instead of one `pins.json`: every server's agentwall lists
  tools at startup at the same time and one shared file would lose updates.
- A changed tool is detected when a `tools/list` RESULT arrives. A call sent before that result is not blocked
  (the agent has not seen the new description yet).
- CI runs on pull requests and on pushes to `main` only (not twice per PR).

## Known issues / notes for next session
- Follow-up issues to open once gh works:
  - Duplicate keys / escapes inside `params.arguments`: policy decodes arguments with Go's rules (last key wins);
    an upstream that takes the first key would see a different value. Fix idea: re-encode arguments after decoding.
  - No frame size cap in `jsonrpc.Reader` (memory DoS from a hostile upstream). Needed before HTTP mode (M8).
  - `proxy.Run` pending map never expires requests that upstream never answers (cancelled calls).
  - Server-initiated requests (sampling, elicitation, roots) and the agent's replies pass through unfiltered.
- Race detector cannot run locally (no cgo on this Windows box); it runs in CI on Linux.
- Audit hash chains are unkeyed: they catch edits, deletions and reordering inside a chain, but not removal of
  the newest entries, nor a forged whole chain. Say so in the threat model (M9).
- `ask` prompting on the terminal while Claude Code's TUI owns it is untested — check by hand in M8.
- The firewall tests were written together with the code while the policy/audit subagents were still running,
  so they were never seen failing first.
- CHECK IN M8: session id = parent pid assumes the agent starts `agentwall` directly. If Claude Code on Windows goes
  through `cmd /c`, every server gets a different parent and cross-server taint is lost (fails OPEN). Then document
  `AGENTWALL_SESSION` in the `.mcp.json` snippet or find a better default.
- Fingerprints block the normal "read private file, edit, write it back through an egress tool" workflow
  (e.g. github `create_or_update_file` after `get_file_contents`). Escape hatches today: `on_fingerprint: ask`, or
  remove the `egress_sink` tag from that tool. Worth a follow-up issue (e.g. per-tool exemption).
- Fingerprints miss short secrets (< 8 words) and re-encoded text (base64). Say so in the threat model (M9).
- Parent pid reuse can hand old taint to a new agent (fails closed). Reset: delete `<state>/sessions`.
