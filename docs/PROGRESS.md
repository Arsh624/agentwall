# agentwall — Progress (handoff file)

Any model picking this up: read this file, then `docs/PLAN.md`, then `git log --oneline -20`.
Continue from **Next task**. Update this file and commit after every task.

## Status
- Repo: https://github.com/Arsh624/agentwall (public). Module `github.com/Arsh624/agentwall`. gh is signed in as Arsh624.
- Merged to `main` through PRs: M1 (#10), M2 (#11), M3 (#12), M4 (#19), M5 (#20), M6 (#21), M7 (#22), M8 (#23). CI green on ubuntu/windows/macos (+ race detector on Linux).
- Released: `v0.1.0` is published (https://github.com/Arsh624/agentwall/releases/tag/v0.1.0): 6 binaries
  (linux/darwin/windows x amd64/arm64) + `checksums.txt`, built by `.github/workflows/release.yml` (tests and the attack
  suite ran first). `install.sh` was run once on Ubuntu (WSL): it installed `agentwall 0.1.0`, which passed the attack
  suite. NOT run by hand: the macOS and Windows binaries, the checksum-mismatch path of `install.sh`.
- All nine milestones are merged. Nothing is in progress.
- NEEDS THE USER: (1) one real Claude Code session through agentwall (the `claude` CLI on this machine is not logged
  in) - steps in "Known issues" below (issue #18); (2) a 30-second demo GIF at `docs/demo.gif` (the README has a
  placeholder).
- Hardening after v0.1.0 (branch `harden-v0.1.1`): secrets redacted in base64/percent-encoded form and in object keys;
  server notifications and requests redacted, sampling refused (#16); cancelled requests forgotten (#15); tools/call
  params re-encoded before upstream (#13); Windows session id looks past cmd/PowerShell parents (#18). #17 closed
  as by design. `main` is branch-protected: PR + the 3 CI checks required, admin bypass on.
- Next: the stretch list in PLAN.md.
- Issues: milestone M<n> = issue #<n> (#1–#9). Follow-ups #13–#18 are closed.
- Model that last worked: Opus 5.5

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
- M5 — credential broker + redaction (branch `m5-credential-broker`, all Fable):
  - `internal/vault`: `Open(stateDir)` → OS keychain (go-keyring; one entry per secret + an index entry), or an
    AES-256-GCM file `<state>/vault.enc` keyed by PBKDF2 (600k) from `AGENTWALL_PASSPHRASE` when that env var is set.
    `Set` / `Get` / `List` / `All`.
  - `vault.Redactor`: `Text` and `JSON` replace vault values (≥ 8 chars, longest first) with `[REDACTED:<name>]` and
    known token formats (GitHub, `sk-…`, Slack, AWS key id, private key blocks) with `[REDACTED:<kind>]`. JSON is
    redacted on decoded strings, so escaping cannot hide a secret; untouched documents come back byte for byte.
  - `internal/policy`: `servers.<name>.env: {VAR: "vault:<secret>"}`; literals are rejected.
  - `internal/firewall`: every upstream answer (result, error message, error data) is redacted first, then pinned /
    tainted / fingerprinted; redactions are audited by name (`redact`).
  - CLI: `agentwall secret set NAME` (value from stdin), `agentwall secret list`; `wrap` builds the server env =
    our env − `AGENTWALL_PASSPHRASE` + the server's vault secrets, and refuses to start if one is missing.
  - Verified end to end: upstream receives the token (mock `printenv` tool), the agent sees `[REDACTED:github]`,
    the passphrase is not passed on, another server does not get the token, no file holds the token in clear text.
- M6 — injection heuristics (branch `m6-injection-heuristics`):
  - `internal/detect` (Sonnet): `Score(text) Result{Score, Signals}`, `Threshold = 3`. Signals: `override` (3),
    `hidden-unicode` (3), `role` (2), `addressed` (2), `secrecy` (2), `exfil` (2), `base64` (1), `url-send` (1).
    Corpus in `testdata/injections/{positive,negative}`; `TestCorpus` prints precision/recall and fails below 0.90 / 0.85.
    Keyword search on a lowercased copy picks small windows for the regexps, so cost stays low on large outputs;
    `TestFastMatchesReference` checks it against the plain whole-text version.
  - `internal/firewall` (Fable): `scan` runs on every `tools/call` result of a session that is not yet untrusted;
    a suspicious result marks the session `untrusted` and is audited as `detect` with the signal names. It never blocks.
  - Verified: an injection returned by an UNTAGGED tool taints the session and then completes the trifecta.
- M7 — attack suite + benchmarks (branch `m7-attack-suite`):
  - `firewall.Open(Config)` (Fable): one constructor used by `wrap`, the attack runner, tests and benchmarks.
  - `attacks/*.json` + `internal/attack` (Sonnet): 5 attacks (github heist, rug pull, secret exfil via fetch,
    zero-width injection, fingerprint across sessions) and 4 benign controls, embedded in the binary, replayed through
    the real proxy + firewall against in-process mock servers. `agentwall attack` prints the table and
    `blocked 5/5 attacks, false positives 0/4`; exit code 1 on any regression. CI runs it on all three OSes.
  - Benchmarks (Sonnet): `internal/firewall/bench_test.go`, `scripts/load` (real processes, direct vs wrapped,
    p50/p99), hidden `agentwall mock-server <scenario.json>`, `docs/BENCHMARKS.md` with the measured numbers:
    added p99 about 0.2 ms at 1 KB and 0.5 ms at 10 KB (target < 2 ms).
  - Redaction regexps now run only on strings containing a token hint (Fable): halved the per-call cost.
- M8 — real-world integration (branch `m8-real-world`, all Fable):
  - Ran the official `@modelcontextprotocol/server-filesystem` (v2.3.0, via `npx`) behind `agentwall wrap` with a
    scripted client: initialize, tools/list (16 tools pinned), list/read/write calls, token formats in a file redacted
    (also inside `structuredContent`), private taint set, audit verified, clean exit. Added latency per call was not
    visible next to the server's own.
  - Gap found and fixed: the default policy missed `list_directory_with_sizes` and all the tool names of the current
    `github/github-mcp-server` (`issue_read`, `pull_request_read`, `issue_write`, ...). Untagged tools get no flow control.
  - `agentwall init`: writes `<state>/policy.yaml` once (never overwrites), finds `.mcp.json`, `.cursor/mcp.json`,
    `~/.claude.json`, `~/.cursor/mcp.json` and prints the wrapped version of each server. It never edits those files
    and never prints env values.
  - Frame cap: one JSON-RPC frame is at most 64 MiB (`jsonrpc.MaxFrame`), closes #14.
  - HTTP mode: `proxy.HTTPHandler` + `agentwall proxy --upstream URL [--listen 127.0.0.1:7878] [--server] [--policy]`.
    Same hooks as stdio; JSON and SSE replies go through `OnResponse`; policy `servers.<name>.headers: {Authorization:
    "vault:x"}` puts the credential on upstream requests only; requests with an `Origin` header are refused.
  - Verified: heist blocked over HTTP through the CLI against a test MCP-over-HTTP server that only accepts the vault
    credential. NOT verified: a real remote HTTP MCP server, and a logged-in Claude Code session.
- M9 — ship (branch `m9-ship`, Haiku subagents, reviewed by Fable):
  - `agentwall --version` (set by `-ldflags "-X main.version=..."`), `.goreleaser.yaml` (linux/darwin/windows ×
    amd64/arm64, checksums), `.github/workflows/release.yml` (on `v*` tags: tests, attack suite, GoReleaser),
    `install.sh` (POSIX sh; verifies SHA-256 before installing into `~/.local/bin`; no sudo).
  - `README.md` (pitch, demo placeholder, problem, features, install, quick start, policy, attack table, benchmark
    table, threat model, comparison, commands, status) and `docs/ARCHITECTURE.md` (picture, shared state, decisions
    with why and trade-off, concepts, limits).
  - NOT verified: GoReleaser, the release workflow and `install.sh` cannot run until a tag exists.

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
- Vault backend choice: `AGENTWALL_PASSPHRASE` set → encrypted file, otherwise the OS keychain. No automatic
  fallback: a silent switch of backend would hide where secrets live. No keychain and no passphrase → `wrap` still
  runs with pattern-only redaction (warning on stderr) unless the policy needs a secret for that server.
- `secret list` was added (names only) because a keychain cannot be listed by hand; there is no `secret get` on
  purpose (nothing should print a secret).
- Vault values shorter than 8 characters are stored but not redacted (they would blank ordinary text).
- HTTP mode refuses any request that carries an `Origin` header: browsers send it, MCP clients do not, and the proxy
  adds credentials, so a web page must not be able to use the local port. It listens on loopback by default and warns
  when told to listen elsewhere.
- HTTP mode uses one session per proxy process (not per `Mcp-Session-Id`). JSON-RPC batches are refused in both transports.
- Server messages (#16): redacted, not tainted (logs and progress are not model input in today's agents). Sampling
  is refused outright: the server would write the prompt and read the answer, which no policy can see into.
- Vault values are also matched percent-encoded and as the 3 base64 alignments (std and URL alphabets), so a
  server echoing a Basic auth header is caught. Hex and compressed forms are not.
- #17 stays as designed: writing private text back through an egress tool is blocked, because the firewall cannot
  tell the user's repo from an attacker's. Workarounds: `on_fingerprint: ask`, or untag the tool.
- `init` only prints what to change; editing a user's agent config is theirs to do.
- The README keeps the SPEC's pitch ("Your agent never sees a real secret") and lists the cases where that does not
  hold under "What it does not stop". The comparison section only says what we know and tells the reader to check.

## Known issues / notes for next session
- Race detector cannot run locally (no cgo on this Windows box); it runs in CI on Linux.
- Audit hash chains are unkeyed: they catch edits, deletions and reordering inside a chain, but not removal of
  the newest entries, nor a forged whole chain. Say so in the threat model (M9).
- `ask` prompting on the terminal while Claude Code's TUI owns it is untested — check by hand in M8.
- The firewall tests were written together with the code while the policy/audit subagents were still running,
  so they were never seen failing first.
- Fingerprints block the normal "read private file, edit, write it back through an egress tool" workflow
  (e.g. github `create_or_update_file` after `get_file_contents`). Escape hatches today: `on_fingerprint: ask`, or
  remove the `egress_sink` tag from that tool. Worth a follow-up issue (e.g. per-tool exemption).
- Fingerprints miss short secrets (< 8 words) and re-encoded text (base64). Say so in the threat model (M9).
- Parent pid reuse can hand old taint to a new agent (fails closed). Reset: delete `<state>/sessions`.
- `secret set` echoes the value when typed at a terminal (hiding it needs x/term, not an allowed dependency). Pipe it in.
- The vault tests and the M5 CLI wiring were written together with the code, not seen failing first (the redactor, policy env, firewall and CLI tests were).
- `detect` speed (83 µs per 10 KB) comes from keyword hits + short anchored regexps. Known gaps versus the plain whole-text version: matches longer than 160 bytes, non-ASCII look-alike letters, and a rare false `addressed` hit on very long lines. Two corpus false positives are accepted (a security blog quoting an attack, curl upload docs): they only taint.
- TO VERIFY WITH A REAL AGENT: in a project, create `.mcp.json` with two servers started through
  `agentwall wrap` (e.g. the filesystem server and `uvx mcp-server-fetch`), use both in one Claude Code session, then run
  `agentwall log`: every entry of that session must show the same session id. If the ids differ, set
  `AGENTWALL_SESSION` in each server's `env` in `.mcp.json`. Evidence so far: the not-logged-in CLI created one
  session directory for the servers it started.
- `ask` prompting on the terminal is still untested with a real agent UI.
