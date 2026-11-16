# agentwall — Build Plan

Read `docs/SPEC.md` first. Work milestones **in order**. Each milestone: write tests first
(superpowers:test-driven-development), make them pass, update `docs/PROGRESS.md`, commit.

**Model tag** on each task = who should do it:
- `[FABLE]` — hard design/security logic. Main session model does it itself.
- `[SONNET]` — normal code. Dispatch a subagent with `model: "sonnet"`.
- `[HAIKU]` — boilerplate, docs, config. Dispatch a subagent with `model: "haiku"`.

Keep implementations basic: std lib first, no abstractions nobody asked for.

---

## M0 — Scaffold `[HAIKU]`
- [ ] `go mod init github.com/<user>/agentwall`, dirs: `cmd/agentwall`, `internal/{jsonrpc,proxy,session,policy,flow,pin,vault,detect,audit}`, `attacks/`, `testdata/`
- [ ] cobra CLI skeleton with all commands from SPEC §6 (stubs return "not implemented")
- [ ] `.github/workflows/ci.yml`: `go vet`, `go test ./...` on ubuntu/windows/macos
- [ ] `.gitignore`, MIT `LICENSE`, one-paragraph `README.md`
- **Done when:** `go build ./... && go test ./...` passes; CI green.

## M1 — JSON-RPC stdio proxy `[FABLE]`
- [ ] `internal/jsonrpc`: read/write newline-delimited JSON-RPC 2.0 frames; types for request/response/notification/error
- [ ] `internal/proxy`: `wrap -- <cmd>` spawns upstream, pipes agent↔upstream both ways, tracks pending request ids so responses can be matched to the tool call that caused them
- [ ] hook points: `OnRequest(req) (decision)`, `OnResponse(req, resp) (resp')`
- [ ] `testdata/mockserver`: tiny Go MCP server (initialize, tools/list, tools/call) driven by a JSON scenario file
- [ ] integration test: agent→proxy→mockserver round trip; large payloads; concurrent ids
- **Done when:** proxy is transparent (no hooks) and tests pass.

## M2 — Policy + audit `[SONNET]`
- [ ] `internal/policy`: load YAML (`servers.<name>.tools.<tool>: {tags, action, deny_args}`), defaults, `Decide(server, tool, args) → allow|deny|ask + reason`
- [ ] default policy file for github, filesystem, fetch, slack servers (tags per SPEC §3.2)
- [ ] `internal/audit`: append JSONL `{ts, session, server, tool, args_hash, decision, reason, prev_hash, hash}`; `Verify()`; `agentwall verify` + `agentwall log`
- [ ] tests: table tests for Decide; tamper test (edit a line → verify fails)
- **Done when:** blocked calls return JSON-RPC error with reason; every call is logged.

## M3 — Flow control (headline) `[FABLE]`
- [ ] `internal/session`: taint set per session `{untrusted, private}`; set from tool tags on response
- [ ] trifecta rule: session has untrusted+private → `egress_sink` calls get `deny` (or `ask` if policy says)
- [ ] `internal/flow` fingerprints: from `private_source` outputs, store hashed rolling n-grams (e.g. 8 words, Rabin-Karp); egress args checked for matches → deny even in a fresh session. Cap store size (LRU).
- [ ] tests: the GitHub heist scenario (read public issue → read private repo → create PR) is blocked at step 3; benign sequences pass; fingerprint catches pasted private text
- **Done when:** heist scenario blocked, false-positive tests pass.

## M4 — Tool pinning `[SONNET]`
- [ ] `internal/pin`: hash name+description+inputSchema (canonical JSON); store in `~/.agentwall/pins.json`
- [ ] on `tools/list` response: new tool → pin (trust on first use); changed tool → remove from list + warn on stderr + audit
- [ ] `agentwall approve <server>/<tool>`
- [ ] tests: rug-pull scenario (description changes on 2nd list) → tool hidden
- **Done when:** rug pull blocked.

## M5 — Credential broker + redaction `[FABLE]`
- [ ] `internal/vault`: `secret set/get/list` via go-keyring, fallback AES-GCM file keyed from a passphrase env var
- [ ] policy: `servers.<name>.env: {GITHUB_TOKEN: "vault:github"}` → injected only into the upstream process env
- [ ] redaction: every response scanned for known vault values + common token patterns (ghp_, sk-, xox, AKIA…) → replaced with `[REDACTED:name]`
- [ ] tests: secret never appears in agent-side output; upstream receives it
- **Done when:** demo config has zero secrets and still works.

## M6 — Injection heuristics `[SONNET]`
- [ ] `internal/detect`: score text (instruction phrases, zero-width/bidi unicode, long base64, "you are now", URLs + "send"); score ≥ threshold → mark session `untrusted` + audit
- [ ] tests with a small corpus in `testdata/injections/` (positives + benign negatives)
- **Done when:** corpus precision/recall printed by test; no blocking on its own.

## M7 — Attack suite + benchmarks `[SONNET]`
- [ ] `attacks/*.json` scenarios: github heist, rug pull, secret exfil via fetch, zero-width injection, fingerprint exfil across sessions, benign control cases
- [ ] `agentwall attack` runs them against mockserver, prints table + "blocked X/Y, false positives Z"
- [ ] CI runs `agentwall attack` and fails on regression
- [ ] `bench_test.go` + `scripts/load` → p50/p99 overhead; write numbers to `docs/BENCHMARKS.md`
- **Done when:** score table and real benchmark numbers exist.

## M8 — Real-world integration `[FABLE]`
- [ ] `agentwall init`: write default policy; print the `.mcp.json` snippet for Claude Code / Cursor
- [ ] verify by hand with the real `@modelcontextprotocol/server-github` (or filesystem server) through Claude Code; note any protocol gaps and fix
- [ ] Streamable HTTP mode (`agentwall proxy`) — basic, reuse same hooks
- **Done when:** a real agent session works through agentwall.

## M9 — Ship `[HAIKU]`
- [ ] goreleaser config + release workflow; `install.sh`
- [ ] README: pitch, 30-sec demo GIF placeholder, quickstart, threat model, attack table, benchmark table, honest comparison (Docker MCP Gateway, Kong, guardbee, Interlock)
- [ ] `docs/ARCHITECTURE.md` with the design decisions + why (for interview prep)
- **Done when:** `v0.1.0` tag builds binaries.

---

## Stretch (only after M9)
- Cedar/OPA policy backend · small ONNX injection classifier · RFC 8693 token exchange for short-lived scoped tokens · Helm chart · static landing page on Cloudflare Pages · web log viewer
