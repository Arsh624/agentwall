# agentwall — Spec

> A local firewall for AI agents. Your agent never sees a real secret, and data it read from strangers can't leak your private data.

## 1. Problem

AI agents (Claude Code, Cursor, custom agents) call tools through MCP. An agent that
(a) can read private data, (b) reads untrusted content, and (c) can send data out
has the **lethal trifecta** (Simon Willison). One poisoned GitHub issue can make it
copy a private repo into a public PR — the real "GitHub MCP data heist" (2025).

Existing gateways (Docker MCP Gateway, Kong, Obot, TrueFoundry) do routing, auth and logs,
but don't enforce information flow. Small OSS repos attempt pieces of it. Nobody ships a
fast, well-tested, one-line-install tool that combines **credential isolation + flow control +
tool pinning + tamper-evident audit + a public attack suite**.

## 2. Users

- **Individual devs** using Claude Code / Cursor with MCP servers (primary; one-line install).
- **Small teams / startups** shipping agents (self-host in Docker/K8s).

## 3. Goals (v0.1, must ship)

1. **MCP proxy** — wraps any MCP server (stdio first, Streamable HTTP second). Transparent JSON-RPC 2.0 pass-through.
2. **Flow control (headline)** — per-session taint labels. Tools are tagged `untrusted_source`, `private_source`, `egress_sink` in policy. When a session holds both `untrusted` and `private` taint, calls to `egress_sink` tools are **blocked** (or `ask`). Plus content fingerprinting: hash n-grams of private tool outputs; block egress args that contain them even across sessions.
3. **Credential broker** — secrets live in agentwall's vault (OS keychain via `zalando/go-keyring`, fallback encrypted file). They're injected only into the upstream server's env/headers. The agent's config holds no secrets. Any secret-looking string in tool output is redacted before the agent sees it.
4. **Tool pinning** — on `tools/list`, hash each tool's name+description+schema; store pins. A changed tool is hidden and flagged until `agentwall approve <tool>` (stops rug pulls).
5. **Policy** — one YAML file. Per-tool: tags, `allow|deny|ask`, arg regex rules. Ships sensible defaults for popular servers (github, filesystem, fetch, slack).
6. **Audit log** — append-only JSONL, each entry carries `prev_hash` (SHA-256 chain). `agentwall verify` detects tampering.
7. **Injection heuristics** — cheap scorer (patterns: "ignore previous", hidden unicode/zero-width, base64 blobs, instruction-like text in tool outputs). Raises taint to `untrusted`; does NOT block alone.
8. **Attack suite** — `agentwall attack` replays scripted scenarios against mock MCP servers (poisoned GitHub issue, rug-pull tool, secret exfil via fetch, zero-width injection). Prints "blocked X/Y". Same suite runs in CI.
9. **Benchmarks** — Go benchmarks + a load script. Publish p50/p99 added latency. Target: < 2 ms p99 overhead per call on a laptop.

## 4. Non-goals (v0.1)

No web dashboard, no SaaS, no ML classifier, no OPA/Cedar, no multi-user auth, no K8s operator.
(Stretch list in PLAN.md.)

## 5. Architecture

```
Agent (Claude Code) ──stdio──> agentwall wrap ──stdio──> real MCP server (gets secrets via env)
                                  │
                                  ├─ jsonrpc  : parse/forward frames, match req↔resp ids
                                  ├─ session  : taint labels per session
                                  ├─ policy   : YAML → decisions (allow/deny/ask)
                                  ├─ flow     : trifecta rule + n-gram fingerprints
                                  ├─ pin      : tool hash store
                                  ├─ vault    : secrets, redaction
                                  ├─ detect   : injection heuristics
                                  └─ audit    : hash-chained JSONL
```

- Language: **Go** (single static binary, fast, cross-platform). Std lib first; deps allowed: `gopkg.in/yaml.v3`, `zalando/go-keyring`, `spf13/cobra` (CLI).
- Blocked call → return a JSON-RPC error to the agent with a clear reason (agent can tell the user).
- `ask` → prompt on the terminal/TTY of agentwall (stderr) if available, otherwise deny.
- State dir: `~/.agentwall/` (pins.json, audit.jsonl, policy.yaml, fingerprints).

## 6. CLI

```
agentwall init                         # write default policy + detect Claude Code / Cursor config
agentwall wrap [--policy f] -- <cmd>   # run an MCP server behind the firewall (stdio)
agentwall proxy --upstream URL         # HTTP mode
agentwall secret set NAME              # store secret in vault
agentwall approve <server>/<tool>      # accept a changed tool
agentwall verify                       # check audit chain
agentwall attack                       # run attack suite, print score
agentwall log [--tail]                 # pretty-print audit
```

Install: `go install`, GitHub Releases via goreleaser, `curl | sh` script.
Claude Code usage: in `.mcp.json`, command becomes `agentwall wrap -- npx @modelcontextprotocol/server-github`.

## 7. Quality bar

- Unit tests per package; table tests for policy + flow rules.
- Integration test: real stdio round trip with a mock MCP server.
- Attack suite passes 100% in CI (GitHub Actions).
- README: 30-second demo GIF, threat model, benchmark table, comparison table vs alternatives (honest).

## 8. Cost

$0. Runs on the user's machine. CI on GitHub Actions free. Optional landing page on Cloudflare Pages free.

## 9. Interview concepts this teaches

Reverse proxies & framing, JSON-RPC, information-flow control / taint tracking, capability-based security,
least privilege & credential isolation, supply-chain attacks (rug pulls), hash chains / tamper evidence,
Rabin-Karp-style n-gram fingerprinting, latency benchmarking (p50/p99), threat modeling.
