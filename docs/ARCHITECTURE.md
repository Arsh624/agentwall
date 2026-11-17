# agentwall architecture

This page explains how agentwall is built and why. The product pitch and goals are in [SPEC.md](SPEC.md). The build history and the open issues are in [PROGRESS.md](PROGRESS.md).

## 1. The picture

The agent starts one `agentwall wrap` process for each MCP server. Each process sits between the agent and one real server.

```
Agent (Claude Code, Cursor)
   |  stdio: newline-delimited JSON-RPC 2.0 frames
   v
agentwall wrap            one process per MCP server
   |
   |  proxy        (internal/proxy, internal/jsonrpc)
   |                 reads frames, re-encodes them, matches replies to requests
   |  firewall     (internal/firewall)  the only place the hooks are defined
   |     policy    (internal/policy)    allow / deny / ask, deny_args, tags, env
   |     pin       (internal/pin)       hash of each tool definition
   |     session   (internal/session)   taint markers, shared by all wraps of one agent
   |     flow      (internal/flow)      fingerprints of private text
   |     vault     (internal/vault)     secrets, redaction of answers
   |     detect    (internal/detect)    injection heuristics
   |     audit     (internal/audit)     hash-chained JSONL log
   |
   |  stdio, or HTTP in `agentwall proxy`
   v
Real MCP server           gets its secrets in its environment or headers
```

`mockserver` and `attack` are not on the call path. `mockserver` is a scripted MCP server used by the tests and the benchmarks. `attack` replays attack scripts through the real proxy and firewall against mock servers, and scores the result. `cmd/agentwall` builds the CLI on top of all of this.

The life of one tool call: the agent sends a `tools/call` request. The firewall checks the policy (including `deny_args`), the pin (a hidden tool is denied), and the flow rules for egress tools (the trifecta rule and the fingerprint rule). If the call is allowed, the proxy sends it to the server. When the reply comes back, the firewall first redacts secrets from the answer, then pins the tool list if this was a `tools/list`. For a `tools/call` it taints the session (from the tool's tags), runs the injection heuristics, taints the session again if the tool is `private_source`, and fingerprints the private text. Only then does the agent get the reply. If any of the state cannot be recorded, the agent gets an error instead.

## 2. One process per server, shared state in files

Claude Code starts one `agentwall wrap` per MCP server. A common attack spans servers: an issue from the github server, a file from the filesystem server, and a send through the fetch server. So taint and fingerprints must be visible to all of these processes. There is no daemon. The processes share files under `~/.agentwall/` (or `AGENTWALL_HOME`). No process needs a lock on them.

- **Session taint: `sessions/<id>/untrusted` and `sessions/<id>/private`.** These are marker files. A process only ever creates them, never deletes them. Creating a file that exists is harmless, so there is no race to handle. The session id is shared by all wraps of one agent (see decision 9).
- **Fingerprints: `fingerprints`.** One append-only file. Its first 8 bytes are a generation number, then come 8-byte fingerprints. Each process reads the file into memory, and appends its own new fingerprints. When the file is full, it is rewritten with the newest half under a new generation number. Other processes see the new generation and reload. Fingerprints are shared across sessions on purpose, so the block still applies in a fresh session.
- **Audit log: `audit.jsonl`.** Every process opens it with `O_APPEND` and writes one line per entry. Several processes cannot share one linear chain without a cross-platform file lock, and the project has none. So each process keeps its own hash chain: each entry has a random `chain` id, and `prev_hash` points to the previous entry of the same chain. `agentwall verify` checks each chain separately.
- **Tool pins: `pins/<server>.json`.** One file per server. Every wrap process lists tools at startup, so one shared file would lose updates.
- **Policy: `policy.yaml`.** Read at start. Changing it needs a restart of the agent's servers.
- **Secrets:** the OS keychain, or `vault.enc` (AES-256-GCM) when `AGENTWALL_PASSPHRASE` is set.

## 3. Design decisions and why

Each entry gives the decision, the reason, and the cost.

### Always re-encode frames

- **Decision.** The proxy parses each frame into a `Message` and writes it back from that parsed value. It does not forward the raw bytes. The `params` and `result` fields are kept as they were, but compacted.
- **Why.** The upstream then sees exactly what the hooks looked at. There is no difference in how the two sides parse the frame, and a hook cannot be skipped by sending odd bytes.
- **Trade-off.** Extra work for every frame. The benchmarks show the proxy costs about 9 µs per call in process.

### Fail closed on odd traffic and on state that cannot be recorded

- **Decision.** A bad frame from the agent gets a `-32700` reply. A bad frame from the upstream, or a reply with an unknown id, is dropped and logged to stderr. JSON-RPC batches are refused, since MCP removed them. If the audit log cannot take an entry, the call is denied. If taint or fingerprints cannot be recorded, the result is withheld. If the tool list cannot be checked against the pins, the list is withheld.
- **Why.** The agent must never see data that the firewall failed to track.
- **Trade-off.** A server that sends unusual but valid traffic can break. The agent sees errors instead of silent gaps.

### Taint on the response

- **Decision.** A tool's tags taint the session when its answer comes back, not when the call goes out. This applies to error answers too.
- **Why.** Taint describes what the agent now knows. The data reaches the agent only with the answer.
- **Trade-off.** A call that is already in flight when the taint arrives is not blocked. The egress call that comes after the taint is what gets blocked.

### One 8-word fingerprint match is enough to block

- **Decision.** Text is hashed in windows of 8 words (lowercased letters and digits only). One matching window in the egress arguments blocks the call.
- **Why.** An attacker can copy a short piece of private text. Requiring many matches would let a short leak through.
- **Trade-off.** An egress call that legitimately contains 8 words of private text is blocked too. The clearest case is writing back an edited private file (issue #17).

### FIFO eviction instead of LRU

- **Decision.** When the fingerprint store is full (cap 2^18 fingerprints, about 1.5 MB of text), the oldest half is dropped.
- **Why.** The store is an append-only shared file, so the file order is the insertion order for free. An LRU cache would need every process to write when it reads, which needs cross-process bookkeeping.
- **Trade-off.** A fingerprint that is still used can be dropped because it is old.

### Hashing the whole tool definition

- **Decision.** A pin is a hash of the complete tool object: name, description, input schema, annotations, title, output schema and so on.
- **Why.** A rug pull can hide an instruction in a field other than the description, such as `annotations` or `outputSchema`. Hashing only the usual fields would miss it.
- **Trade-off.** A harmless change to any field, for example a wording change in `annotations`, hides the tool until `agentwall approve`.

### Vault backend choice

- **Decision.** The OS keychain is the default. If `AGENTWALL_PASSPHRASE` is set, the encrypted file is used instead. There is no automatic fallback between them. Without either, `wrap` still runs with pattern-only redaction and prints a warning, unless the policy needs a secret for that server.
- **Why.** A silent switch of backend would hide where the secrets are. The passphrase is also removed from the server's environment, so the server never gets it.
- **Trade-off.** On a machine with no keychain, the user must set the passphrase variable. Pattern-only redaction misses secrets that do not match a known token format.

### Redaction on decoded JSON strings

- **Decision.** Redaction works on the strings inside a decoded JSON document, not on the raw bytes. A document with no secret comes back byte for byte.
- **Why.** Escaping (for example `github`) cannot hide a secret from the redactor.
- **Trade-off.** Documents with secrets are decoded and encoded again. Vault values shorter than 8 characters are not redacted, so short values do not blank normal text.

### Heuristics only taint

- **Decision.** A suspicious tool answer marks the session untrusted. It never blocks a call by itself. The flow rules decide what an untrusted session may do.
- **Why.** Pattern matching has false positives. The corpus in `testdata/injections` has two accepted false positives: a security blog quoting an attack, and curl upload docs. Blocking on them would stop normal work.
- **Trade-off.** An injection that does not lead to an egress call does nothing. The heuristics can also be evaded.

### Keyword-first scanning for speed

- **Decision.** The scanner first looks for keywords in one pass. A regular expression runs only on a short slice around each keyword hit. Secret-format regular expressions run only on strings that contain their literal hint.
- **Why.** Go's `regexp` costs about 30 ns per byte, too slow to run over every tool answer. The earlier version took 1.1 to 1.4 ms added p99 for 10 KB payloads. After this change the figure is about 0.5 ms.
- **Trade-off.** Known gaps against the plain whole-text version: matches longer than 160 bytes, non-ASCII look-alike letters, and a rare false `addressed` hit on very long lines.

### HTTP mode refuses `Origin`

- **Decision.** `agentwall proxy` refuses any request that has an `Origin` header. It listens on loopback by default and warns when told to listen elsewhere.
- **Why.** Browsers send `Origin`. MCP clients do not. The proxy adds the server's credentials to upstream requests, so a web page must not be able to use the local port.
- **Trade-off.** A client that runs in a browser cannot use HTTP mode.

### Session id from the parent process

- **Decision.** The session id is `ppid-<agent pid>`, so all wraps started by one agent share it. The agent is our parent; on Windows, a `cmd /c` or PowerShell parent is skipped, because those stay alive between the agent and us. The environment variable `AGENTWALL_SESSION` overrides it.
- **Why.** The agent starts each wrap as its child. This needs no config, and it works without any agent-specific support.
- **Trade-off.** The OS can reuse a pid, so a new agent may inherit old taint. That fails closed: delete `sessions/` to reset. Another kind of wrapper process would give each server its own id, and taint would not be shared between them; `AGENTWALL_SESSION` fixes that.

### Module layout: `firewall` is the only place the hooks are defined

- **Decision.** `internal/proxy` knows only two hook functions, `OnRequest` and `OnResponse`. `internal/firewall` builds those hooks from policy, pins, session, flow, vault, detect and audit. Every check is in one place.
- **Why.** The proxy stays small and easy to test with plain mock traffic. The order of the checks is in one file to read.
- **Trade-off.** `firewall` is the largest package, and the order of its checks matters. For example, a response is redacted before it is pinned, tainted and fingerprinted.

### Policy in YAML, not OPA or Cedar

- **Decision.** The policy is a strict YAML file. Unknown keys are errors.
- **Why.** It is the smallest format that does the job for v0.1, and the file is easy to read.
- **Trade-off.** The policy language cannot express complex rules. OPA and Cedar are non-goals for v0.1 (see SPEC.md).

## 4. Concepts this project uses

- **Reverse proxy and framing.** A proxy stands between two parties and relays messages. MCP over stdio sends one JSON message per line, so the proxy reads lines (a "frame") and must handle very long lines. Code: `internal/jsonrpc` (`Reader` has a 64 MiB frame cap, `MaxFrame`), `internal/proxy`.
- **JSON-RPC 2.0.** A small protocol for calls over a stream. A request has a `method` and an `id`; a response has the same `id` and either `result` or `error`. A notification has no `id` and gets no reply. The proxy matches replies to requests by `id`. Code: `internal/jsonrpc`, `internal/proxy` (pending map).
- **Taint tracking and information-flow control.** Data gets a label when it enters the system, and the labels follow the data to where it goes. Here the labels are per session: "read untrusted content" and "read private data". A rule then decides what a session with a label may do. Code: `internal/session`, `internal/firewall` (`flowRules`).
- **Lethal trifecta.** The combination of reading private data, reading untrusted content and sending data out, which lets outside text steer an agent into a leak. The name is from Simon Willison. Code: the trifecta rule in `internal/firewall/firewall.go`.
- **Rabin-Karp rolling hash.** A hash of a sliding window of text that can be updated in constant time as the window moves. Used to fingerprint every 8-word window of private text without rehashing it each time. Code: `internal/flow/flow.go`.
- **Trust on first use.** A system accepts a value the first time it sees it and flags later changes. Tool pins work this way: the first tool definition is accepted, and a changed one is hidden until approved. Code: `internal/pin/pin.go`.
- **Hash chains.** Each log entry includes the hash of the previous entry, so editing or removing an entry in the middle breaks the chain. A hash chain without a key does not stop someone who rewrites the whole chain. Code: `internal/audit/audit.go` (`prev_hash`, `hash`).
- **AES-GCM and PBKDF2.** AES-GCM is an encryption mode that also detects tampering. PBKDF2 turns a passphrase into an encryption key by running a hash many times (agentwall uses 600,000 rounds of HMAC-SHA256). Code: `internal/vault/vault.go`.
- **p50 and p99 latency.** The 50th and 99th percentile of the time per call. p99 shows the slow tail that users notice. The benchmark measures the added time, wrapped minus direct. See [BENCHMARKS.md](BENCHMARKS.md). Code: `scripts/load`.

## 5. Known limits

Each line says what does not work. The sources are in [PROGRESS.md](PROGRESS.md) and in the README threat model.

- Fingerprints miss secrets shorter than 8 words and text that was re-encoded (for example base64).
- Vault values shorter than 8 characters are not redacted. Values are caught as written, percent-encoded or in base64, not in other encodings.
- Without a keychain and a passphrase, redaction is by pattern only.
- The audit hash chain is not keyed. It detects edits, deletions and reordering inside a chain. It does not detect removal of the newest entries, or a forged whole chain.
- Server notifications and requests are redacted but not tainted. Sampling is refused; over HTTP the refusal is a dropped request, not an error reply.
- A tool that the policy does not tag gets no flow control.
- Taint is shared between servers by the agent's process id. This is not yet confirmed with a logged-in Claude Code session.
- A request that the server never answers and the agent never cancels stays in the pending map until the process exits.
- The fingerprint rule blocks writing an edited private file back through an egress tool. The workarounds are `on_fingerprint: ask` or removing the `egress_sink` tag from that tool.
- The injection heuristics are pattern matching and can be evaded.
- Not yet verified: a real Claude Code session through agentwall, a real remote HTTP MCP server, and the `ask` prompt with a real agent UI.
