# agentwall

[![CI](https://github.com/Arsh624/agentwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Arsh624/agentwall/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Arsh624/agentwall)](https://github.com/Arsh624/agentwall/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/Arsh624/agentwall)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A local firewall for AI agents. Your agent never sees a real secret, and data it read from strangers can't leak your private data.

agentwall sits between an AI agent (Claude Code, Cursor) and the MCP servers it uses. MCP (Model Context Protocol) is the way agents call tools such as "read a file" or "open a pull request". agentwall runs on your machine as one binary, checks every tool call and every tool answer, and blocks the calls that would leak data.

It is for people who run AI agents with MCP servers on their own computer, and who want the agent to read private data without that data being sent out by a prompt-injected tool call.

**At a glance**

- Blocks 5 of 5 scripted attacks in the bundled suite, with 0 false positives on 4 normal sessions. You can rerun it with `agentwall attack`.
- Adds about 0.2 ms at p99 per tool call for 1 KB payloads (0.5 ms for 10 KB), well under the 2 ms target. See [Benchmarks](#benchmarks).
- One Go binary for Linux, macOS and Windows. Works with stdio and HTTP MCP servers.
- Covers the GitHub MCP "lethal trifecta" heist, secret exfiltration through fetch, tool rug pulls, zero-width injection and cross-session leaks of private text.

## Demo

![agentwall attack suite: 5 of 5 attacks blocked, 0 false positives, and the GitHub heist call being refused](docs/demo.svg)

Text version of the demo, a copy of the GitHub heist scenario in `attacks/github-heist.json`:

1. The agent reads a public issue. The issue text tells the agent to copy a private repo into a pull request. The session is now marked untrusted.
2. The agent reads a file from the private repo. The session is now marked private too.
3. The agent calls `create_pull_request`. agentwall blocks the call and returns this error to the agent (JSON-RPC error code -32001):

```
agentwall blocked this call: lethal trifecta: this session has read untrusted content and private data, so a tool that sends data out is not allowed
```

## The problem

An agent that can read private data, read untrusted content, and send data out has what is called the lethal trifecta (a term from Simon Willison). Each part is normal. Together they let anyone who can write text the agent reads steer the agent into leaking your data. The real-world case named in the project spec is the GitHub MCP data heist (2025): one poisoned GitHub issue made an agent copy a private repository into a public pull request. The third part, a tool that sends data out, is what turns it into a leak. agentwall tracks what the agent has read in each session and blocks the third part when the first two are both present.

```mermaid
flowchart LR
    A[AI agent<br/>Claude Code, Cursor] -->|tool call| W{agentwall}
    W -->|allowed| S[MCP servers<br/>GitHub, filesystem, fetch]
    S -->|tool output| W
    W -->|redacted output| A
    W -. session taint, fingerprints, pins .-> T[(~/.agentwall state)]
    W -. every decision .-> L[(hash-chained audit log)]
    W -->|untrusted + private + egress| X[blocked, error -32001]
```

## What it does

- **Flow control.** Each tool in the policy is tagged `untrusted_source`, `private_source` or `egress_sink`. A session that has read untrusted content and private data cannot call an egress tool. This works across all the MCP servers of one agent.
- **Fingerprints of private text.** Text from private tool outputs is hashed in 8-word windows. An egress call whose arguments contain that text is blocked, even in a later session.
- **Credential broker.** Secrets are stored in agentwall's vault (the OS keychain, or an encrypted file). They are passed only to the MCP server's environment or HTTP headers, so the agent's config holds no secret. Secret-looking text in tool output is replaced with `[REDACTED:<name>]` before the agent sees it.
- **Tool pinning.** agentwall hashes each tool's whole definition the first time it sees it. If the definition changes later (a rug pull, where a tool quietly changes what it does), the tool is hidden until you run `agentwall approve`.
- **Policy file.** One YAML file sets tags, `allow` / `deny` / `ask` per tool, argument rules, and the environment for each server.
- **Tamper-evident audit log.** Every decision is written to a JSONL file. Each entry includes a hash of the previous entry. `agentwall verify` detects edits, deletions and reordering.
- **Injection heuristics.** Pattern checks look for text such as "ignore previous instructions" and hidden zero-width characters in tool output. A match marks the session untrusted. It never blocks a call by itself.
- **Attack suite.** `agentwall attack` replays scripted attacks and harmless control runs against mock servers, so you can check the firewall yourself.

## Install

Pick one:

- With Go: `go install github.com/Arsh624/agentwall/cmd/agentwall@latest`
- Install script (Linux and macOS). It downloads the release and verifies its checksum: `curl -fsSL https://raw.githubusercontent.com/Arsh624/agentwall/main/install.sh | sh`
- Binary: download it from the Releases page on GitHub.

The latest release is [v0.1.1](https://github.com/Arsh624/agentwall/releases/tag/v0.1.1). It has binaries for Linux, macOS and Windows (amd64 and arm64) and a `checksums.txt` file. The install script was run on Linux (Ubuntu under WSL), and the Windows amd64 binary was run by hand; both passed the attack suite. The macOS and arm64 binaries were built by the release workflow but have not been run by hand.

## Quick start

1. Write the default policy and find your agent's MCP servers:

   ```
   agentwall init
   ```

   This writes `~/.agentwall/policy.yaml` (only if the file does not exist). It prints the wrapped version of each server it finds in `.mcp.json`, `.cursor/mcp.json`, `~/.claude.json` and `~/.cursor/mcp.json`. It never edits those files.

2. Put each MCP server behind agentwall in your agent config. In `.mcp.json`, change this:

   ```json
   {
     "mcpServers": {
       "github": {
         "command": "npx",
         "args": ["-y", "@modelcontextprotocol/server-github"]
       }
     }
   }
   ```

   to this:

   ```json
   {
     "mcpServers": {
       "github": {
         "command": "agentwall",
         "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
       }
     }
   }
   ```

3. Move the token out of the agent config and into the vault. The value is read from stdin, not from the command line:

   ```
   printf '%s\n' "$GITHUB_PERSONAL_ACCESS_TOKEN" | agentwall secret set github
   ```

   Then add this to `~/.agentwall/policy.yaml`, so the server gets the token from the vault:

   ```yaml
   servers:
     github:
       env:
         GITHUB_PERSONAL_ACCESS_TOKEN: "vault:github"
   ```

   Remove the token from your agent config yourself. agentwall does not edit it.

4. Use the agent as usual. Then check what happened:

   ```
   agentwall log
   agentwall verify
   agentwall attack
   ```

- When a tool's definition changes, its calls are blocked and the error tells you the command to run. Accept the change with `agentwall approve <server>/<tool>`.
- For an HTTP MCP server, run `agentwall proxy --upstream URL` and point the agent at the address set by `--listen` (default `127.0.0.1:7878`).

## Policy

The policy is one YAML file. Here is an annotated example. Most keys are optional.

```yaml
# What happens to a tool call that no tool rule covers: allow, deny or ask.
default_action: allow

# What happens to an egress call when the session has read both untrusted and
# private data (on_trifecta), or when its arguments contain private text (on_fingerprint).
# deny blocks the call. ask asks you on the terminal.
on_trifecta: deny
on_fingerprint: deny

servers:
  github:                              # the name the policy uses for this server
    tools:
      get_issue:
        tags: [untrusted_source]       # text here is written by strangers
      get_file_contents:
        tags: [private_source]         # text here may be your private data
      create_pull_request:
        tags: [egress_sink]            # this call sends data out
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "vault:github"   # filled from the vault, for this server only

  filesystem:
    tools:
      read_file:
        tags: [private_source]
        deny_args:
          path: '\.env$'               # deny the call when this argument matches the regexp
      write_file:
        action: ask                    # ask you before each call
```

The three tags:

- `untrusted_source`: the output can be written by people outside your control, such as issues or web pages.
- `private_source`: the output can contain your private data, such as repo files or local files.
- `egress_sink`: the call can send data out, such as posting a comment, opening a pull request or fetching a URL.

The policy file is `~/.agentwall/policy.yaml`. To use another file, pass `--policy FILE` to `wrap` or `proxy`. If there is no policy file, agentwall uses the built-in policy, which tags tools of the github, filesystem, fetch and slack servers.

## Attack suite

The suite replays five attacks and four harmless runs through the real proxy and firewall:

```
SCENARIO                   KIND    RESULT
benign-issue-triage        benign  allowed
benign-private-coding      benign  allowed
benign-stable-tools        benign  allowed
benign-web-research        benign  allowed
fingerprint-cross-session  attack  blocked
github-heist               attack  blocked
rug-pull                   attack  blocked
secret-exfil-fetch         attack  blocked
zero-width-injection       attack  blocked

blocked 5/5 attacks, false positives 0/4
```

CI runs the suite on Linux, Windows and macOS.

## Benchmarks

| case | direct p50 | direct p99 | wrapped p50 | wrapped p99 | added p50 | added p99 |
|---|---|---|---|---|---|---|
| echo 1 KB | 15 µs | 58 µs | 80 µs | 287 µs | 65 µs | 229 µs |
| private read 1 KB | 13 µs | 42 µs | 80 µs | 258 µs | 67 µs | 216 µs |
| echo 10 KB | 48 µs | 202 µs | 296 µs | 693 µs | 248 µs | 490 µs |

Machine: Intel Core Ultra 7 255H, 16 cores, 31.4 GB RAM, Windows 11 Home 10.0.26200, go1.27.3 windows/amd64, 2026-11-16

```
target: added p99 < 2000 µs — met
```

Full method and in-process numbers: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

## Threat model

### What it is meant to stop

- An agent that has read untrusted content and then sends private data out through an egress tool, in one session or across MCP servers of one agent.
- Private text that is pasted into an egress call, including in a later session.
- Secrets appearing in tool output, and secrets sitting in the agent's config.
- A tool whose definition changed after you accepted it.
- Prompt-injection text in tool output. It marks the session untrusted, so the flow rules apply.
- Edits, deletions and reordering of entries inside the audit log chain (`agentwall verify` detects them).

### What it does not stop

- Fingerprints miss secrets shorter than 8 words, and text that was re-encoded (for example in base64).
- Vault values shorter than 8 characters are stored but not redacted.
- A vault secret is caught as written, percent-encoded, or inside base64 (for example a Basic auth header). Other encodings (hex, compression, a secret split across fields) are not.
- Without a keychain and without `AGENTWALL_PASSPHRASE`, `wrap` runs with pattern-only redaction. It prints a warning.
- The audit hash chain is not keyed. It detects edits, deletions and reordering inside a chain. It does not detect removal of the newest entries, or a forged whole chain.
- Server notifications and requests (logs, progress, elicitation, roots) are redacted but not tainted. Sampling requests are refused. Over HTTP a refused request gets no answer, so the server waits for one.
- A tool that the policy does not tag gets no flow control.
- Taint is shared between the MCP servers of one agent by the agent's process id (on Windows, agentwall looks past `cmd /c` and PowerShell wrappers). This has not yet been confirmed with a logged-in Claude Code session. If the servers still get different ids, set the same `AGENTWALL_SESSION` in each server's `env`.
- The injection heuristics are pattern matching. They can be evaded.
- The fingerprint rule blocks writing an edited private file back through an egress tool (for example, reading a file and then committing it with `create_or_update_file`). Set `on_fingerprint: ask` to be asked instead, or remove the `egress_sink` tag from that tool. This is on purpose: the firewall cannot tell your own repository from someone else's.
- Anyone with access to your user account can read `~/.agentwall`.

## How it compares

> This is the author's reading of other projects' public documentation when agentwall was started. Check their docs before relying on it.
>
> - **MCP gateways** (Docker MCP Gateway, Kong's MCP support, Obot, TrueFoundry) focus on routing, authentication and logging for many servers and teams. As far as we know they do not track where data came from or stop a session that has read both untrusted and private data from sending data out. If you need a team gateway, use one of them; agentwall can sit in front of a single server next to them.
> - **Small open-source guards** (for example guardbee and Interlock) cover parts of this problem. We have not compared them feature by feature and make no claim that agentwall is better.
> - **What agentwall adds** in one local binary: information-flow control, fingerprinting of private text, credential isolation, tool pinning, a tamper-evident log, and a public attack suite you can run yourself.
> - **What agentwall does not have:** a web dashboard, multi-user access control, a hosted service, an ML classifier, OPA/Cedar policies.

## Commands

| Command | What it does |
|---|---|
| `agentwall init` | Write the default policy and show how to wrap your Claude Code / Cursor servers |
| `agentwall wrap [--policy file] [--server name] -- <cmd> [args...]` | Run an MCP server behind the firewall (stdio) |
| `agentwall proxy --upstream URL [--listen addr] [--server name] [--policy file]` | Run the firewall in front of an HTTP MCP server |
| `agentwall secret set NAME` | Store a secret in the vault (the value is read from stdin) |
| `agentwall secret list` | List the names of the stored secrets |
| `agentwall approve <server>/<tool>` | Accept a changed tool |
| `agentwall verify` | Check the audit log hash chain |
| `agentwall log [--tail]` | Pretty-print the audit log; `--tail` keeps printing new entries |
| `agentwall attack` | Run the attack suite and print the score |

## Status

v0.1, early. The firewall and its tests run on Linux, Windows and macOS in CI. Two things are not yet verified: a real Claude Code session going through agentwall, and a real remote HTTP MCP server. The `ask` prompt has not been tested with a real agent UI.

State lives in `~/.agentwall/`:

- `policy.yaml`: the policy file written by `init`.
- `audit.jsonl`: the audit log.
- `pins/`: one file per server with the accepted tool hashes.
- `sessions/`, `fingerprints`: taint markers and fingerprints shared by the processes of one agent.
- `vault.enc`: the encrypted vault, only when the passphrase backend is used.

Environment variables:

- `AGENTWALL_HOME`: use another state directory instead of `~/.agentwall`.
- `AGENTWALL_PASSPHRASE`: store secrets in an AES-256-GCM file instead of the OS keychain. The key is derived from this passphrase with PBKDF2.
- `AGENTWALL_SESSION`: set the session id yourself instead of using the parent process id.

For the design, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). For the goals and the reasoning, see [docs/SPEC.md](docs/SPEC.md).

## License

MIT. See [LICENSE](LICENSE).
