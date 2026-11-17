# Benchmarks

agentwall promises "< 2 ms p99 added latency per call on a laptop". This page says how that is measured and what the numbers were.

## What is measured

- **End to end, real processes** (`scripts/load`): an agent stand-in starts a server process, sends one `tools/call` at a time over stdin/stdout pipes, and times each request-to-reply round trip. Each case runs twice: `direct` (the mock server alone) and `wrapped` (`agentwall wrap` in front of the same mock server). **Added latency = wrapped minus direct**, for p50 and p99 separately. Each case does 300 warm-up calls, then 3000 measured calls.
- **In process** (`go test -bench`): the same round trip over `io.Pipe`, with no process or OS-pipe cost, so you can see where the firewall's time goes. Overhead is `BenchmarkFirewall/<case>` minus `BenchmarkDirect`.

Not measured: concurrent calls, HTTP mode, first-call startup cost (process start, opening the audit log and state files; the warm-up calls are discarded).

## How to reproduce

```
go build -o "$TEMP/agentwall-bench.exe" ./cmd/agentwall
go run ./scripts/load -agentwall "$TEMP/agentwall-bench.exe"
go test -run xxx -bench . -benchmem ./internal/firewall/ ./internal/detect/
```

The load script uses a temporary state directory and session, so it does not touch `~/.agentwall`. The mock server is the hidden command `agentwall mock-server <scenario.json>`.

## The machine

- CPU: Intel Core Ultra 7 255H, 16 cores / 16 threads
- RAM: 31.4 GB
- OS: Windows 11 Home 10.0.26200
- Go: go1.27.3 windows/amd64
- Date: 2026-11-16

## Results

Load script, default `-n 3000`, run twice; this is the run with the worse added p99 (the other run had 199 / 226 / 439 µs added p99 for the three cases).

| case | direct p50 | direct p99 | wrapped p50 | wrapped p99 | added p50 | added p99 |
|---|---|---|---|---|---|---|
| echo 1 KB | 15 µs | 58 µs | 80 µs | 287 µs | 65 µs | 229 µs |
| private read 1 KB | 13 µs | 42 µs | 80 µs | 258 µs | 67 µs | 216 µs |
| echo 10 KB | 48 µs | 202 µs | 296 µs | 693 µs | 248 µs | 490 µs |

```
target: added p99 < 2000 µs — met
```

`go test -run xxx -bench . -benchmem ./internal/firewall/ ./internal/detect/`:

```
BenchmarkDirect-16       	  139473	      8551 ns/op	    8044 B/op	      22 allocs/op
BenchmarkProxyOnly-16    	   71542	     17458 ns/op	   13014 B/op	      32 allocs/op
BenchmarkFirewall/untagged-1KB-16         	   17829	     66847 ns/op	   31526 B/op	     112 allocs/op
BenchmarkFirewall/private-1KB-16          	   17812	     67501 ns/op	   25306 B/op	     128 allocs/op
BenchmarkFirewall/private-10KB-16         	    4122	    327220 ns/op	  188052 B/op	     142 allocs/op
BenchmarkFirewall/egress-1KB-16           	   12470	     95159 ns/op	   37833 B/op	     137 allocs/op
BenchmarkScore-16          	   15250	     81599 ns/op	 126.01 MB/s	   33411 B/op	      85 allocs/op
BenchmarkScoreBenign-16    	   15508	     76137 ns/op	 138.96 MB/s	   25284 B/op	      21 allocs/op
```

## Reading the numbers

The 2 ms target is met in all three cases on this machine: about 0.2 ms added at p99 for 1 KB payloads and about 0.5 ms for 10 KB.

Cost grows with payload size, not with the policy tag. A 1 KB call adds about 65 µs at p50 whether or not the tool is tagged; a 10 KB payload adds about 250 µs. Every result is decoded, scanned for secrets, scanned for injection text, and, for `private_source` tools, fingerprinted. The proxy itself (parse, match the id, re-encode) costs about 9 µs per call (`BenchmarkProxyOnly` minus `BenchmarkDirect`); `egress-1KB` is the slowest 1 KB case in process because it also checks the arguments against the fingerprint store.

An earlier version of this page measured 1.1 to 1.4 ms added p99 for the 10 KB case. A CPU profile showed about half the time in the secret-redaction regular expressions, which ran over every string. They now run only on strings that contain a literal part of a token format (found with a fast substring search), which cut the 10 KB case to the figures above. The injection heuristics got the same treatment earlier (1.8 ms to about 80 µs per 10 KB).

Caveats:

- The same text is returned on every private read, so the fingerprint store stops growing after the first call. A real server returning new files adds entries over time; that growth is not measured.
- A result that does contain token-like text pays for the regular expressions again. That path is not in the table.
- The in-process numbers move between runs on this machine. Treat differences under about 2x as noise.
- p99 on Windows includes process scheduling noise: the direct baseline alone has a p99 several times its p50, and the two load runs differed by up to about 50 µs at p99 for the same case.
- The load script reads the Windows performance counter, because Go's normal clock ticks only about every 0.5 ms on Windows, too coarse for these round trips.
- The mock server replies instantly. A real MCP server's own latency is not part of the added figure.
