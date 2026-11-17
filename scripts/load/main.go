// Command load measures the latency agentwall adds to an MCP tool call, end to end,
// with real processes over stdio pipes: each case is run directly against the mock
// server and again wrapped by agentwall, and the difference is the added latency.
//
//	go build -o "$TEMP/agentwall-bench.exe" ./cmd/agentwall
//	go run ./scripts/load -agentwall "$TEMP/agentwall-bench.exe"
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

var words = strings.Fields(`the quick river carried small boats past the old mill while farmers counted
their harvest and children watched geese cross a quiet field before winter arrived
and every house along the lane kept its lamp lit until morning brought fresh bread`)

// prose returns n bytes of deterministic English-like text.
func prose(n int) string {
	var sb strings.Builder
	x := uint32(1)
	for sb.Len() < n {
		x = x*1664525 + 1013904223
		sb.WriteString(words[(x>>16)%uint32(len(words))])
		sb.WriteByte(' ')
	}
	return sb.String()[:n]
}

type testCase struct {
	name, server, tool string
	args               map[string]any
}

func main() {
	bin := flag.String("agentwall", "", "path to a built agentwall binary (required)")
	n := flag.Int("n", 3000, "measured calls per case")
	warmup := flag.Int("warmup", 300, "warm-up calls per case, not measured")
	flag.Parse()
	if *bin == "" {
		fatal("-agentwall is required")
	}

	dir, err := os.MkdirTemp("", "agentwall-load-")
	check(err)
	defer os.RemoveAll(dir)
	scenario := filepath.Join(dir, "scenario.json")
	check(writeScenario(scenario))
	home := filepath.Join(dir, "home")

	cases := []testCase{
		{"echo 1 KB", "bench", "echo", map[string]any{"text": prose(1 << 10)}},
		{"private read 1 KB", "github", "get_file_contents", map[string]any{"path": "README.md"}},
		{"echo 10 KB", "bench", "echo", map[string]any{"text": prose(10 << 10)}},
	}
	fmt.Println("| case | direct p50 | direct p99 | wrapped p50 | wrapped p99 | added p50 | added p99 |")
	fmt.Println("|---|---|---|---|---|---|---|")
	var worst float64
	worstName := ""
	for _, c := range cases {
		direct := measure(c, *n, *warmup, home, *bin, "mock-server", scenario)
		wrapped := measure(c, *n, *warmup, home, *bin, "wrap", "--server", c.server, "--", *bin, "mock-server", scenario)
		d50, d99 := pct(direct, 0.50), pct(direct, 0.99)
		w50, w99 := pct(wrapped, 0.50), pct(wrapped, 0.99)
		fmt.Printf("| %s | %.0f µs | %.0f µs | %.0f µs | %.0f µs | %.0f µs | %.0f µs |\n", c.name, d50, d99, w50, w99, w50-d50, w99-d99)
		if added := w99 - d99; worstName == "" || added > worst {
			worst, worstName = added, c.name
		}
	}
	if worst < 2000 {
		fmt.Println("\ntarget: added p99 < 2000 µs — met")
	} else {
		fmt.Printf("\ntarget: added p99 < 2000 µs — NOT met (%s = %.0f µs)\n", worstName, worst)
	}
}

func writeScenario(path string) error {
	text, _ := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "text", "text": prose(1 << 10)}}})
	sc := map[string]any{
		"tools": []any{
			map[string]any{"name": "echo", "inputSchema": map[string]any{"type": "object"}},
			map[string]any{"name": "get_file_contents", "inputSchema": map[string]any{"type": "object"}},
		},
		"calls": map[string]any{"get_file_contents": json.RawMessage(text)},
	}
	b, _ := json.Marshal(sc)
	return os.WriteFile(path, b, 0o600)
}

// measure runs one server process and returns the round-trip time in microseconds of n tools/call requests.
func measure(c testCase, n, warmup int, home, bin string, args ...string) []float64 {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "AGENTWALL_HOME="+home, "AGENTWALL_SESSION=load")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	check(err)
	out, err := cmd.StdoutPipe()
	check(err)
	check(cmd.Start())
	replies := bufio.NewReaderSize(out, 64<<10)

	id := 0
	send := func(line string) {
		id++
		_, err := fmt.Fprintf(in, line+"\n", id)
		check(err)
	}
	read := func() {
		line, err := replies.ReadString('\n')
		check(err)
		if strings.Contains(line, `"error"`) {
			fatal("%s: got a JSON-RPC error, the numbers would be meaningless: %s", c.name, line)
		}
	}
	send(`{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"load","version":"0"}}}`)
	read()
	fmt.Fprintln(in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	params, _ := json.Marshal(map[string]any{"name": c.tool, "arguments": c.args})
	call := `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":` + strings.ReplaceAll(string(params), "%", "%%") + `}`
	samples := make([]float64, 0, n)
	for i := 0; i < warmup+n; i++ {
		start := micros()
		send(call)
		read()
		if i >= warmup {
			samples = append(samples, micros()-start)
		}
	}
	in.Close()
	check(cmd.Wait())
	return samples
}

// pct returns the p-th percentile (0..1) of samples: sorted, index ceil(p*n)-1.
func pct(samples []float64, p float64) float64 {
	s := slices.Clone(samples)
	slices.Sort(s)
	return s[int(math.Ceil(p*float64(len(s))))-1]
}

func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "load: "+format+"\n", a...)
	os.Exit(1)
}
