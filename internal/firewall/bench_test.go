package firewall_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/firewall"
	"github.com/Arsh624/agentwall/internal/mockserver"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/proxy"
)

var words = strings.Fields(`the quick river carried small boats past the old mill while farmers counted
their harvest and children watched geese cross a quiet field before winter arrived
and every house along the lane kept its lamp lit until morning brought fresh bread`)

// prose returns n bytes of deterministic English-like text; different seeds give different text.
func prose(n, seed int) string {
	var sb strings.Builder
	x := uint32(seed)
	for sb.Len() < n {
		x = x*1664525 + 1013904223
		sb.WriteString(words[(x>>16)%uint32(len(words))])
		sb.WriteByte(' ')
	}
	return sb.String()[:n]
}

func textResult(s string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}})
	return b
}

func request(tool string, args map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args}})
	return append(b, '\n')
}

// connect starts a mock server (behind proxy.Run with hooks, unless hooks is nil)
// and returns a function that sends one request line and reads its reply line.
func connect(b *testing.B, sc *mockserver.Scenario, hooks *proxy.Hooks) func(req []byte) []byte {
	b.Helper()
	agentInR, agentInW := io.Pipe()
	agentOutR, agentOutW := io.Pipe()
	done := make(chan struct{})
	if hooks == nil {
		go func() { mockserver.Serve(agentInR, agentOutW, sc); agentOutW.Close(); close(done) }()
	} else {
		upInR, upInW := io.Pipe()
		upOutR, upOutW := io.Pipe()
		go func() { mockserver.Serve(upInR, upOutW, sc); upOutW.Close() }()
		go func() { proxy.Run(agentInR, agentOutW, upInW, upOutR, *hooks); close(done) }()
	}
	b.Cleanup(func() { agentInW.Close(); <-done })
	replies := bufio.NewReader(agentOutR)
	return func(req []byte) []byte {
		if _, err := agentInW.Write(req); err != nil {
			b.Fatal(err)
		}
		line, err := replies.ReadBytes('\n')
		if err != nil {
			b.Fatal(err)
		}
		if bytes.Contains(line, []byte(`"error"`)) {
			b.Fatalf("call failed: %s", line)
		}
		return line
	}
}

func loop(b *testing.B, call func([]byte) []byte, req []byte) {
	b.ReportAllocs()
	for b.Loop() {
		call(req)
	}
}

func echoScenario() *mockserver.Scenario { return &mockserver.Scenario{} }

func BenchmarkDirect(b *testing.B) {
	loop(b, connect(b, echoScenario(), nil), request("echo", map[string]any{"text": prose(1024, 1)}))
}

func BenchmarkProxyOnly(b *testing.B) {
	loop(b, connect(b, echoScenario(), &proxy.Hooks{}), request("echo", map[string]any{"text": prose(1024, 1)}))
}

func BenchmarkFirewall(b *testing.B) {
	// open returns a connection through the firewall for the given server name.
	open := func(b *testing.B, server string, sc *mockserver.Scenario) func([]byte) []byte {
		fw, err := firewall.Open(firewall.Config{StateDir: b.TempDir(), Server: server, Session: "bench", Policy: policy.Default()})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { fw.Close() }) // registered first, so it runs after the proxy has stopped
		return connect(b, sc, ptr(fw.Hooks()))
	}
	privateRead := func(size int) *mockserver.Scenario {
		return &mockserver.Scenario{Calls: map[string]json.RawMessage{"get_file_contents": textResult(prose(size, 2))}}
	}
	read := request("get_file_contents", map[string]any{"path": "README.md"})

	b.Run("untagged-1KB", func(b *testing.B) {
		loop(b, open(b, "bench", echoScenario()), request("echo", map[string]any{"text": prose(1024, 1)}))
	})
	for _, size := range []int{1 << 10, 10 << 10} {
		b.Run(fmt.Sprintf("private-%dKB", size>>10), func(b *testing.B) {
			loop(b, open(b, "github", privateRead(size)), read)
		})
	}
	b.Run("egress-1KB", func(b *testing.B) {
		call := open(b, "github", privateRead(1024))
		call(read) // puts fingerprints in the store and taints the session
		loop(b, call, request("create_pull_request", map[string]any{"title": "t", "body": prose(1024, 3)}))
	})
}

func ptr[T any](v T) *T { return &v }
