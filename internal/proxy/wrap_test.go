package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentwall/agentwall/internal/jsonrpc"
	"github.com/agentwall/agentwall/internal/mockserver"
)

func TestMain(m *testing.M) {
	mockserver.RunIfChild() // the wrapped "upstream" is this test binary re-executed
	os.Exit(m.Run())
}

// wrapMock runs Wrap around a real mock-server subprocess and returns the agent's ends.
func wrapMock(t *testing.T) (w *jsonrpc.Writer, r *jsonrpc.Reader, stop func()) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	env := append(os.Environ(), mockserver.EnvScenario+"=../../testdata/basic.json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	done := make(chan error, 1)
	go func() { done <- Wrap(ctx, []string{os.Args[0]}, env, inR, outW, Hooks{}) }()
	return jsonrpc.NewWriter(inW), jsonrpc.NewReader(outR), func() {
		t.Helper()
		defer cancel()
		inW.Close() // agent exits → upstream sees EOF and exits → Wrap returns
		if err := <-done; err != nil {
			t.Fatalf("Wrap: %v", err)
		}
	}
}

func call(id int, tool, args string) *jsonrpc.Message {
	return msg(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args))
}

func resultText(t *testing.T, m *jsonrpc.Message) string {
	t.Helper()
	var res struct{ Content []struct{ Text string } }
	if err := json.Unmarshal(m.Result, &res); err != nil || len(res.Content) != 1 {
		t.Fatalf("bad tool result %.200s (err=%v, rpc error=%+v)", m.Result, err, m.Error)
	}
	return res.Content[0].Text
}

func TestWrapRoundTrip(t *testing.T) {
	w, r, stop := wrapMock(t)
	defer stop()

	w.Write(msg(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	m, err := r.Read()
	if err != nil || !strings.Contains(string(m.Result), `"mockserver"`) {
		t.Fatalf("initialize: %+v, %v", m, err)
	}
	w.Write(msg(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	w.Write(msg(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if m, err = r.Read(); err != nil || !strings.Contains(string(m.Result), `"read_file"`) {
		t.Fatalf("tools/list: %+v, %v", m, err)
	}
	w.Write(call(3, "read_file", `{"path":"a.txt"}`))
	if m, err = r.Read(); err != nil || resultText(t, m) != "hello from disk" {
		t.Fatalf("tools/call: %+v, %v", m, err)
	}
}

func TestWrapLargePayload(t *testing.T) {
	w, r, stop := wrapMock(t)
	defer stop()

	big := strings.Repeat("x", 5<<20)
	go w.Write(call(1, "echo", `{"text":"`+big+`"}`)) // both directions carry 5 MB
	m, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got := resultText(t, m); got != `{"text":"`+big+`"}` {
		t.Fatalf("large payload changed in transit: got %d bytes", len(got))
	}
}

func TestWrapConcurrentIDs(t *testing.T) {
	w, r, stop := wrapMock(t)
	defer stop()

	const n = 200
	for i := 0; i < n; i++ {
		go w.Write(call(i+1, "echo", fmt.Sprintf(`{"n":%d}`, i+1)))
	}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		m, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		id := string(m.ID)
		if seen[id] {
			t.Fatalf("id %s answered twice", id)
		}
		seen[id] = true
		if got, want := resultText(t, m), `{"n":`+id+`}`; got != want {
			t.Fatalf("id %s got someone else's answer: %s", id, got)
		}
	}
}
