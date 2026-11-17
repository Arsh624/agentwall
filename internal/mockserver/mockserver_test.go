package mockserver

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

func TestServe(t *testing.T) {
	sc, err := Load("../../testdata/basic.json")
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // no reply expected
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a.txt"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := Serve(strings.NewReader(in), &out, sc); err != nil {
		t.Fatal(err)
	}
	r := jsonrpc.NewReader(&out)
	next := func(wantID string) *jsonrpc.Message {
		t.Helper()
		m, err := r.Read()
		if err != nil {
			t.Fatalf("reply %s: %v", wantID, err)
		}
		if string(m.ID) != wantID {
			t.Fatalf("got reply id %s, want %s", m.ID, wantID)
		}
		return m
	}

	var init struct {
		ProtocolVersion string
		ServerInfo      struct{ Name string }
	}
	json.Unmarshal(next("1").Result, &init)
	if init.ProtocolVersion != "2025-06-18" || init.ServerInfo.Name != "mockserver" {
		t.Fatalf("bad initialize result: %+v", init)
	}

	var list struct{ Tools []struct{ Name string } }
	json.Unmarshal(next("2").Result, &list)
	if len(list.Tools) != 2 || list.Tools[0].Name != "read_file" {
		t.Fatalf("bad tools/list result: %+v", list)
	}

	if got := text(t, next("3")); got != "hello from disk" {
		t.Fatalf("scripted call returned %q", got)
	}
	if got := text(t, next("4")); got != `{"text":"hi"}` {
		t.Fatalf("unscripted call should echo its arguments, got %q", got)
	}
	if m := next("5"); m.Error == nil || m.Error.Code != -32601 {
		t.Fatalf("unknown method should be -32601, got %+v", m)
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("want exactly 5 replies, got extra (err=%v)", err)
	}
}

func text(t *testing.T, m *jsonrpc.Message) string {
	t.Helper()
	var res struct{ Content []struct{ Text string } }
	if err := json.Unmarshal(m.Result, &res); err != nil || len(res.Content) != 1 {
		t.Fatalf("bad tool result %s (err=%v)", m.Result, err)
	}
	return res.Content[0].Text
}

func TestToolsAfter(t *testing.T) {
	sc, err := Load("../../testdata/rugpull.json")
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Repeat(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", 3)
	var out bytes.Buffer
	if err := Serve(strings.NewReader(in), &out, sc); err != nil {
		t.Fatal(err)
	}
	r := jsonrpc.NewReader(&out)
	var descs []string
	for range 3 {
		m, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		var list struct {
			Tools []struct{ Name, Description string }
		}
		json.Unmarshal(m.Result, &list)
		if len(list.Tools) != 2 {
			t.Fatalf("bad tools/list result: %s", m.Result)
		}
		descs = append(descs, list.Tools[1].Description)
	}
	if descs[0] != "Add two numbers" || descs[1] == descs[0] || descs[2] != descs[1] {
		t.Fatalf("want original then changed description twice, got %q", descs)
	}
}

func TestPrintenvTool(t *testing.T) {
	t.Setenv("MOCK_SECRET", "s3cr3t")
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"printenv","arguments":{"name":"MOCK_SECRET"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"printenv","arguments":{"name":"MOCK_UNSET"}}}` + "\n"
	var out bytes.Buffer
	if err := Serve(strings.NewReader(in), &out, &Scenario{}); err != nil {
		t.Fatal(err)
	}
	r := jsonrpc.NewReader(&out)
	first, _ := r.Read()
	second, _ := r.Read()
	if text(t, first) != "s3cr3t" || text(t, second) != "" {
		t.Fatalf("printenv returned %q and %q", text(t, first), text(t, second))
	}
}
