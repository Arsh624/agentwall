package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestReadClassifiesFrames(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}` + "\n" +
		"\n" + // blank lines are skipped
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\r\n" + // CRLF from Windows servers
		`{"jsonrpc":"2.0","id":"a","result":{"ok":true}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}}` // no trailing newline
	r := NewReader(strings.NewReader(in))

	m := mustRead(t, r)
	if !m.IsRequest() || m.IsNotification() || m.IsResponse() {
		t.Fatalf("frame 1 should be a request: %+v", m)
	}
	if m.Method != "tools/call" || string(m.ID) != "1" || string(m.Params) != `{"name":"x"}` {
		t.Fatalf("frame 1 fields wrong: %+v", m)
	}

	m = mustRead(t, r)
	if !m.IsNotification() || m.IsRequest() || m.IsResponse() {
		t.Fatalf("frame 2 should be a notification: %+v", m)
	}

	m = mustRead(t, r)
	if !m.IsResponse() || m.IsRequest() || string(m.ID) != `"a"` || string(m.Result) != `{"ok":true}` {
		t.Fatalf("frame 3 should be a result response: %+v", m)
	}

	m = mustRead(t, r)
	if !m.IsResponse() || m.Error == nil || m.Error.Code != -32601 || m.Error.Message != "nope" {
		t.Fatalf("frame 4 should be an error response: %+v", m)
	}

	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("want io.EOF at end, got %v", err)
	}
}

func TestReadNullResultIsAResponse(t *testing.T) {
	m := mustRead(t, NewReader(strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":null}`+"\n")))
	if !m.IsResponse() {
		t.Fatalf("null result must still be a response: %+v", m)
	}
}

func TestReadRejectsBadFramesAndContinues(t *testing.T) {
	bad := []string{
		`not json`,
		`[{"jsonrpc":"2.0","id":1,"method":"x"}]`, // batches are not supported
		`{}`,                                    // no method, result or error
		`{"jsonrpc":"1.0","id":1,"method":"x"}`, // wrong version
		`{"jsonrpc":"2.0","id":1}`,              // id only
	}
	for _, line := range bad {
		r := NewReader(strings.NewReader(line + "\n" + `{"jsonrpc":"2.0","method":"ok"}` + "\n"))
		_, err := r.Read()
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Fatalf("%s: want *ParseError, got %v", line, err)
		}
		if m := mustRead(t, r); m.Method != "ok" {
			t.Fatalf("%s: reader did not recover, got %+v", line, m)
		}
	}
}

func TestReadLargeFrame(t *testing.T) {
	big := strings.Repeat("x", 5<<20) // well past any bufio default
	in := `{"jsonrpc":"2.0","id":1,"result":{"text":"` + big + `"}}` + "\n"
	m := mustRead(t, NewReader(strings.NewReader(in)))
	if len(m.Result) < 5<<20 {
		t.Fatalf("large frame truncated: %d bytes", len(m.Result))
	}
}

func TestWriteRoundTrip(t *testing.T) {
	// Params are pretty-printed on purpose: the writer must still emit exactly one line.
	in := &Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage("{\n  \"html\": \"<b>&</b>\"\n}")}
	var buf bytes.Buffer
	if err := NewWriter(&buf).Write(in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("want exactly one newline-terminated line, got %q", out)
	}
	if !strings.Contains(out, `<b>&</b>`) {
		t.Fatalf("payload bytes must not be HTML-escaped: %q", out)
	}
	m := mustRead(t, NewReader(&buf))
	if m.Method != "tools/call" || string(m.ID) != "1" || string(m.Params) != `{"html":"<b>&</b>"}` {
		t.Fatalf("round trip changed the message: %+v", m)
	}
}

func TestWriteIsSafeForConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Write(&Message{JSONRPC: "2.0", Method: "n", Params: json.RawMessage(`{"pad":"` + strings.Repeat("y", 4096) + `"}`)})
		}()
	}
	wg.Wait()
	r := NewReader(&buf)
	for i := 0; i < 50; i++ {
		mustRead(t, r) // an interleaved write would fail to parse
	}
}

func TestErrorResponse(t *testing.T) {
	m := ErrorResponse(json.RawMessage(`"abc"`), -32001, "blocked")
	if !m.IsResponse() || string(m.ID) != `"abc"` || m.Error.Code != -32001 || m.Error.Message != "blocked" {
		t.Fatalf("bad error response: %+v", m)
	}
	var buf bytes.Buffer
	NewWriter(&buf).Write(ErrorResponse(nil, CodeParseError, "bad"))
	if !strings.Contains(buf.String(), `"id":null`) {
		t.Fatalf("missing id must be written as null: %s", buf.String())
	}
}

func mustRead(t *testing.T, r *Reader) *Message {
	t.Helper()
	m, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return m
}
