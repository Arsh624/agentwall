package proxy

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

// harness runs the proxy between an in-memory "agent" and "upstream" the test controls.
type harness struct {
	t          *testing.T
	agentW     *jsonrpc.Writer // agent → proxy
	agentR     *jsonrpc.Reader // proxy → agent
	upR        *jsonrpc.Reader // proxy → upstream
	upW        *jsonrpc.Writer // upstream → proxy
	agentInRaw io.WriteCloser
	upOutRaw   io.WriteCloser
	upInRaw    io.Reader
	done       chan error
}

func start(t *testing.T, h Hooks) *harness {
	agentInR, agentInW := io.Pipe()
	agentOutR, agentOutW := io.Pipe()
	upInR, upInW := io.Pipe()
	upOutR, upOutW := io.Pipe()
	hn := &harness{
		t: t, done: make(chan error, 1),
		agentW: jsonrpc.NewWriter(agentInW), agentR: jsonrpc.NewReader(agentOutR),
		upR: jsonrpc.NewReader(upInR), upW: jsonrpc.NewWriter(upOutW),
		agentInRaw: agentInW, upOutRaw: upOutW, upInRaw: upInR,
	}
	go func() { hn.done <- Run(agentInR, agentOutW, upInW, upOutR, h) }()
	return hn
}

func msg(s string) *jsonrpc.Message {
	var m jsonrpc.Message
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		panic(err)
	}
	return &m
}

// read fails the test instead of hanging when the proxy never delivers a frame.
func (hn *harness) read(r *jsonrpc.Reader) *jsonrpc.Message {
	hn.t.Helper()
	type res struct {
		m   *jsonrpc.Message
		err error
	}
	c := make(chan res, 1)
	go func() { m, err := r.Read(); c <- res{m, err} }()
	select {
	case x := <-c:
		if x.err != nil {
			hn.t.Fatalf("read: %v", x.err)
		}
		return x.m
	case <-time.After(5 * time.Second):
		hn.t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func TestTransparentBothWays(t *testing.T) {
	hn := start(t, Hooks{})

	// agent request → upstream, response → agent
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`))
	if m := hn.read(hn.upR); m.Method != "tools/call" || string(m.ID) != "1" || string(m.Params) != `{"name":"x"}` {
		t.Fatalf("upstream got %+v", m)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	if m := hn.read(hn.agentR); string(m.ID) != "1" || string(m.Result) != `{"ok":true}` {
		t.Fatalf("agent got %+v", m)
	}

	// agent notification → upstream
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if m := hn.read(hn.upR); m.Method != "notifications/initialized" {
		t.Fatalf("upstream got %+v", m)
	}

	// server-initiated request → agent, agent's response → upstream
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":"s1","method":"roots/list"}`))
	if m := hn.read(hn.agentR); m.Method != "roots/list" || string(m.ID) != `"s1"` {
		t.Fatalf("agent got %+v", m)
	}
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":"s1","result":{"roots":[]}}`))
	if m := hn.read(hn.upR); !m.IsResponse() || string(m.ID) != `"s1"` {
		t.Fatalf("upstream got %+v", m)
	}

	// server notification → agent
	hn.upW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
	if m := hn.read(hn.agentR); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("agent got %+v", m)
	}
}

func TestResponsesAreMatchedToTheirRequests(t *testing.T) {
	type pair struct{ tool, result string }
	seen := make(chan pair, 3)
	hn := start(t, Hooks{OnResponse: func(req, resp *jsonrpc.Message) *jsonrpc.Message {
		seen <- pair{string(req.Params), string(resp.Result)}
		return resp
	}})
	for _, id := range []string{"1", "2", "3"} {
		hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":"tool` + id + `"}`))
		hn.read(hn.upR)
	}
	for _, id := range []string{"3", "1", "2"} { // upstream answers out of order
		hn.upW.Write(msg(`{"jsonrpc":"2.0","id":` + id + `,"result":"result` + id + `"}`))
		if m := hn.read(hn.agentR); string(m.ID) != id {
			t.Fatalf("agent got id %s, want %s", m.ID, id)
		}
		p := <-seen
		if p.tool != `"tool`+id+`"` || p.result != `"result`+id+`"` {
			t.Fatalf("id %s: hook saw request %s with result %s", id, p.tool, p.result)
		}
	}
}

func TestDeniedRequestNeverReachesUpstream(t *testing.T) {
	hn := start(t, Hooks{OnRequest: func(req *jsonrpc.Message) Decision {
		if strings.Contains(req.Method+string(req.Params), "evil") {
			return Decision{Deny: true, Reason: "evil tool"}
		}
		return Decision{}
	}})
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"evil"}}`))
	m := hn.read(hn.agentR)
	if string(m.ID) != "1" || m.Error == nil || m.Error.Code != CodeBlocked || !strings.Contains(m.Error.Message, "evil tool") {
		t.Fatalf("agent should get a blocked error with the reason, got %+v", m)
	}
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/evil"}`)) // denied notification: dropped silently
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"good"}}`))
	if m := hn.read(hn.upR); string(m.ID) != "2" {
		t.Fatalf("first frame upstream sees must be the allowed call, got %+v", m)
	}
}

func TestOnResponseCanRewrite(t *testing.T) {
	hn := start(t, Hooks{OnResponse: func(req, resp *jsonrpc.Message) *jsonrpc.Message {
		resp.Result = json.RawMessage(`"[REDACTED]"`)
		return resp
	}})
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	hn.read(hn.upR)
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":1,"result":"secret"}`))
	if m := hn.read(hn.agentR); string(m.Result) != `"[REDACTED]"` {
		t.Fatalf("agent got %s", m.Result)
	}
}

func TestBadFrames(t *testing.T) {
	hn := start(t, Hooks{OnResponse: func(req, resp *jsonrpc.Message) *jsonrpc.Message {
		if req == nil {
			t.Error("OnResponse called without a request")
		}
		return resp
	}})

	// agent sends garbage: it gets a parse error back, upstream sees nothing
	io.WriteString(hn.agentInRaw, "garbage\n")
	if m := hn.read(hn.agentR); m.Error == nil || m.Error.Code != jsonrpc.CodeParseError {
		t.Fatalf("agent should get a parse error, got %+v", m)
	}

	// upstream sends garbage and a response nobody asked for: both dropped
	io.WriteString(hn.upOutRaw, "log line on stdout\n")
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":99,"result":"unsolicited"}`))

	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if m := hn.read(hn.upR); m.Method != "ping" {
		t.Fatalf("upstream got %+v", m)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if m := hn.read(hn.agentR); string(m.ID) != "1" {
		t.Fatalf("agent should only see the answer to its own request, got %+v", m)
	}
}

func TestShutdown(t *testing.T) {
	hn := start(t, Hooks{})
	hn.agentInRaw.Close() // agent goes away → proxy closes upstream stdin
	if _, err := io.ReadAll(hn.upInRaw); err != nil {
		t.Fatalf("upstream stdin should reach EOF: %v", err)
	}
	hn.upOutRaw.Close() // upstream exits → Run returns
	select {
	case err := <-hn.done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}
