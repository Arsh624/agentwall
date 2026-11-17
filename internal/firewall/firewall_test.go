package firewall

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/flow"
	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/pin"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/session"
)

const testPolicy = `
servers:
  srv:
    tools:
      blocked: {action: deny}
      careful: {action: ask}
      post:
        deny_args: {body: "(?i)password"}
`

func newFirewall(t *testing.T) (*Firewall, string) {
	t.Helper()
	p, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return open(t, dir, "srv", "s1", p), filepath.Join(dir, "audit.jsonl")
}

// open builds a firewall the way one agentwall process does: its own handles on the shared state dir.
func open(t *testing.T, stateDir, server, sessionID string, p *policy.Policy) *Firewall {
	t.Helper()
	log, err := audit.Open(filepath.Join(stateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.Open(stateDir, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	prints, err := flow.OpenStore(filepath.Join(stateDir, "fingerprints"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close(); prints.Close() })
	return &Firewall{Server: server, Session: sess, Policy: p, Audit: log, Prints: prints, Pins: pin.Open(filepath.Join(stateDir, "pins"))}
}

func toolCall(name, args string) *jsonrpc.Message {
	return &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"` + name + `","arguments":` + args + `}`)}
}

func lastEntry(t *testing.T, path string, wantCount int) audit.Entry {
	t.Helper()
	entries, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != wantCount {
		t.Fatalf("audit log has %d entries, want %d", len(entries), wantCount)
	}
	if _, err := audit.Verify(path); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
	return entries[len(entries)-1]
}

func TestToolCallsAreDecidedAndAudited(t *testing.T) {
	cases := []struct {
		name, tool, args string
		ask              func(string) bool
		deny             bool
		reasonHas        string
	}{
		{name: "unlisted tool is allowed", tool: "read", args: `{"path":"a"}`},
		{name: "denied tool", tool: "blocked", args: `{}`, deny: true, reasonHas: "denied by policy"},
		{name: "deny_args match", tool: "post", args: `{"body":"my PASSWORD is x"}`, deny: true, reasonHas: `"body"`},
		{name: "deny_args no match", tool: "post", args: `{"body":"hello"}`},
		{name: "ask without a terminal is denied", tool: "careful", args: `{}`, deny: true, reasonHas: "approval"},
		{name: "ask refused", tool: "careful", args: `{}`, ask: func(string) bool { return false }, deny: true, reasonHas: "approval"},
		{name: "ask approved", tool: "careful", args: `{}`, ask: func(string) bool { return true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, path := newFirewall(t)
			f.Ask = c.ask
			d := f.Hooks().OnRequest(toolCall(c.tool, c.args))
			if d.Deny != c.deny || !strings.Contains(d.Reason, c.reasonHas) {
				t.Fatalf("decision = %+v, want deny=%v with reason containing %q", d, c.deny, c.reasonHas)
			}
			e := lastEntry(t, path, 1)
			wantDecision := "allow"
			if c.deny {
				wantDecision = "deny"
			}
			if e.Decision != wantDecision || e.Server != "srv" || e.Tool != c.tool || e.Session != "s1" ||
				e.ArgsHash != audit.HashArgs([]byte(c.args)) || e.Reason != d.Reason {
				t.Fatalf("bad audit entry: %+v", e)
			}
		})
	}
}

func TestAskQuestionNamesTheTool(t *testing.T) {
	f, _ := newFirewall(t)
	var asked string
	f.Ask = func(q string) bool { asked = q; return true }
	f.Hooks().OnRequest(toolCall("careful", `{}`))
	if !strings.Contains(asked, "srv/careful") {
		t.Fatalf("question should name the tool, got %q", asked)
	}
}

func TestOtherMethodsPassUnaudited(t *testing.T) {
	f, path := newFirewall(t)
	for _, method := range []string{"initialize", "tools/list", "notifications/initialized"} {
		if d := f.Hooks().OnRequest(&jsonrpc.Message{JSONRPC: "2.0", Method: method}); d.Deny {
			t.Fatalf("%s must pass, got %+v", method, d)
		}
	}
	lastEntryCount(t, path, 0)
}

func TestMalformedToolCallIsDenied(t *testing.T) {
	for _, params := range []string{``, `"x"`, `{}`, `{"name":7}`} {
		f, _ := newFirewall(t)
		req := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: json.RawMessage(params)}
		if d := f.Hooks().OnRequest(req); !d.Deny {
			t.Fatalf("params %q must be denied", params)
		}
	}
}

func TestCallIsDeniedWhenItCannotBeAudited(t *testing.T) {
	f, _ := newFirewall(t)
	f.Audit.Close() // every later Append fails
	if d := f.Hooks().OnRequest(toolCall("read", `{}`)); !d.Deny || !strings.Contains(d.Reason, "audit") {
		t.Fatalf("an unauditable call must be denied, got %+v", d)
	}
}

func lastEntryCount(t *testing.T, path string, want int) {
	t.Helper()
	entries, err := audit.Read(path)
	if err != nil || len(entries) != want {
		t.Fatalf("audit log has %d entries (err=%v), want %d", len(entries), err, want)
	}
}
