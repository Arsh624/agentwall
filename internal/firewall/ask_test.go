package firewall

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/policy"
)

func initialize(t *testing.T, f *Firewall, capabilities string) {
	t.Helper()
	req := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`0`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":` + capabilities + `,"clientInfo":{"name":"t","version":"1"}}`)}
	if d := f.Hooks().OnRequest(req); d.Deny || d.Ask != "" {
		t.Fatalf("initialize must pass: %+v", d)
	}
}

func TestAskGoesToTheAgentWhenItCanElicit(t *testing.T) {
	p, _ := policy.Parse([]byte(`servers: {srv: {tools: {push: {action: ask}}}}`))
	dir := t.TempDir()
	f := open(t, dir, "srv", "s1", p)
	f.Elicit = true
	initialize(t, f, `{"elicitation":{}}`)

	req := toolCall("push", `{"branch":"main"}`)
	d := f.Hooks().OnRequest(req)
	if d.Deny || !strings.Contains(d.Ask, "srv/push") {
		t.Fatalf("an ask rule must become a question for the agent: %+v", d)
	}
	if final := f.Hooks().OnAnswer(req, true, "approved by the user in the agent"); final.Deny {
		t.Fatalf("an approved call goes through: %+v", final)
	}
	if !auditHas(t, dir, "allow", "push", "approved by the user in the agent") {
		t.Fatal("the answer must be audited")
	}
	if final := f.Hooks().OnAnswer(req, false, "the user declined in the agent"); !final.Deny {
		t.Fatalf("a declined call is denied: %+v", final)
	}
	if !auditHas(t, dir, "deny", "push", "declined") {
		t.Fatal("the refusal must be audited")
	}
}

func TestAskFallsBackWithoutElicitation(t *testing.T) {
	p, _ := policy.Parse([]byte(`servers: {srv: {tools: {push: {action: ask}}}}`))
	for name, c := range map[string]struct {
		elicit bool
		caps   string
	}{
		"agent cannot elicit":     {true, `{}`},
		"transport cannot (HTTP)": {false, `{"elicitation":{}}`},
	} {
		t.Run(name, func(t *testing.T) {
			f := open(t, t.TempDir(), "srv", "s1", p)
			f.Elicit = c.elicit
			initialize(t, f, c.caps)
			// f.Ask is nil here, like a run with no terminal: the ask ends in a deny
			if d := f.Hooks().OnRequest(toolCall("push", `{}`)); d.Ask != "" || !d.Deny {
				t.Fatalf("want the terminal path (a deny without a terminal), got %+v", d)
			}
		})
	}
}
