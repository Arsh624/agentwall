package firewall

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/policy"
)

// meta2026 is what Claude Code 2.1.327 puts on every request (MCP 2026-07-28: no initialize).
const meta2026 = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}},"progressToken":3}`

func call2026(id, args, extra string) *jsonrpc.Message {
	return &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(id), Method: "tools/call",
		Params: json.RawMessage(`{"name":"push","arguments":` + args + extra + `,` + meta2026 + `}`)}
}

type inputRequired struct {
	ResultType    string `json:"resultType"`
	RequestState  string `json:"requestState"`
	InputRequests map[string]struct {
		Method string `json:"method"`
		Params struct {
			Mode            string `json:"mode"`
			Message         string `json:"message"`
			RequestedSchema struct {
				Properties map[string]struct{ Type string }
			} `json:"requestedSchema"`
		} `json:"params"`
	} `json:"inputRequests"`
}

func askPolicy(t *testing.T) *policy.Policy {
	p, err := policy.Parse([]byte(`servers: {srv: {tools: {push: {action: ask}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// first asks and returns the input_required reply's requestState.
func first(t *testing.T, f *Firewall, args string) string {
	t.Helper()
	d := f.Hooks().OnRequest(call2026("1", args, ""))
	var r inputRequired
	if d.Deny || d.Result == nil || json.Unmarshal(d.Result, &r) != nil || r.ResultType != "input_required" || r.RequestState == "" {
		t.Fatalf("a 2026 client must get an input_required reply: %+v %s", d, d.Result)
	}
	q := r.InputRequests[approvalKey]
	if q.Method != "elicitation/create" || q.Params.Mode != "form" || !strings.Contains(q.Params.Message, "srv/push") ||
		q.Params.RequestedSchema.Properties["allow"].Type != "boolean" {
		t.Fatalf("the question must be a form asking for one boolean: %s", d.Result)
	}
	return r.RequestState
}

func retry(state, action string, allow bool) string {
	b, _ := json.Marshal(map[string]any{approvalKey: map[string]any{"action": action, "content": map[string]any{"allow": allow}}})
	s, _ := json.Marshal(state)
	return `,"inputResponses":` + string(b) + `,"requestState":` + string(s)
}

func TestAskThroughInputRequired(t *testing.T) {
	dir := t.TempDir()
	f := open(t, dir, "srv", "s1", askPolicy(t))
	f.Elicit = true
	state := first(t, f, `{"branch":"main"}`)

	// the client retries with a new id and the user's yes: the call goes upstream without our fields
	req := call2026("2", `{"branch":"main"}`, retry(state, "accept", true))
	if d := f.Hooks().OnRequest(req); d.Deny || d.Result != nil || d.Ask != "" {
		t.Fatalf("an approved retry is forwarded: %+v", d)
	}
	if p := string(req.Params); strings.Contains(p, approvalKey) || strings.Contains(p, "requestState") || !strings.Contains(p, "progressToken") {
		t.Fatalf("upstream must get the call without agentwall's answer, _meta kept: %s", p)
	}
	if !auditHas(t, dir, "allow", "push", "approved by the user in the agent") {
		t.Fatal("the approval must be audited")
	}

	for name, c := range map[string]struct{ args, extra, reason string }{
		"declined":             {`{"branch":"main"}`, retry(state, "decline", false), "declined"},
		"answered no":          {`{"branch":"main"}`, retry(state, "accept", false), "answered no"},
		"other arguments":      {`{"branch":"prod"}`, retry(state, "accept", true), "does not match"},
		"forged state":         {`{"branch":"main"}`, retry(state[:len(state)-4]+"AAAA", "accept", true), "does not match"},
		"approval without ask": {`{"branch":"main"}`, retry("x", "accept", true), "does not match"},
	} {
		if d := f.Hooks().OnRequest(call2026("3", c.args, c.extra)); !d.Deny || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s: want a deny mentioning %q, got %+v", name, c.reason, d)
		}
	}
}

func TestInputRequiredApprovalExpires(t *testing.T) {
	f := open(t, t.TempDir(), "srv", "s1", askPolicy(t))
	f.Elicit = true
	defer func(d time.Duration) { approvalTTL = d }(approvalTTL)
	approvalTTL = -time.Second // already expired when it is answered
	state := first(t, f, `{}`)
	if d := f.Hooks().OnRequest(call2026("2", `{}`, retry(state, "accept", true))); !d.Deny || !strings.Contains(d.Reason, "expired") {
		t.Fatalf("an old approval must not count: %+v", d)
	}
}

// Without elicitation in the request's capabilities, no input_required: the terminal path.
func TestInputRequiredNeedsTheCapability(t *testing.T) {
	f := open(t, t.TempDir(), "srv", "s1", askPolicy(t))
	f.Elicit = true
	req := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"push","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`)}
	if d := f.Hooks().OnRequest(req); d.Result != nil || !d.Deny {
		t.Fatalf("want the terminal path (a deny without a terminal), got %+v", d)
	}
}
