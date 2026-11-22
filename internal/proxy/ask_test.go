package proxy

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

type answers struct {
	mu  sync.Mutex
	got []string // "approved: why" per OnAnswer call
}

func (a *answers) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.got...)
}

// askHooks asks about every tools/call named "risky" and records each outcome.
func askHooks(a *answers, veto bool) Hooks {
	return Hooks{
		OnRequest: func(req *jsonrpc.Message) Decision {
			if strings.Contains(string(req.Params), "risky") {
				return Decision{Ask: "allow srv/risky?", Reason: "tool needs approval"}
			}
			return Decision{}
		},
		OnAnswer: func(req *jsonrpc.Message, approved bool, why string) Decision {
			a.mu.Lock()
			a.got = append(a.got, map[bool]string{true: "yes", false: "no"}[approved]+": "+why)
			a.mu.Unlock()
			if !approved || veto {
				return Decision{Deny: true, Reason: why}
			}
			return Decision{}
		},
	}
}

const riskyCall = `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"risky"}}`

func (hn *harness) question() *jsonrpc.Message {
	hn.t.Helper()
	q := hn.read(hn.agentR)
	if q.Method != "elicitation/create" || !strings.HasPrefix(string(q.ID), `"agentwall-`) || !strings.Contains(string(q.Params), "allow srv/risky?") {
		hn.t.Fatalf("want an elicitation question, got %+v", q)
	}
	var p struct {
		RequestedSchema struct {
			Properties map[string]struct{ Type string }
			Required   []string
		}
	}
	json.Unmarshal(q.Params, &p)
	if p.RequestedSchema.Properties["allow"].Type != "boolean" || len(p.RequestedSchema.Required) != 1 {
		hn.t.Fatalf("the question must ask for one boolean: %s", q.Params)
	}
	return q
}

func answer(q *jsonrpc.Message, result string) *jsonrpc.Message {
	return msg(`{"jsonrpc":"2.0","id":` + string(q.ID) + `,"result":` + result + `}`)
}

func TestAskApprovedInTheAgent(t *testing.T) {
	var a answers
	hn := start(t, askHooks(&a, false))
	hn.agentW.Write(msg(riskyCall))
	q := hn.question()

	// the agent keeps working while the question is open
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"safe"}}`))
	if m := hn.read(hn.upR); string(m.ID) != "6" {
		t.Fatalf("other calls must not wait for the question, upstream got %+v", m)
	}

	hn.agentW.Write(answer(q, `{"action":"accept","content":{"allow":true}}`))
	if m := hn.read(hn.upR); string(m.ID) != "5" {
		t.Fatalf("an approved call goes upstream, got %+v", m)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":5,"result":"done"}`))
	if m := hn.read(hn.agentR); string(m.ID) != "5" || string(m.Result) != `"done"` {
		t.Fatalf("the server's answer reaches the agent, got %+v", m)
	}
	if got := a.list(); len(got) != 1 || !strings.HasPrefix(got[0], "yes") {
		t.Fatalf("OnAnswer: %v", got)
	}
}

func TestAskDeclinedOrVetoed(t *testing.T) {
	for _, c := range []struct {
		name, result string
		veto         bool
	}{
		{"declined", `{"action":"decline"}`, false},
		{"cancelled in the agent", `{"action":"cancel"}`, false},
		{"accepted with allow false", `{"action":"accept","content":{"allow":false}}`, false},
		{"approved but the firewall vetoes", `{"action":"accept","content":{"allow":true}}`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var a answers
			hn := start(t, askHooks(&a, c.veto))
			hn.agentW.Write(msg(riskyCall))
			hn.agentW.Write(answer(hn.question(), c.result))
			if m := hn.read(hn.agentR); string(m.ID) != "5" || m.Error == nil || m.Error.Code != CodeBlocked {
				t.Fatalf("want a blocked error for call 5, got %+v", m)
			}
			hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"safe"}}`))
			if m := hn.read(hn.upR); string(m.ID) != "7" {
				t.Fatalf("the refused call must never reach upstream, got %+v", m)
			}
		})
	}
}

func TestAskTimesOutAndLateAnswerIsDropped(t *testing.T) {
	defer func(d time.Duration) { askTimeout = d }(askTimeout)
	askTimeout = 50 * time.Millisecond
	var a answers
	hn := start(t, askHooks(&a, false))
	hn.agentW.Write(msg(riskyCall))
	q := hn.question()
	if m := hn.read(hn.agentR); string(m.ID) != "5" || m.Error == nil {
		t.Fatalf("no answer in time: want a blocked error, got %+v", m)
	}
	hn.agentW.Write(answer(q, `{"action":"accept","content":{"allow":true}}`)) // too late
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"safe"}}`))
	if m := hn.read(hn.upR); string(m.ID) != "7" {
		t.Fatalf("a late approval must not forward the call (nor the answer), upstream got %+v", m)
	}
	if got := a.list(); len(got) != 1 || !strings.Contains(got[0], "no answer") {
		t.Fatalf("exactly one outcome, the timeout: %v", got)
	}
}

func TestAskCancelledByTheAgent(t *testing.T) {
	var a answers
	hn := start(t, askHooks(&a, false))
	hn.agentW.Write(msg(riskyCall))
	q := hn.question()
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}`))
	hn.agentW.Write(answer(q, `{"action":"accept","content":{"allow":true}}`))
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"safe"}}`))
	if m := hn.read(hn.upR); string(m.ID) != "7" {
		t.Fatalf("a cancelled call is not forwarded, nor its cancellation, upstream got %+v", m)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":7,"result":"ok"}`))
	if m := hn.read(hn.agentR); string(m.ID) != "7" {
		t.Fatalf("no reply is owed for a cancelled call; the next frame must be call 7's answer, got %+v", m)
	}
}
