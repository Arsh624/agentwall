package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

func TestServerMessagesGoThroughTheHook(t *testing.T) {
	hn := start(t, Hooks{OnServerMessage: func(m *jsonrpc.Message) Decision {
		if m.Method == "sampling/createMessage" || m.Method == "notifications/evil" {
			return Decision{Deny: true, Reason: "no " + m.Method}
		}
		m.Params = json.RawMessage(`"[REDACTED]"`)
		return Decision{}
	}})

	hn.upW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"secret"}}`))
	if m := hn.read(hn.agentR); string(m.Params) != `"[REDACTED]"` {
		t.Fatalf("notification must be rewritten, agent got %s", m.Params)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":"s1","method":"elicitation/create","params":{"message":"secret"}}`))
	if m := hn.read(hn.agentR); string(m.Params) != `"[REDACTED]"` {
		t.Fatalf("server request must be rewritten, agent got %s", m.Params)
	}

	// a denied server request is answered by the proxy, and the agent never sees it
	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":"s2","method":"sampling/createMessage","params":{}}`))
	if m := hn.read(hn.upR); string(m.ID) != `"s2"` || m.Error == nil || m.Error.Code != CodeBlocked || !strings.Contains(m.Error.Message, "no sampling") {
		t.Fatalf("upstream must get a blocked error, got %+v", m)
	}
	hn.upW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/evil"}`)) // denied notification: dropped
	hn.upW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/ok"}`))
	if m := hn.read(hn.agentR); m.Method != "notifications/ok" {
		t.Fatalf("denied messages must not reach the agent, got %+v", m)
	}
}

func TestCancelledRequestIsForgotten(t *testing.T) {
	hn := start(t, Hooks{})
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow"}}`))
	hn.read(hn.upR)
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`))
	hn.read(hn.upR) // the cancellation is forwarded, and the request is forgotten

	hn.upW.Write(msg(`{"jsonrpc":"2.0","id":7,"result":"late"}`)) // a late answer has no hook to vet it: dropped
	hn.upW.Write(msg(`{"jsonrpc":"2.0","method":"notifications/ok"}`))
	if m := hn.read(hn.agentR); m.Method != "notifications/ok" {
		t.Fatalf("the late answer to a cancelled request must be dropped, agent got %+v", m)
	}
}
