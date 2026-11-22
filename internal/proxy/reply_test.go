package proxy

import (
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

var replyHooks = Hooks{OnRequest: func(req *jsonrpc.Message) Decision {
	if strings.Contains(string(req.Params), "risky") {
		return Decision{Result: []byte(`{"resultType":"input_required","requestState":"s"}`)}
	}
	return Decision{}
}}

// A Decision with Result answers the agent directly; upstream never sees the call.
func TestDecisionResultAnswersTheAgent(t *testing.T) {
	hn := start(t, replyHooks)
	hn.agentW.Write(msg(riskyCall))
	if m := hn.read(hn.agentR); string(m.ID) != "5" || !strings.Contains(string(m.Result), "input_required") || m.Error != nil {
		t.Fatalf("want the firewall's result for call 5, got %+v", m)
	}
	hn.agentW.Write(msg(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"safe"}}`))
	if m := hn.read(hn.upR); string(m.ID) != "6" {
		t.Fatalf("the answered call must not reach upstream, got %+v", m)
	}
}

func TestHTTPDecisionResultAnswersTheAgent(t *testing.T) {
	u := &upstream{}
	p := front(t, u, replyHooks)
	resp, body := post(t, p.URL, riskyCall)
	if resp.StatusCode != 200 || !strings.Contains(body, "input_required") || u.seen() != 0 {
		t.Fatalf("status %d, body %s, upstream saw %d", resp.StatusCode, body, u.seen())
	}
}
