package firewall

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/policy"
)

// Upstream must get exactly what the policy inspected, even when a parser
// there would read duplicate keys differently from Go (first key wins).
func TestUpstreamGetsTheArgumentsThePolicyChecked(t *testing.T) {
	p, err := policy.Parse([]byte(`
servers:
  srv:
    tools:
      read_file: {deny_args: {path: '^/etc/'}}
      delete_repo: {action: deny}
`))
	if err != nil {
		t.Fatal(err)
	}
	f := open(t, t.TempDir(), "srv", "s1", p)

	req := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"delete_repo","name":"read_file","arguments":{"path":"/etc/shadow","path":"notes.txt","n":12345678901234567890,"html":"<b>&"},"_meta":{"progressToken":7}}`)}
	if d := f.Hooks().OnRequest(req); d.Deny {
		t.Fatalf("the call Go reads (read_file notes.txt) is allowed: %v", d)
	}
	got := string(req.Params)
	for _, gone := range []string{"delete_repo", "/etc/shadow"} {
		if strings.Contains(got, gone) {
			t.Fatalf("upstream would see %q, which the policy never checked: %s", gone, got)
		}
	}
	for _, kept := range []string{`"name":"read_file"`, `"path":"notes.txt"`, `12345678901234567890`, `"<b>&"`, `"progressToken":7`} {
		if !strings.Contains(got, kept) {
			t.Fatalf("lost %s: %s", kept, got)
		}
	}
}
