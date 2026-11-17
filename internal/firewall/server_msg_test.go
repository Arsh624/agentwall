package firewall

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/vault"
)

func TestServerMessagesAreRedactedAndSamplingIsRefused(t *testing.T) {
	dir := t.TempDir()
	f := open(t, dir, "srv", "s1", policy.Default())
	f.Redact = vault.NewRedactor(map[string]string{"github": vaultToken})
	hook := f.Hooks().OnServerMessage

	logMsg := &jsonrpc.Message{JSONRPC: "2.0", Method: "notifications/message",
		Params: json.RawMessage(`{"level":"debug","data":"using token ` + vaultToken + `"}`)}
	if d := hook(logMsg); d.Deny || strings.Contains(string(logMsg.Params), vaultToken) || !strings.Contains(string(logMsg.Params), "[REDACTED:github]") {
		t.Fatalf("a log notification must be redacted and delivered: %v %s", d, logMsg.Params)
	}
	ask := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`"e1"`), Method: "elicitation/create",
		Params: json.RawMessage(`{"message":"confirm ` + vaultToken + `?"}`)}
	if d := hook(ask); d.Deny || strings.Contains(string(ask.Params), vaultToken) {
		t.Fatalf("an elicitation must be redacted and delivered: %v %s", d, ask.Params)
	}
	sampling := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`"s1"`), Method: "sampling/createMessage", Params: json.RawMessage(`{}`)}
	if d := hook(sampling); !d.Deny || !strings.Contains(d.Reason, "sampling") {
		t.Fatalf("sampling must be refused: %v", d)
	}

	entries, _ := audit.Read(filepath.Join(dir, "audit.jsonl"))
	var got []string
	for _, e := range entries {
		got = append(got, e.Tool+"="+e.Decision)
	}
	if strings.Join(got, " ") != "notifications/message=redact elicitation/create=redact sampling/createMessage=deny" {
		t.Fatalf("audit entries: %v", got)
	}
}
