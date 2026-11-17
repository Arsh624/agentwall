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

const vaultToken = "hunter2-very-secret-token"

func TestSecretsNeverReachTheAgent(t *testing.T) {
	dir := t.TempDir()
	f := open(t, dir, "srv", "s1", policy.Default())
	f.Redact = vault.NewRedactor(map[string]string{"github": vaultToken})

	// a tool result that dumps the environment
	req := toolCall("run", `{"cmd":"env"}`)
	f.Hooks().OnRequest(req)
	out := f.Hooks().OnResponse(req, &jsonrpc.Message{JSONRPC: "2.0", ID: req.ID,
		Result: json.RawMessage(`{"content":[{"type":"text","text":"GITHUB_TOKEN=` + vaultToken + `\nAWS=AKIAIOSFODNN7EXAMPLE"}]}`)})
	got := string(out.Result)
	if strings.Contains(got, vaultToken) || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") ||
		!strings.Contains(got, "[REDACTED:github]") || !strings.Contains(got, "[REDACTED:aws-key]") {
		t.Fatalf("result not redacted: %s", got)
	}

	// an error that quotes the token, on a method that is not a tool call
	init := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "initialize"}
	errResp := jsonrpc.ErrorResponse(init.ID, -32000, "401 for token "+vaultToken)
	errResp.Error.Data = json.RawMessage(`{"header":"Bearer ` + vaultToken + `"}`)
	out = f.Hooks().OnResponse(init, errResp)
	if strings.Contains(out.Error.Message+string(out.Error.Data), vaultToken) ||
		!strings.Contains(out.Error.Message, "[REDACTED:github]") || !strings.Contains(string(out.Error.Data), "[REDACTED:github]") {
		t.Fatalf("error not redacted: %+v data=%s", out.Error, out.Error.Data)
	}

	entries, _ := audit.Read(filepath.Join(dir, "audit.jsonl"))
	var redactions []string
	for _, e := range entries {
		if e.Decision == "redact" {
			redactions = append(redactions, e.Tool+": "+e.Reason)
		}
	}
	if len(redactions) != 2 || !strings.Contains(redactions[0], "run") || !strings.Contains(redactions[0], "github") ||
		!strings.Contains(redactions[0], "aws-key") || !strings.Contains(redactions[1], "initialize") {
		t.Fatalf("redactions must be audited by name, got %q", redactions)
	}
	for _, e := range entries {
		if strings.Contains(e.Reason, vaultToken) {
			t.Fatal("the audit log must not contain the secret")
		}
	}
}

func TestCleanResultsAreUntouched(t *testing.T) {
	f := open(t, t.TempDir(), "srv", "s1", policy.Default())
	req := toolCall("run", `{}`)
	f.Hooks().OnRequest(req)
	in := `{ "content" : [ {"type":"text","text":"nothing secret, 1.10"} ] }`
	out := f.Hooks().OnResponse(req, &jsonrpc.Message{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(in)})
	if string(out.Result) != in {
		t.Fatalf("clean result changed: %s", out.Result)
	}
}
