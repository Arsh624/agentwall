package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInitApplyWrapsEveryStdioServer(t *testing.T) {
	_, home, cwd := isolate(t)
	exe, _ := os.Executable()
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	project := `{
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "ghp_live"}},
    "docs": {"type": "http", "url": "https://mcp.example.com/mcp"},
    "safe": {"command": "agentwall", "args": ["wrap", "--", "uvx", "mcp-server-fetch"]}
  }
}`
	os.WriteFile(filepath.Join(cwd, ".mcp.json"), []byte(project), 0o600)
	claude, _ := json.Marshal(map[string]any{
		"oauthAccount": map[string]any{"emailAddress": "keep@example.test"},
		"numStartups":  json.Number("12345678901234567890"),
		"projects": map[string]any{
			cwd:            map[string]any{"mcpServers": map[string]any{"notes": map[string]any{"command": "node", "args": []any{"notes.js"}}}},
			"/elsewhere/x": map[string]any{"mcpServers": map[string]any{"other": map[string]any{"command": "node"}}},
		},
	})
	os.WriteFile(filepath.Join(home, ".claude.json"), claude, 0o600)

	// before: --check lists every server that is not protected, and changes nothing
	out, err := run(t, "", "init", "--check")
	for _, want := range []string{`"github"`, `"notes"`, `"docs" in`} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("--check must list %s: %q %v", want, out, err)
		}
	}
	if strings.Contains(out, `"safe"`) || strings.Contains(out, `"other"`) {
		t.Fatalf("--check lists a protected server or another project's: %q", out)
	}

	if out, err = run(t, "", "init", "--apply"); err != nil || !strings.Contains(out, "Restart your agent") {
		t.Fatalf("--apply: %q %v", out, err)
	}
	doc, _ := readConfig(filepath.Join(cwd, ".mcp.json"))
	github := doc["mcpServers"].(map[string]any)["github"].(map[string]any)
	if github["command"] != exe || !reflect.DeepEqual(github["args"], []any{"wrap", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"}) {
		t.Fatalf("github not wrapped by absolute path: %v", github)
	}
	if github["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_live" {
		t.Fatal("the server's env must be kept")
	}
	if safe := doc["mcpServers"].(map[string]any)["safe"].(map[string]any); safe["command"] != "agentwall" {
		t.Fatalf("an already wrapped server must be left alone: %v", safe)
	}
	backups, _ := filepath.Glob(filepath.Join(cwd, ".mcp.json.agentwall-backup-*"))
	if len(backups) != 1 {
		t.Fatalf("want one backup, got %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != project {
		t.Fatal("the backup must hold the original bytes")
	}

	raw, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	for _, keep := range []string{"keep@example.test", "12345678901234567890", `"other"`} {
		if !strings.Contains(string(raw), keep) {
			t.Fatalf("~/.claude.json lost %s: %s", keep, raw)
		}
	}
	cdoc, _ := readConfig(filepath.Join(home, ".claude.json"))
	notes := cdoc["projects"].(map[string]any)[cwd].(map[string]any)["mcpServers"].(map[string]any)["notes"].(map[string]any)
	if notes["command"] != exe {
		t.Fatalf("the project's local server must be wrapped: %v", notes)
	}

	// after: only the HTTP server is left, and a second run changes nothing
	if out, _ = run(t, "", "init", "--check"); strings.Contains(out, `"github"`) || strings.Contains(out, `"notes"`) || !strings.Contains(out, `"docs"`) {
		t.Fatalf("--check after --apply: %q", out)
	}
	if out, _ = run(t, "", "init", "--apply"); !strings.Contains(out, "already goes through agentwall") {
		t.Fatalf("second --apply: %q", out)
	}
	if backups, _ = filepath.Glob(filepath.Join(cwd, ".mcp.json.agentwall-backup-*")); len(backups) != 1 {
		t.Fatalf("a second --apply must not write another backup: %v", backups)
	}
}

func TestInitCheckIsSilentWhenAllIsProtected(t *testing.T) {
	_, _, cwd := isolate(t)
	os.WriteFile(filepath.Join(cwd, ".mcp.json"), []byte(`{"mcpServers": {"safe": {"command": "C:\\tools\\agentwall.exe", "args": ["wrap", "--", "x"]}}}`), 0o600)
	if out, err := run(t, "", "init", "--check"); err != nil || out != "" {
		t.Fatalf("want no output, got %q %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("AGENTWALL_HOME"), "policy.yaml")); err == nil {
		t.Fatal("--check must not write anything")
	}
}
