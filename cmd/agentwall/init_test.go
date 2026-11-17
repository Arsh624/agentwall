package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/policy"
)

// isolate points the state dir, the home dir and the working dir at fresh temp dirs.
func isolate(t *testing.T) (state, home, cwd string) {
	t.Helper()
	state, home, cwd = filepath.Join(t.TempDir(), "state"), t.TempDir(), t.TempDir()
	t.Setenv("AGENTWALL_HOME", state)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(cwd)
	return
}

func TestInitWritesThePolicyOnce(t *testing.T) {
	state, _, _ := isolate(t)
	out, err := run(t, "", "init")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "policy.yaml")
	if _, err := policy.Load(path); err != nil {
		t.Fatalf("init must write a valid policy: %v", err)
	}
	if !strings.Contains(out, path) {
		t.Fatalf("init must say where the policy is: %s", out)
	}
	// no MCP config anywhere: print a generic example
	if !strings.Contains(out, `"command": "agentwall"`) || !strings.Contains(out, "server-github") {
		t.Fatalf("init must print an example snippet: %s", out)
	}

	os.WriteFile(path, []byte("default_action: ask\n"), 0o600) // the user's edits
	if _, err := run(t, "", "init"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "default_action: ask\n" {
		t.Fatal("init must never overwrite an existing policy")
	}
}

func TestInitShowsHowToWrapDetectedServers(t *testing.T) {
	_, home, cwd := isolate(t)
	original := `{
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "ghp_live"}},
    "docs": {"type": "http", "url": "https://mcp.example.com/mcp"},
    "safe": {"command": "agentwall", "args": ["wrap", "--", "uvx", "mcp-server-fetch"]}
  }
}`
	os.WriteFile(filepath.Join(cwd, ".mcp.json"), []byte(original), 0o600)
	os.MkdirAll(filepath.Join(home, ".cursor"), 0o700)
	os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{"mcpServers": {"files": {"command": "npx", "args": ["server-filesystem", "/tmp"]}}}`), 0o600)

	out, err := run(t, "", "init")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		".mcp.json", filepath.Join(".cursor", "mcp.json"),
		`"wrap", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"`,
		`"wrap", "--server", "files", "--", "npx", "server-filesystem", "/tmp"`,
		"agentwall proxy --upstream https://mcp.example.com/mcp", // HTTP servers go through proxy mode
		"agentwall secret set", // the env block holds a secret: say how to move it
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ghp_live") {
		t.Error("init must not print secret values from the config")
	}
	if strings.Contains(out, `"safe"`) {
		t.Error("a server that is already wrapped needs no change")
	}
	if b, _ := os.ReadFile(filepath.Join(cwd, ".mcp.json")); string(b) != original {
		t.Error("init must not edit the user's config")
	}
}
