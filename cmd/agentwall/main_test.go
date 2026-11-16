package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentwall/agentwall/internal/mockserver"
)

func TestMain(m *testing.M) {
	mockserver.RunIfChild() // lets "wrap" run this test binary as its upstream server
	os.Exit(m.Run())
}

// run executes the CLI with a private state dir and returns stdout.
func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestStubCommandsRegistered(t *testing.T) {
	for _, line := range []string{"init", "proxy", "secret set NAME", "approve srv/tool", "attack"} {
		if _, err := run(t, "", strings.Fields(line)...); err == nil || err.Error() != "not implemented" {
			t.Fatalf("%q: error = %v, want %q", line, err, "not implemented")
		}
	}
}

func TestWrapProxiesToUpstream(t *testing.T) {
	t.Setenv("AGENTWALL_HOME", t.TempDir())
	t.Setenv(mockserver.EnvScenario, "../../testdata/basic.json")
	out, err := run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", "wrap", "--", os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"read_file"`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout must hold exactly the upstream's reply, got %q", out)
	}
}

func TestWrapNeedsACommand(t *testing.T) {
	if _, err := run(t, "", "wrap"); err == nil || err.Error() == "not implemented" {
		t.Fatalf("wrap without a command should be a usage error, got %v", err)
	}
}

func TestWrapEnforcesPolicyAndAudits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	t.Setenv(mockserver.EnvScenario, "../../testdata/basic.json")
	policyFile := filepath.Join(home, "p.yaml")
	os.WriteFile(policyFile, []byte("servers: {mock: {tools: {echo: {action: deny}}}}\n"), 0o600)

	stdin := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a"}}}` + "\n"
	out, err := run(t, stdin, "wrap", "--policy", policyFile, "--server", "mock", "--", os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 ||
		!strings.Contains(lines[0], `"id":1`) || !strings.Contains(lines[0], `-32001`) || !strings.Contains(lines[0], "denied by policy") ||
		!strings.Contains(lines[1], `"id":2`) || !strings.Contains(lines[1], "hello from disk") {
		t.Fatalf("want a blocked error for id 1 and a result for id 2, got %q", out)
	}

	if out, err = run(t, "", "verify"); err != nil || !strings.Contains(out, "2 entries") {
		t.Fatalf("verify: %q, %v", out, err)
	}
	out, err = run(t, "", "log")
	if err != nil || strings.Count(out, "\n") != 2 || !strings.Contains(out, "mock/echo") ||
		!strings.Contains(out, "deny") || !strings.Contains(out, "mock/read_file") {
		t.Fatalf("log: %q, %v", out, err)
	}

	// tampering with the log must make verify fail
	audit := filepath.Join(home, "audit.jsonl")
	b, _ := os.ReadFile(audit)
	os.WriteFile(audit, bytes.Replace(b, []byte(`"deny"`), []byte(`"allow"`), 1), 0o600)
	if _, err = run(t, "", "verify"); err == nil {
		t.Fatal("verify must fail on a tampered log")
	}
}

func TestWrapUsesPolicyFromStateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	t.Setenv(mockserver.EnvScenario, "../../testdata/basic.json")
	os.WriteFile(filepath.Join(home, "policy.yaml"), []byte("default_action: deny\n"), 0o600)
	out, err := run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`+"\n", "wrap", "--", os.Args[0])
	if err != nil || !strings.Contains(out, "-32001") {
		t.Fatalf("policy.yaml in the state dir must apply, got %q, %v", out, err)
	}
}

func TestWrapRejectsBadPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	os.WriteFile(filepath.Join(home, "policy.yaml"), []byte("default_action: maybe\n"), 0o600)
	if _, err := run(t, "", "wrap", "--", os.Args[0]); err == nil {
		t.Fatal("a broken policy must stop wrap from starting")
	}
}

func TestServerName(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github"}, "github"},
		{[]string{"npx", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"}, "filesystem"},
		{[]string{"uvx", "mcp-server-fetch"}, "fetch"},
		{[]string{"/usr/local/bin/slack-mcp"}, "slack-mcp"},
		{[]string{`C:\tools\thing.exe`, "--flag"}, "thing"},
	}
	for _, c := range cases {
		if got := serverName(c.argv); got != c.want {
			t.Errorf("serverName(%q) = %q, want %q", c.argv, got, c.want)
		}
	}
}
