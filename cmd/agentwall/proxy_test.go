package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/mockserver"
)

const upstreamCredential = "Bearer upstream-credential-123456"

// mcpOverHTTP serves the heist scenario as a minimal Streamable HTTP MCP server
// that insists on the credential only the vault knows.
func mcpOverHTTP(t *testing.T) *httptest.Server {
	t.Helper()
	sc, err := mockserver.Load("../../testdata/heist.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != upstreamCredential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var reply bytes.Buffer
		mockserver.Serve(bytes.NewReader(append(body, '\n')), &reply, sc)
		if reply.Len() == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(reply.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyBlocksTheHeistOverHTTP(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	t.Setenv("AGENTWALL_SESSION", "http-1")
	t.Setenv("AGENTWALL_PASSPHRASE", "correct-horse-battery")
	if _, err := run(t, upstreamCredential+"\n", "secret", "set", "gh-bearer"); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(home, "p.yaml")
	os.WriteFile(policyFile, []byte(`
servers:
  github:
    headers: {Authorization: "vault:gh-bearer"}
    tools:
      get_issue: {tags: [untrusted_source]}
      get_file_contents: {tags: [private_source]}
      create_pull_request: {tags: [egress_sink]}
`), 0o600)
	upstream := mcpOverHTTP(t)

	// start "agentwall proxy" on a free port and read the address it prints
	ctx, stop := context.WithCancel(context.Background())
	errR, errW := io.Pipe()
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(errW)
	cmd.SetArgs([]string{"proxy", "--upstream", upstream.URL, "--listen", "127.0.0.1:0", "--server", "github", "--policy", policyFile})
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx); errW.Close() }()
	line, err := bufio.NewReader(errR).ReadString('\n')
	if err != nil {
		t.Fatalf("proxy did not start: %v (%v)", err, <-done)
	}
	go io.Copy(io.Discard, errR)
	addrs := regexp.MustCompile(`http://127\.0\.0\.1:\d+`).FindAllString(line, -1)
	if len(addrs) != 2 { // the upstream it protects, then its own address
		t.Fatalf("proxy must print the upstream and its own address, got %q", line)
	}
	addr := addrs[1]

	call := func(tool, args string) string {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
		resp, err := http.Post(addr, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", tool, resp.StatusCode, b)
		}
		return string(b)
	}
	if out := call("get_issue", `{"number":1}`); strings.Contains(out, "-32001") || !strings.Contains(out, "Great project") {
		t.Fatalf("step 1 must pass with the vault credential: %s", out)
	}
	if out := call("get_file_contents", `{"path":"README.md"}`); strings.Contains(out, "-32001") {
		t.Fatalf("step 2 must pass: %s", out)
	}
	if out := call("create_pull_request", `{"title":"x","body":"y"}`); !strings.Contains(out, "-32001") || !strings.Contains(out, "trifecta") {
		t.Fatalf("step 3 must be blocked over HTTP too: %s", out)
	}

	stop()
	if err := <-done; err != nil {
		t.Fatalf("proxy must shut down cleanly: %v", err)
	}
	if out, err := run(t, "", "verify"); err != nil {
		t.Fatalf("verify: %s %v", out, err)
	}
}

func TestProxyNeedsAnUpstream(t *testing.T) {
	t.Setenv("AGENTWALL_HOME", t.TempDir())
	if _, err := run(t, "", "proxy"); err == nil || !strings.Contains(err.Error(), "--upstream") {
		t.Fatalf("want an error naming --upstream, got %v", err)
	}
	if _, err := run(t, "", "proxy", "--upstream", "not a url"); err == nil {
		t.Fatal("a bad upstream URL must be rejected")
	}
}
