package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testYAML = `
servers:
  s:
    tools:
      denied: {action: deny}
      asked: {action: ask}
      exact: {action: allow}
      dargs:
        tags: [egress_sink]
        action: allow
        deny_args:
          body: "(?i)password"
          a_first: "secret"
      "*": {action: ask, tags: [private_source]}
  t:
    tools:
      x: {tags: [untrusted_source]}
`

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecide(t *testing.T) {
	p := mustParse(t, testYAML)
	deny := mustParse(t, "default_action: deny\n")
	tests := []struct {
		name         string
		p            *Policy
		server, tool string
		args         string
		want         Action
		reason       string
	}{
		{"default allow", mustParse(t, ""), "s", "x", "", Allow, ""},
		{"unknown server", p, "nope", "x", "", Allow, ""},
		{"unknown tool no wildcard", p, "t", "y", "", Allow, ""},
		{"no action entry", p, "t", "x", "", Allow, ""},
		{"explicit deny", p, "s", "denied", "", Deny, "tool is denied by policy"},
		{"explicit ask", p, "s", "asked", "", Ask, "tool needs approval"},
		{"default deny", deny, "s", "x", "", Deny, "tool is denied by policy"},
		{"wildcard", p, "s", "other", "", Ask, "tool needs approval"},
		{"exact beats wildcard", p, "s", "exact", "", Allow, ""},
		{"string match", p, "s", "dargs", `{"body":"my Password is"}`, Deny, `argument "body" matches deny rule`},
		{"no match", p, "s", "dargs", `{"body":"hello"}`, Allow, ""},
		{"number as json text", mustParse(t, "servers: {s: {tools: {t: {deny_args: {n: '^42$'}}}}}"), "s", "t", `{"n":42}`, Deny, `argument "n" matches deny rule`},
		{"nested object as json text", mustParse(t, "servers: {s: {tools: {t: {deny_args: {o: 'k\":\"v'}}}}}"), "s", "t", `{"o":{"k": "v"}}`, Deny, `argument "o" matches deny rule`},
		{"escaped string", p, "s", "dargs", `{"body":"password"}`, Deny, `argument "body" matches deny rule`},
		{"alphabetical first", p, "s", "dargs", `{"body":"password","a_first":"secret"}`, Deny, `argument "a_first" matches deny rule`},
		{"not an object", p, "s", "dargs", `[1]`, Deny, "arguments are not a JSON object"},
		{"invalid json", p, "s", "dargs", `{`, Deny, "arguments are not a JSON object"},
		{"empty args", p, "s", "dargs", "", Allow, ""},
		{"null args", p, "s", "dargs", "null", Allow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args json.RawMessage
			if tt.args != "" {
				args = json.RawMessage(tt.args)
			}
			got := tt.p.Decide(tt.server, tt.tool, args)
			if got.Action != tt.want || got.Reason != tt.reason {
				t.Errorf("got %+v, want %s %q", got, tt.want, tt.reason)
			}
		})
	}
}

func TestReasonHasNoValue(t *testing.T) {
	d := mustParse(t, testYAML).Decide("s", "dargs", json.RawMessage(`{"body":"hunter2 password"}`))
	if d.Action != Deny || strings.Contains(d.Reason, "hunter2") {
		t.Errorf("bad decision %+v", d)
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"bad default": "default_action: nope",
		"bad action":  "servers: {s: {tools: {t: {action: nope}}}}",
		"bad tag":     "servers: {s: {tools: {t: {tags: [nope]}}}}",
		"bad regexp":  "servers: {s: {tools: {t: {deny_args: {a: '('}}}}}",
		"unknown key": "servers: {s: {tools: {t: {deny_arg: {a: x}}}}}",
		"malformed":   "servers: [",
	}
	for name, y := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(y)); err == nil {
				t.Error("expected error")
			}
		})
	}
	_, err := Parse([]byte("servers: {srv: {tools: {tl: {action: nope}}}}"))
	if err == nil || !strings.Contains(err.Error(), "srv") || !strings.Contains(err.Error(), "tl") {
		t.Errorf("error should name server and tool: %v", err)
	}
}

func TestTags(t *testing.T) {
	p := mustParse(t, testYAML)
	if got := p.Tags("s", "dargs"); !reflect.DeepEqual(got, []string{TagEgress}) {
		t.Errorf("exact: %v", got)
	}
	if got := p.Tags("s", "other"); !reflect.DeepEqual(got, []string{TagPrivate}) {
		t.Errorf("wildcard: %v", got)
	}
	if got := p.Tags("t", "y"); got != nil {
		t.Errorf("none: %v", got)
	}
	if got := p.Tags("zzz", "y"); got != nil {
		t.Errorf("unknown server: %v", got)
	}
}

func TestDefault(t *testing.T) {
	p := Default()
	has := func(server, tool string, tags ...string) {
		t.Helper()
		got := p.Tags(server, tool)
		for _, tag := range tags {
			found := false
			for _, g := range got {
				found = found || g == tag
			}
			if !found {
				t.Errorf("%s/%s missing %s, has %v", server, tool, tag, got)
			}
		}
	}
	has("github", "get_issue", TagUntrusted)
	has("github", "get_file_contents", TagPrivate)
	has("github", "create_pull_request", TagEgress)
	has("fetch", "fetch", TagUntrusted, TagEgress)
	if d := p.Decide("github", "create_pull_request", nil); d.Action != Allow {
		t.Errorf("got %+v", d)
	}
}

func TestLoad(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(f, []byte("default_action: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("a", "b", nil).Action != Deny {
		t.Error("default_action not applied")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
