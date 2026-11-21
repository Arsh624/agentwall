package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAllowedHosts(t *testing.T) {
	p, err := Parse([]byte(`servers: {fetch: {tools: {fetch: {allowed_hosts: [example.org, GitHub.com]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for args, want := range map[string]Action{
		`{"url":"https://example.org/a"}`:                             Allow,
		`{"url":"https://api.github.com/x"}`:                          Allow, // subdomain of a listed host
		`{"url":"HTTPS://EXAMPLE.ORG:443/a"}`:                         Allow,
		`{"url":"https://evil.test/?q=1"}`:                            Deny,
		`{"url":"https://example.org.evil.test/"}`:                    Deny,
		`{"url":"https://notgithub.com/"}`:                            Deny,
		`{"url":"https://example.org@evil.test/"}`:                    Deny, // userinfo trick
		`{"note":"see http://evil.test", "url":"https://github.com"}`: Deny, // every URL counts
		`{"q":"no url here"}`:                                         Allow,
	} {
		d := p.Decide("fetch", "fetch", json.RawMessage(args))
		if d.Action != want {
			t.Errorf("%s: %v (%s), want %v", args, d.Action, d.Reason, want)
		}
		if want == Deny && !strings.Contains(d.Reason, "allowed_hosts") {
			t.Errorf("%s: reason must name allowed_hosts: %q", args, d.Reason)
		}
	}
	if d := p.Decide("fetch", "other", json.RawMessage(`{"url":"https://evil.test"}`)); d.Action != Allow {
		t.Errorf("tools without allowed_hosts are not checked: %v", d)
	}
	for _, bad := range []string{`[https://x.test]`, `[x.test/path]`, `[""]`} {
		if _, err := Parse([]byte(`servers: {s: {tools: {t: {allowed_hosts: ` + bad + `}}}}`)); err == nil {
			t.Errorf("allowed_hosts %s must be rejected", bad)
		}
	}
}
