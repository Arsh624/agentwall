package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	ghToken    = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dbPassword = `p@ss "quoted" \ and ünïcode`
)

func TestRedactText(t *testing.T) {
	r := NewRedactor(map[string]string{"db": dbPassword, "long": "zyxwvuts12345678", "short-prefix": "zyxwvuts", "pin": "1234"})
	cases := []struct{ name, in, want string }{
		{"vault value", "password is " + dbPassword + " ok", "password is [REDACTED:db] ok"},
		{"every occurrence", dbPassword + dbPassword, "[REDACTED:db][REDACTED:db]"},
		{"longest secret wins", "x zyxwvuts12345678 y zyxwvuts z", "x [REDACTED:long] y [REDACTED:short-prefix] z"},
		{"values under 8 chars are left alone", "pin 1234 and 12345", "pin 1234 and 12345"},
		{"github token", "token=" + ghToken, "token=[REDACTED:github-token]"},
		{"github fine-grained", "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz", "[REDACTED:github-token]"},
		{"openai/anthropic style", "sk-ant-api03-abcdefghijklmnopqrstuvwx", "[REDACTED:api-key]"},
		{"slack", "xoxb-1234567890-abcdefghij", "[REDACTED:slack-token]"},
		{"aws", "id AKIAIOSFODNN7EXAMPLE.", "id [REDACTED:aws-key]."},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\naGVsbG8=\n-----END OPENSSH PRIVATE KEY-----\nafter",
			"[REDACTED:private-key]\nafter"},
		{"benign", "task-123 skeleton sk-1 ghp_short xoxo AKIA is a prefix, see github_path", "task-123 skeleton sk-1 ghp_short xoxo AKIA is a prefix, see github_path"},
	}
	for _, c := range cases {
		if got, _ := r.Text(c.in); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
	if _, found := r.Text("x " + dbPassword + " " + ghToken); len(found) != 2 || found[0] != "db" || found[1] != "github-token" {
		t.Fatalf("found = %v, want [db github-token]", found)
	}
	if _, found := r.Text("nothing here"); found != nil {
		t.Fatalf("found = %v, want none", found)
	}
}

func TestRedactJSON(t *testing.T) {
	r := NewRedactor(map[string]string{"db": dbPassword, "digits": "1234567890"})
	escaped, _ := json.Marshal("env: DB=" + dbPassword) // the secret is JSON-escaped on the wire
	in := `{"content":[{"type":"text","text":` + string(escaped) + `},{"type":"text","text":"` + ghToken + `"}],` +
		`"big":12345678901234567890,"price":1.10,"n":1234567890,"s":"id 1234567890 <b>&</b>","ok":true,"none":null}`
	out, found := r.JSON(json.RawMessage(in))

	if strings.Contains(string(out), "quoted") || strings.Contains(string(out), ghToken) {
		t.Fatalf("secret survived: %s", out)
	}
	var got map[string]any
	dec := json.NewDecoder(strings.NewReader(string(out)))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	content := got["content"].([]any)
	if content[0].(map[string]any)["text"] != "env: DB=[REDACTED:db]" || content[1].(map[string]any)["text"] != "[REDACTED:github-token]" {
		t.Fatalf("bad redaction: %s", out)
	}
	// only strings change: numbers keep their exact digits, even when they equal a secret
	for key, want := range map[string]string{"big": "12345678901234567890", "price": "1.10", "n": "1234567890"} {
		if got[key].(json.Number).String() != want {
			t.Errorf("%s = %v, want %s", key, got[key], want)
		}
	}
	if got["s"] != "id [REDACTED:digits] <b>&</b>" || !strings.Contains(string(out), "<b>&</b>") {
		t.Errorf("s = %q (raw %s)", got["s"], out)
	}
	if len(found) != 3 {
		t.Errorf("found = %v, want db, digits, github-token", found)
	}

	clean := json.RawMessage(`{ "a" : [1, "two", {"three": 3.0}] }`)
	if out, found := r.JSON(clean); string(out) != string(clean) || found != nil {
		t.Fatalf("clean JSON must come back byte for byte, got %s %v", out, found)
	}
	if out, _ := r.JSON(nil); out != nil {
		t.Fatal("nil stays nil")
	}
}
