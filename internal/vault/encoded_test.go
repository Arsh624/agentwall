package vault

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestEncodedSecretsAreRedacted(t *testing.T) {
	const token = "s3cr3t/value+with=odd-chars_0123456789"
	r := NewRedactor(map[string]string{"tok": token})
	for _, prefix := range []string{"", "x", "xy", "x-access-token:", "user:"} { // every base64 alignment
		for name, enc := range map[string]*base64.Encoding{"std": base64.StdEncoding, "url": base64.URLEncoding, "raw": base64.RawStdEncoding} {
			in := "Authorization: Basic " + enc.EncodeToString([]byte(prefix+token+" tail"))
			out, found := r.Text(in)
			if len(found) != 1 || found[0] != "tok" {
				t.Errorf("%s base64 after %q: not redacted: %q", name, prefix, out)
			}
			if dec, _ := enc.DecodeString(strings.TrimPrefix(out, "Authorization: Basic ")); strings.Contains(string(dec), token[4:len(token)-4]) {
				t.Errorf("%s base64 after %q: the secret survives: %q", name, prefix, out)
			}
		}
	}
	for _, in := range []string{"https://x.test/?t=" + url.QueryEscape(token), "https://x.test/" + url.PathEscape(token)} {
		if out, found := r.Text(in); found == nil || strings.Contains(out, "0123456789") {
			t.Errorf("percent-encoded secret not redacted: %q", out)
		}
	}
	if out, found := r.Text("an ordinary sentence about base64 and URLs"); found != nil {
		t.Errorf("false positive: %q", out)
	}
}

func TestSecretsInObjectKeysAreRedacted(t *testing.T) {
	r := NewRedactor(map[string]string{"tok": "abcdefgh12345678"})
	out, found := r.JSON(json.RawMessage(`{"abcdefgh12345678":{"k":"v"},"ok":1}`))
	if found == nil || strings.Contains(string(out), "abcdefgh12345678") || !strings.Contains(string(out), `"ok":1`) {
		t.Fatalf("got %s (%v)", out, found)
	}
}
