package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// minSecretLen keeps short vault values (a PIN) from blanking ordinary text.
const minSecretLen = 8

// tokenPatterns catch well-known credential formats that are not in the vault.
// A regexp costs ~30 ns per byte, so it only runs on text that contains one of
// its hints: a literal every match must include, found with a fast substring search.
var tokenPatterns = []struct {
	kind  string
	hints []string
	re    *regexp.Regexp
}{
	{"github-token", githubHints, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`)},
	{"api-key", []string{"sk-"}, regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)},
	{"slack-token", []string{"xox"}, regexp.MustCompile(`\bxox[abeprs]-[A-Za-z0-9-]{10,}`)},
	{"aws-key", []string{"AKIA", "ASIA"}, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"private-key", []string{"PRIVATE KEY-----"}, regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
}

// escapeRE matches CSI (ESC [ ... final), OSC (ESC ] ... BEL or ESC \) and two-byte ESC sequences;
// a lone ESC at the end goes too, and so does U+009B, the one-character CSI some terminals honour.
var escapeRE = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[ -~])?|\x{9b}[0-?]*[ -/]*[@-~]`)

var githubHints = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}

// Redactor replaces secrets with [REDACTED:<name>] before the agent sees them.
type Redactor struct {
	secrets []secret // longest first, so a secret that contains another is replaced whole
}

type secret struct{ name, value string }

func NewRedactor(secrets map[string]string) *Redactor {
	r := &Redactor{}
	for name, value := range secrets {
		if len(value) < minSecretLen {
			continue
		}
		for _, v := range encodings(value) {
			if !slices.Contains(r.secrets, secret{name, v}) {
				r.secrets = append(r.secrets, secret{name, v})
			}
		}
	}
	slices.SortFunc(r.secrets, func(a, b secret) int {
		if len(a.value) != len(b.value) {
			return len(b.value) - len(a.value)
		}
		return strings.Compare(a.name, b.name)
	})
	return r
}

// encodings are the forms a secret takes when a server echoes it back:
// as is, percent-encoded in a URL, or inside base64 (a Basic auth header,
// a git extraheader). base64 shifts with the secret's offset in the encoded
// text, so each of the three alignments gets the run of characters that
// encodes only secret bytes.
func encodings(s string) []string {
	out := []string{s, url.QueryEscape(s), url.PathEscape(s)}
	for k, skip := range []int{0, 2, 3} { // leading characters that mix in the k bytes before the secret
		b := append(make([]byte, k), s...)
		b = b[:len(b)/3*3] // the last partial group mixes in the bytes after it
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			out = append(out, enc.EncodeToString(b)[skip:])
		}
	}
	return out
}

// Text redacts s and returns the names of what it found (nil if nothing).
func (r *Redactor) Text(s string) (string, []string) {
	var found []string
	note := func(label string) {
		if !slices.Contains(found, label) {
			found = append(found, label)
		}
	}
	for _, sec := range r.secrets {
		if strings.Contains(s, sec.value) {
			s = strings.ReplaceAll(s, sec.value, "[REDACTED:"+sec.name+"]")
			note(sec.name)
		}
	}
	if strings.IndexByte(s, 0x1b) >= 0 || strings.ContainsRune(s, 0x9b) { // terminal escapes can hide or rewrite text where output is shown
		s = escapeRE.ReplaceAllString(s, "")
		note("terminal-escape")
	}
	for _, p := range tokenPatterns {
		if slices.ContainsFunc(p.hints, func(h string) bool { return strings.Contains(s, h) }) && p.re.MatchString(s) {
			s = p.re.ReplaceAllString(s, "[REDACTED:"+p.kind+"]")
			note(p.kind)
		}
	}
	return s, found
}

// JSON redacts every string value inside a JSON document. Working on decoded
// strings means escaping cannot hide a secret and numbers are never touched.
// A document with nothing to redact comes back byte for byte.
func (r *Redactor) JSON(raw json.RawMessage) (json.RawMessage, []string) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as written
	var doc any
	if dec.Decode(&doc) != nil {
		return raw, nil
	}
	var found []string
	var walk func(any) any
	walk = func(v any) any {
		switch v := v.(type) {
		case string:
			out, f := r.Text(v)
			for _, label := range f {
				if !slices.Contains(found, label) {
					found = append(found, label)
				}
			}
			return out
		case []any:
			for i := range v {
				v[i] = walk(v[i])
			}
		case map[string]any:
			out := make(map[string]any, len(v))
			for k, val := range v {
				out[walk(k).(string)] = walk(val)
			}
			return out
		}
		return v
	}
	doc = walk(doc)
	if found == nil {
		return raw, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(doc) != nil {
		return raw, nil
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), found
}
