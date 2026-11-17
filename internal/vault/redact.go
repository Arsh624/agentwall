package vault

import (
	"bytes"
	"encoding/json"
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

var githubHints = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}

// Redactor replaces secrets with [REDACTED:<name>] before the agent sees them.
type Redactor struct {
	secrets []secret // longest first, so a secret that contains another is replaced whole
}

type secret struct{ name, value string }

func NewRedactor(secrets map[string]string) *Redactor {
	r := &Redactor{}
	for name, value := range secrets {
		if len(value) >= minSecretLen {
			r.secrets = append(r.secrets, secret{name, value})
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
			for k := range v {
				v[k] = walk(v[k])
			}
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
