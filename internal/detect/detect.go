// Package detect scores text for prompt-injection heuristics.
package detect

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Threshold is the score at which text counts as suspicious.
const Threshold = 3

type Result struct {
	Score   int
	Signals []string // names of the signals that fired, sorted, no duplicates
}

func (r Result) Suspicious() bool { return r.Score >= Threshold }

// Go's regexp is an NFA (~30 ns/byte), so Score never runs one over the whole
// text. A single pass over the text finds keyword hits; a regexp then runs only
// on a short slice at a hit (anchored at it, see matchAt).
const (
	maxGap   = 80  // characters allowed between an action verb and its object
	matchLen = 160 // bytes handed to an anchored regexp at a hit
	nounLen  = 48  // longest noun match we look for
	addrPre  = 64  // addressed: bytes of context before a hit
	addrPost = 32  // addressed: bytes of context after a hit
	addrSnap = 128 // addressed: how far the context may move back to a line start
)

// The patterns below are anchored at the first word of each alternative (the
// hit); the word boundary before it is checked by the scan.
var (
	overrideRe = regexp.MustCompile(`(?i)^(?:ignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|messages|context|rules)|disregard\s+(?:\w+\s+){0,4}(?:instructions|rules)|forget\s+(?:everything|all)\s+(?:above|previous|you\s+were\s+told)|new\s+instructions\s*:|override\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions))`)
	roleRe     = regexp.MustCompile(`(?i)^(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+(?:are|will|must)|act\s+as\s+(?:an?\s+)?(?:[\w-]+\s+){0,6}(?:assistant|ai|agent|model)\s+with\s+no|system\s+prompt|developer\s+mode|jailbreak|dan\s+mode)\b`)
	secrecyRe  = regexp.MustCompile(`(?i)^(?:(?:do\s+not|don['’]?t|never)\s+(?:tell|mention|inform|reveal|show)\s+(?:\w+\s+){0,6}user|without\s+(?:telling|informing|asking|notifying)\s+(?:the\s+)?user|keep\s+this\s+(?:secret|hidden|between\s+us))`)
	nounRe     = regexp.MustCompile(`^(?:(?:passwords?|credentials|tokens?|api\s+keys?|secrets?|ssh\s+key|private\s+key|private\s+repo(?:sitory)?|contents\s+of)\b|\.env\b|id_rsa)`)

	// addressedRe is unanchored: it needs a line or sentence start before the hit.
	addressedRe = regexp.MustCompile(`(?im)(?:^|[.!?]\s+)[\s<!\-#*>/]*(?:(?:dear|attention|hey|note\s+to)\s+|important[:,]?\s+)?(?:ai\s+)?(?:ai|assistant|agent|llm|model|claude|chatgpt|copilot|cursor)s?\s*[,:]|<important>|<system>|\[system\]|###\s*system`)
)

type kind int

const (
	kVerb kind = iota
	kNoun
	kURL
	kOverride
	kRole
	kSecrecy
	kAddressed
	kSensitive
	numKinds
)

// A trailing "*" lets the word continue with more word bytes; a leading "~"
// drops the check for a word boundary on its left.
var keywords = map[kind][]string{
	kVerb:      {"send", "post", "upload", "forward", "email", "exfiltrate", "leak", "transmit", "curl"},
	kNoun:      {"password*", "credentials*", "token*", "api*", "secret*", "ssh*", "private*", "contents*", "~.env*", "~id_rsa*"},
	kURL:       {"~http://*", "~https://*"},
	kOverride:  {"ignore", "disregard", "forget", "new", "override"},
	kRole:      {"you", "from", "act", "system", "developer", "jailbreak", "dan"},
	kSecrecy:   {"do", "don*", "never", "without", "keep"},
	kAddressed: {"ai*", "assistant*", "agent*", "llm*", "model*", "claude*", "chatgpt*", "copilot*", "cursor*", "important*", "system*"},
	kSensitive: {".ssh", "id_rsa*", "id_ed25519*", ".env", "mcp.json", ".aws", ".netrc"},
}

type word struct {
	text        string
	kind        kind
	loose, free bool
}

var byFirst = func() (t [256][]word) {
	for k, ws := range keywords {
		for _, w := range ws {
			x := word{kind: k}
			if strings.HasPrefix(w, "~") {
				x.free, w = true, w[1:]
			}
			if strings.HasSuffix(w, "*") {
				x.loose, w = true, w[:len(w)-1]
			}
			x.text = w
			t[w[0]] = append(t[w[0]], x)
		}
	}
	return
}()

type span struct{ start, end int }

// scan holds the lowercased text and, per kind, the sorted spans of keyword hits.
type scan struct {
	lower string
	hits  [numKinds][]span
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func scanKeywords(lower string) *scan {
	s := &scan{lower: lower}
	for i := 0; i < len(lower); i++ {
		ws := byFirst[lower[i]]
		if len(ws) == 0 {
			continue
		}
		leftOK := i == 0 || !isWord(lower[i-1])
		for _, w := range ws {
			e := i + len(w.text)
			if !strings.HasPrefix(lower[i:], w.text) || !w.free && !leftOK || !w.loose && e < len(lower) && isWord(lower[e]) {
				continue
			}
			s.hits[w.kind] = append(s.hits[w.kind], span{i, e})
		}
	}
	return s
}

type signal struct {
	name   string
	weight int // in tool output (Score)
	tool   int // in a tool definition (ScoreTool)
	match  func(text string, s *scan) bool
}

// Kept in name order so Signals comes out sorted.
var signals = []signal{
	{"addressed", 2, 3, func(text string, s *scan) bool {
		var hits []span
		for _, h := range s.hits[kAddressed] {
			if addressedHit(text, h) {
				hits = append(hits, h)
			}
		}
		for _, w := range addressedWindows(text, hits) {
			if addressedRe.MatchString(text[w.start:w.end]) {
				return true
			}
		}
		return false
	}},
	{"base64", 1, 1, func(text string, _ *scan) bool { return hasBase64Run(text) }},
	{"exfil", 2, 2, func(text string, s *scan) bool {
		n := nouns(s.lower, s.hits[kNoun])
		return near(text, s.hits[kVerb], n) || near(text, n, s.hits[kVerb])
	}},
	{"hidden-unicode", 3, 3, func(text string, _ *scan) bool { return hasHiddenUnicode(text) }},
	{"override", 3, 3, func(text string, s *scan) bool { return anyMatchAt(overrideRe, text, s.hits[kOverride], matchLen) }},
	{"role", 2, 2, func(text string, s *scan) bool { return anyMatchAt(roleRe, text, s.hits[kRole], matchLen) }},
	{"secrecy", 2, 3, func(text string, s *scan) bool { return anyMatchAt(secrecyRe, text, s.hits[kSecrecy], matchLen) }},
	// a description that names secret files is asking the model to read them; in tool output it is just a listing
	{"sensitive-file", 0, 3, func(_ string, s *scan) bool { return len(s.hits[kSensitive]) > 0 }},
	{"url-send", 1, 1, func(text string, s *scan) bool {
		return near(text, s.hits[kVerb], s.hits[kURL]) || near(text, s.hits[kURL], s.hits[kVerb])
	}},
}

// Score rates text. It is pure, safe for concurrent use, and linear in len(text).
func Score(text string) Result { return score(text, false) }

// ScoreTool rates a tool definition (name, description, schema). A description
// talks to the model by design, so hiding things from the user, <IMPORTANT>-style
// tags and secret file paths weigh more here than in tool output.
func ScoreTool(text string) Result { return score(text, true) }

func score(text string, tool bool) Result {
	s := scanKeywords(lowerASCII(text))
	var r Result
	for _, sg := range signals {
		w := sg.weight
		if tool {
			w = sg.tool
		}
		if w > 0 && sg.match(text, s) {
			r.Score += w
			r.Signals = append(r.Signals, sg.name)
		}
	}
	return r
}

// lowerASCII lowercases A-Z only: strings.ToLower can change byte length, and
// offsets found in the lowercase copy must index the original text.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// matchAt runs an anchored re on at most n bytes from start. A match touching
// the cut has not seen its right-hand word boundary, so it does not count.
func matchAt(re *regexp.Regexp, text string, start, n int) (end int, ok bool) {
	cut := min(start+n, len(text))
	loc := re.FindStringIndex(text[start:cut])
	if loc == nil || loc[1] == cut-start && cut < len(text) {
		return 0, false
	}
	return start + loc[1], true
}

func anyMatchAt(re *regexp.Regexp, text string, hits []span, n int) bool {
	for _, h := range hits {
		if _, ok := matchAt(re, text, h.start, n); ok {
			return true
		}
	}
	return false
}

// nouns confirms noun candidates with nounRe, keeping their end offsets.
func nouns(lower string, cands []span) []span {
	var out []span
	for _, c := range cands {
		if end, ok := matchAt(nounRe, lower, c.start, nounLen); ok {
			out = append(out, span{c.start, end})
		}
	}
	return out
}

// near reports whether some y starts at most maxGap characters after some x
// ends. Characters, not bytes: "." in the reference patterns is a rune. The
// first y after an x is the closest, so one binary search per x suffices.
func near(text string, xs, ys []span) bool {
	for _, x := range xs {
		i, _ := slices.BinarySearchFunc(ys, x.end, func(y span, end int) int { return cmp.Compare(y.start, end) })
		if i == len(ys) {
			continue
		}
		gap := ys[i].start - x.end
		if gap <= maxGap || gap <= 4*maxGap && utf8.RuneCountInString(text[x.end:ys[i].start]) <= maxGap {
			return true
		}
	}
	return false
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// addressedHit is a cheap filter: it keeps hits followed by the "," or ":" (or a
// closing tag bracket) addressedRe needs, or preceded by "###".
func addressedHit(text string, h span) bool {
	e := h.end
	if e < len(text) && (text[e] == 's' || text[e] == 'S') {
		e++
	}
	for e < len(text) && isSpace(text[e]) {
		e++
	}
	if e < len(text) && strings.IndexByte(",:>]", text[e]) >= 0 {
		return true
	}
	k := h.start
	for k > 0 && isSpace(text[k-1]) {
		k--
	}
	return k >= 3 && text[k-3:k] == "###"
}

// addressedWindows turns hits into merged ranges of text. Each starts at a line
// start when one is near, since a cut mid-line would fake a (?m)^ match.
func addressedWindows(text string, hits []span) []span {
	var out []span
	for _, h := range hits {
		lo, hi := max(h.start-addrPre, 0), min(h.end+addrPost, len(text))
		if base := max(lo-addrSnap, 0); lo > 0 {
			if i := strings.LastIndexByte(text[base:lo], '\n'); i >= 0 {
				lo = base + i + 1
			}
		}
		if n := len(out); n > 0 && lo <= out[n-1].end {
			out[n-1].start, out[n-1].end = min(out[n-1].start, lo), max(out[n-1].end, hi)
			continue
		}
		out = append(out, span{lo, hi})
	}
	return out
}

var base64Byte = func() (t [256]bool) {
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		t[c] = true
	}
	return
}()

func hasBase64Run(text string) bool {
	run := 0
	for i := 0; i < len(text); i++ {
		if !base64Byte[text[i]] {
			run = 0
		} else if run++; run >= 200 {
			return true
		}
	}
	return false
}

func hasHiddenUnicode(text string) bool {
	for i := 0; i < len(text); {
		if text[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(text[i:])
		switch {
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E,
			r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069,
			r >= 0xE0000 && r <= 0xE007F:
			return true
		case r == 0xFEFF && i > 0:
			return true
		}
		i += n
	}
	return false
}
