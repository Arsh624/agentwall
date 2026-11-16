package flow

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var wordRE = regexp.MustCompile(`[\p{L}\p{Nd}]+`)

// naive hashes every N-word window from scratch; the rolling version must agree.
func naive(text string) []uint64 {
	words := wordRE.FindAllString(strings.ToLower(text), -1)
	var out []uint64
	for i := 0; i+N <= len(words); i++ {
		var h uint64
		for _, w := range words[i : i+N] {
			f := fnv.New64a()
			f.Write([]byte(w))
			h = h*base + f.Sum64()
		}
		out = append(out, h)
	}
	return out
}

func TestRollingHashMatchesNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	vocab := strings.Fields("alpha beta gamma delta épsilon ζήτα 42 x y1 The QUICK brown-fox")
	for i := 0; i < 200; i++ {
		var b strings.Builder
		for n := rng.Intn(40); n > 0; n-- {
			b.WriteString(vocab[rng.Intn(len(vocab))])
			b.WriteString([]string{" ", "\n", ", ", "--", "\t(", " "}[rng.Intn(6)])
		}
		if got, want := Fingerprints(b.String()), naive(b.String()); !reflect.DeepEqual(got, want) {
			t.Fatalf("text %q:\n got %v\nwant %v", b.String(), got, want)
		}
	}
}

func TestFingerprintWindows(t *testing.T) {
	seven := "one two three four five six seven"
	if got := Fingerprints(seven); len(got) != 0 {
		t.Fatalf("%d words must give no fingerprint, got %d", N-1, len(got))
	}
	if got := Fingerprints(seven + " eight"); len(got) != 1 {
		t.Fatalf("%d words must give one fingerprint, got %d", N, len(got))
	}
	if got := Fingerprints(seven + " eight nine ten"); len(got) != 3 {
		t.Fatalf("want 3 windows, got %d", len(got))
	}
	a := Fingerprints("The quick brown fox jumps over the lazy dog")
	b := Fingerprints("the QUICK   brown\nfox, jumps; over (the) lazy... dog!")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("case, spacing and punctuation must not change fingerprints")
	}
	c := Fingerprints("the quick brown fox jumps over the lazy cat")
	if a[0] != c[0] || a[1] == c[1] {
		t.Fatal("a changed word must change exactly the windows that contain it")
	}
}

func TestStrings(t *testing.T) {
	got := Strings([]byte(`{"content":[{"type":"text","text":"hello"}],"n":5,"nested":{"k":["a",{"b":"c"}]},"ok":true}`))
	want := map[string]bool{"text": true, "hello": true, "a": true, "c": true}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for _, s := range got {
		if !want[s] {
			t.Fatalf("unexpected string %q in %q", s, got)
		}
	}
	if Strings([]byte(`not json`)) != nil || Strings(nil) != nil {
		t.Fatal("invalid or empty JSON has no strings")
	}
}

// doc returns 20 words nobody else uses: 13 fingerprints.
func doc(i int) string {
	var b strings.Builder
	for w := 0; w < 20; w++ {
		fmt.Fprintf(&b, "doc%dword%d ", i, w)
	}
	return b.String()
}

const private = "Q3 revenue forecast is 4.2 million dollars and the acquisition of Initech closes on Friday pending board approval"

func mustContain(t *testing.T, s *Store, want bool, text string) {
	t.Helper()
	got, err := s.Contains(text)
	if err != nil || got != want {
		t.Fatalf("Contains(%q) = %v, %v; want %v", text, got, err, want)
	}
}

func TestStoreRecognisesPrivateText(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "fingerprints"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustContain(t, s, false, private)
	if err := s.Add(private); err != nil {
		t.Fatal(err)
	}
	mustContain(t, s, true, private)
	mustContain(t, s, true, "## Summary\nfyi: the ACQUISITION of initech closes on friday, pending board approval!! thanks")
	mustContain(t, s, false, "Fix the flaky login test by waiting for the session cookie before asserting on the redirect")
	mustContain(t, s, false, "acquisition of Initech closes on Friday pending") // 7 shared words: below one window
	mustContain(t, s, false, "")
}

func TestStorePersistsAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprints")
	s, _ := OpenStore(path)
	s.Add(private)
	s.Close()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustContain(t, s, true, private)
}

func TestStoreIsSharedBetweenProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprints")
	files, _ := OpenStore(path) // the filesystem server's agentwall
	fetch, _ := OpenStore(path) // the fetch server's agentwall, already running
	defer files.Close()
	defer fetch.Close()
	mustContain(t, fetch, false, private)
	files.Add(private)
	mustContain(t, fetch, true, private)
}

func TestStoreIsCapped(t *testing.T) {
	old := maxPrints
	maxPrints = 100
	defer func() { maxPrints = old }()

	path := filepath.Join(t.TempDir(), "fingerprints")
	s, _ := OpenStore(path)
	defer s.Close()
	text := doc
	for i := 0; i < 50; i++ {
		if err := s.Add(text(i)); err != nil {
			t.Fatal(err)
		}
	}
	fi, _ := os.Stat(path)
	if fi.Size() > 8+int64(maxPrints+13)*8 {
		t.Fatalf("store grew to %d bytes, cap is %d fingerprints", fi.Size(), maxPrints)
	}
	mustContain(t, s, true, text(49)) // newest kept
	mustContain(t, s, false, text(0)) // oldest evicted

	other, _ := OpenStore(path) // a process that opens after the compaction agrees
	defer other.Close()
	mustContain(t, other, true, text(49))
	mustContain(t, other, false, text(0))
}

func TestStoreSurvivesCompactionByAnotherProcess(t *testing.T) {
	old := maxPrints
	maxPrints = 100
	defer func() { maxPrints = old }()

	path := filepath.Join(t.TempDir(), "fingerprints")
	a, _ := OpenStore(path)
	b, _ := OpenStore(path)
	defer a.Close()
	defer b.Close()
	a.Add(private)
	mustContain(t, b, true, private) // b has now read up to the end of the file
	for i := 0; i < 60; i++ {        // a overflows the cap and rewrites the file
		a.Add(doc(i))
	}
	b.Add("fresh private text that the second process learns after the file was rewritten")
	mustContain(t, a, true, "fresh private text that the second process learns after the file was rewritten")
	mustContain(t, b, false, private) // evicted for everyone
}
