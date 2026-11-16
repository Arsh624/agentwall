package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func entry(tool, decision string) Entry {
	return Entry{Session: "s1", Server: "fs", Tool: tool, ArgsHash: HashArgs([]byte(`{}`)), Decision: decision, Reason: "r"}
}

func writeLog(t *testing.T, decisions ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range decisions {
		if err := l.Append(entry("read", d)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppendVerifyRead(t *testing.T) {
	path := writeLog(t, "allow", "deny", "allow")
	n, err := Verify(path)
	if err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	es, err := Read(path)
	if err != nil || len(es) != 3 {
		t.Fatalf("Read = %d, %v", len(es), err)
	}
	for i, e := range es {
		if e.TS == "" || e.Chain == "" || e.Hash == "" {
			t.Errorf("entry %d missing TS/Chain/Hash: %+v", i, e)
		}
		if i == 0 && e.PrevHash != "" {
			t.Errorf("first PrevHash = %q", e.PrevHash)
		}
		if i > 0 && e.PrevHash != es[i-1].Hash {
			t.Errorf("entry %d PrevHash mismatch", i)
		}
	}
	if len(es[0].Chain) != 16 {
		t.Errorf("chain id %q not 16 chars", es[0].Chain)
	}
}

func TestTamper(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(lines []string) []string
		wantLine string
	}{
		{"edit field", func(l []string) []string {
			l[1] = strings.Replace(l[1], `"allow"`, `"deny!"`, 1)
			return l
		}, "line 2"},
		{"delete middle", func(l []string) []string { return []string{l[0], l[2]} }, "line 2"},
		{"swap lines", func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }, "line 2"},
		{"garbage", func(l []string) []string { return append(l, "not json") }, "line 4"},
		{"blank line", func(l []string) []string { return []string{l[0], "", l[1], l[2]} }, "line 2"},
		{"unknown field", func(l []string) []string {
			l[0] = strings.Replace(l[0], `{"ts"`, `{"extra":1,"ts"`, 1)
			return l
		}, "line 1"},
		{"swap hash", func(l []string) []string {
			e, _ := parseLine(l[1])
			l[1] = strings.Replace(l[1], e.Hash, strings.Repeat("ab", 32), 1)
			return l
		}, "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeLog(t, "allow", "allow", "allow")
			writeLines(t, path, tt.mutate(readLines(t, path)))
			_, err := Verify(path)
			if err == nil {
				t.Fatal("tampering not detected")
			}
			if !strings.Contains(err.Error(), tt.wantLine) {
				t.Errorf("error %q does not mention %q", err, tt.wantLine)
			}
		})
	}
}

func TestTwoChains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := Open(path)
	b, _ := Open(path)
	for i := 0; i < 3; i++ {
		if err := a.Append(entry("a", "allow")); err != nil {
			t.Fatal(err)
		}
		if err := b.Append(entry("b", "allow")); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	b.Close()
	if n, err := Verify(path); err != nil || n != 6 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	lines := readLines(t, path)
	lines[2] = strings.Replace(lines[2], `"allow"`, `"deny!"`, 1)
	writeLines(t, path, lines)
	if _, err := Verify(path); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err = %v, want line 3", err)
	}
}

func TestReopen(t *testing.T) {
	path := writeLog(t, "allow")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(entry("x", "allow")); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if n, err := Verify(path); err != nil || n != 2 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	es, _ := Read(path)
	if es[0].Chain == es[1].Chain {
		t.Error("reopen reused chain id")
	}
}

func TestConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := l.Append(entry("t", "allow")); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	l.Close()
	if n, err := Verify(path); err != nil || n != 400 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.jsonl")
	if n, err := Verify(path); n != 0 || err != nil {
		t.Errorf("Verify = %d, %v", n, err)
	}
	if es, err := Read(path); es != nil || err != nil {
		t.Errorf("Read = %v, %v", es, err)
	}
}

func TestOpenCreatesDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestLongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	e := entry("t", "allow")
	e.Reason = strings.Repeat("x", 200_000)
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if n, err := Verify(path); err != nil || n != 1 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestHashArgs(t *testing.T) {
	if HashArgs([]byte("a")) != HashArgs([]byte("a")) {
		t.Error("not stable")
	}
	if HashArgs([]byte("a")) == HashArgs([]byte("b")) {
		t.Error("collision")
	}
	if len(HashArgs(nil)) != 64 {
		t.Error("want 64 hex chars")
	}
}

func parseLine(line string) (Entry, error) {
	var e Entry
	err := json.Unmarshal([]byte(line), &e)
	return e, err
}
