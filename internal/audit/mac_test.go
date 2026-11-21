package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var key = []byte("test-audit-key-0123456789abcdef")

func writeSigned(t *testing.T, path string, k []byte, reasons ...string) {
	t.Helper()
	l, err := OpenSigned(path, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reasons {
		if err := l.Append(Entry{Tool: "t", Decision: "allow", Reason: r}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
}

func TestSignedEntriesVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSigned(t, path, key, "a", "b")
	if n, unsigned, err := VerifySigned(path, key); err != nil || n != 2 || unsigned != 0 {
		t.Fatalf("n=%d unsigned=%d err=%v", n, unsigned, err)
	}
	if _, _, err := VerifySigned(path, []byte("wrong key")); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("a wrong key must fail: %v", err)
	}
	if n, err := Verify(path); err != nil || n != 2 {
		t.Fatalf("without a key the hash chain still verifies: %d %v", n, err)
	}
}

// Someone who can write the file but has no key rebuilds a valid-looking chain.
func TestForgedChainIsCaught(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSigned(t, path, key, "deny: lethal trifecta")
	es, _ := Read(path)
	forged := es[0]
	forged.Reason = "allow: nothing to see"
	forged.Hash, _ = hashEntry(forged) // recompute the hash; the MAC cannot be recomputed
	line, _ := json.Marshal(forged)
	os.WriteFile(path, append(line, '\n'), 0o600)
	if _, _, err := VerifySigned(path, key); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("an edited signed entry must fail: %v", err)
	}

	// dropping the MAC is a downgrade inside a signed chain
	writeSigned(t, path, key, "x", "y")
	es, _ = Read(path)
	es[len(es)-1].MAC = ""
	var out []byte
	for _, e := range es {
		b, _ := json.Marshal(e)
		out = append(append(out, b...), '\n')
	}
	os.WriteFile(path, out, 0o600)
	if _, _, err := VerifySigned(path, key); err == nil {
		t.Fatal("an unsigned entry in a signed chain must fail")
	}
}

// Logs written before v0.2, or without a vault, have whole unsigned chains: counted, not failed.
func TestUnsignedChainsAreCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeSigned(t, path, nil, "old 1", "old 2")
	writeSigned(t, path, key, "new")
	if n, unsigned, err := VerifySigned(path, key); err != nil || n != 3 || unsigned != 2 {
		t.Fatalf("n=%d unsigned=%d err=%v", n, unsigned, err)
	}
}
