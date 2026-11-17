package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTaintIsStickyAndPerSession(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	if s.Has(Untrusted) || s.Has(Private) {
		t.Fatal("a new session must be clean")
	}
	if added, err := s.Add(Untrusted); err != nil || !added {
		t.Fatalf("first Add = %v, %v; want true, nil", added, err)
	}
	if added, err := s.Add(Untrusted); err != nil || added {
		t.Fatalf("second Add = %v, %v; want false, nil", added, err)
	}
	if !s.Has(Untrusted) || s.Has(Private) {
		t.Fatal("only the added taint must be set")
	}
	other, _ := Open(dir, "b")
	if other.Has(Untrusted) {
		t.Fatal("taint leaked into another session")
	}
}

// Each MCP server gets its own agentwall process; they must see each other's taint.
func TestTaintIsSharedBetweenProcessesOfOneSession(t *testing.T) {
	dir := t.TempDir()
	github, _ := Open(dir, "ppid-1")
	files, _ := Open(dir, "ppid-1")
	fetch, _ := Open(dir, "ppid-1")
	if fetch.Has(Untrusted) { // a negative answer must not be cached
		t.Fatal("clean session reported taint")
	}
	github.Add(Untrusted)
	files.Add(Private)
	if !fetch.Has(Untrusted) || !fetch.Has(Private) {
		t.Fatal("a process must see taint added by the others")
	}
}

func TestSessionIDCannotEscapeTheStateDir(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, `..\../evil:id`)
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Private)
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	if len(entries) != 1 || s.ID() != `..\../evil:id` {
		t.Fatalf("session must live in one directory under sessions/, got %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "sessions", entries[0].Name(), "private")); err != nil {
		t.Fatalf("marker not where expected: %v", err)
	}
}
