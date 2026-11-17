// Package session tracks taint labels per agent session.
//
// An agent runs one agentwall process per MCP server, and an attack usually
// spans servers, so taint lives in marker files every process can see:
// <state>/sessions/<id>/<taint>. Taint is only ever added, which is why plain
// files need no locking.
package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Taint string

const (
	Untrusted Taint = "untrusted" // the session read content a stranger could have written
	Private   Taint = "private"   // the session read private data
)

type Session struct {
	id, dir string
	mu      sync.Mutex
	seen    map[Taint]bool // taint never goes away, so a positive answer can be cached
}

// Open joins (or starts) the session id under stateDir.
// shortcut: the default id is the parent pid, which the OS can reuse, so a new agent may inherit old taint
// (fails closed; delete <state>/sessions to reset). Add the parent's start time to the id if that bites.
func Open(stateDir, id string) (*Session, error) {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, id)
	dir := filepath.Join(stateDir, "sessions", safe)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Session{id: id, dir: dir, seen: map[Taint]bool{}}, nil
}

func (s *Session) ID() string { return s.id }

// Add marks the session and reports whether the taint is new.
func (s *Session) Add(t Taint) (added bool, err error) {
	if s.Has(t) {
		return false, nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, string(t)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) { // another process got there first
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, f.Close()
}

func (s *Session) Has(t Taint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.seen[t] {
		_, err := os.Stat(filepath.Join(s.dir, string(t)))
		s.seen[t] = err == nil
	}
	return s.seen[t]
}
