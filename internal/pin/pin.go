// Package pin stores tool hashes to detect changed tools.
package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

type Status int

const (
	New     Status = iota // first time this tool is seen: it is now pinned (trust on first use)
	Same                  // matches its pin
	Changed               // differs from its pin; the new hash is stored as "pending" until approved
)

var ErrNothingPending = errors.New("pin: no pending change for this tool")

type entry struct {
	Hash    string `json:"hash"`
	Pending string `json:"pending,omitempty"`
}

// Store keeps one pin file per server in a directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open returns a store that keeps one file per server in dir (it does no I/O).
func Open(dir string) *Store { return &Store{dir: dir} }

func name(tool json.RawMessage) (n, hash string, err error) {
	dec := json.NewDecoder(bytes.NewReader(tool))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", "", fmt.Errorf("pin: bad tool: %w", err)
	}
	m, _ := v.(map[string]any)
	n, _ = m["name"].(string)
	if n == "" {
		return "", "", errors.New("pin: tool must be an object with a non-empty string name")
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(canon)
	return n, hex.EncodeToString(sum[:]), nil
}

// Hash returns the hex SHA-256 of the canonical JSON of a whole tool definition.
func Hash(tool json.RawMessage) (string, error) {
	_, h, err := name(tool)
	return h, err
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func (s *Store) path(server string) string {
	return filepath.Join(s.dir, unsafeName.ReplaceAllString(server, "_")+".json")
}

func (s *Store) load(server string) (map[string]*entry, error) {
	pins := map[string]*entry{}
	b, err := os.ReadFile(s.path(server))
	if errors.Is(err, os.ErrNotExist) {
		return pins, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, fmt.Errorf("pin: %s: %w", s.path(server), err)
	}
	return pins, nil
}

func (s *Store) save(server string, pins map[string]*entry) error {
	b, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".pin-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), s.path(server))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// Check compares a server's advertised tools with their pins and returns one Status per tool, in order.
// New tools are pinned; changed tools get their new hash recorded as pending. One load and at most one save per call.
func (s *Store) Check(server string, tools []json.RawMessage) ([]Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load(server)
	if err != nil {
		return nil, err
	}
	out := make([]Status, len(tools))
	dirty := false
	for i, t := range tools {
		n, h, err := name(t)
		if err != nil {
			return nil, err
		}
		e := pins[n]
		switch {
		case e == nil:
			pins[n] = &entry{Hash: h}
			out[i], dirty = New, true
		case e.Hash == h:
			out[i] = Same
			if e.Pending != "" {
				e.Pending, dirty = "", true
			}
		default:
			out[i] = Changed
			if e.Pending != h {
				e.Pending, dirty = h, true
			}
		}
	}
	if dirty {
		return out, s.save(server, pins)
	}
	return out, nil
}

// Distrust withdraws trust from a pinned tool: its definition becomes pending,
// so it reads as Changed until Approve.
func (s *Store) Distrust(server, tool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load(server)
	if err != nil {
		return err
	}
	e := pins[tool]
	if e == nil || e.Hash == "" {
		return nil // nothing trusted to withdraw
	}
	e.Hash, e.Pending = "", e.Hash
	return s.save(server, pins)
}

// Names returns the sorted names of the tools pinned for a server.
func (s *Store) Names(server string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load(server)
	return slices.Sorted(maps.Keys(pins)), err
}

// Others returns the servers other than server that have pins, by their file names.
func (s *Store) Others(server string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	var names []string
	for _, f := range files {
		if f != s.path(server) {
			names = append(names, strings.TrimSuffix(filepath.Base(f), ".json"))
		}
	}
	return names, err
}

// Approve makes the pending definition of server/tool the pinned one.
func (s *Store) Approve(server, tool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := s.load(server)
	if err != nil {
		return err
	}
	e := pins[tool]
	if e == nil || e.Pending == "" {
		return fmt.Errorf("%w: %s/%s", ErrNothingPending, server, tool)
	}
	e.Hash, e.Pending = e.Pending, ""
	return s.save(server, pins)
}
