// Package flow fingerprints private data so it can be recognised when it is
// about to leave through an egress tool, even in a later session.
//
// A fingerprint is a 64-bit Rabin-Karp rolling hash of N consecutive words.
// Words are lowercased letters and digits, so reformatting does not hide a
// copy. Shorter secrets (one token) and re-encoded text (base64) are out of
// reach: the taint rule and the vault's redaction cover those.
package flow

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"unicode"
	"unicode/utf8"
)

// N is the number of words in one fingerprint.
const N = 8

const (
	fnvOffset = 14695981039346656037
	fnvPrime  = 1099511628211
	base      = 0x9E3779B97F4A7C15 // multiplier of the rolling polynomial, arithmetic is mod 2^64
)

// maxPrints caps the store; past it the oldest half is dropped. 2^18 prints ≈ 1.5 MB of text, 2 MB on disk.
var maxPrints = 1 << 18

// Fingerprints returns the hash of every N-word window of text, in order.
func Fingerprints(text string) []uint64 {
	pow := uint64(1) // base^(N-1): the weight of the oldest word in a window
	for i := 1; i < N; i++ {
		pow *= base
	}
	var (
		out    []uint64
		ring   [N]uint64 // hashes of the last N words
		h      uint64
		n      int    // words seen
		word   uint64 = fnvOffset
		inWord bool
		buf    [utf8.UTFMax]byte
	)
	endWord := func() {
		if !inWord {
			return
		}
		if n >= N {
			h -= ring[n%N] * pow // the word sliding out of the window
		}
		h = h*base + word
		ring[n%N] = word
		if n++; n >= N {
			out = append(out, h)
		}
		word, inWord = fnvOffset, false
	}
	for _, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			endWord()
			continue
		}
		for _, b := range buf[:utf8.EncodeRune(buf[:], unicode.ToLower(r))] { // FNV-1a of the word's bytes
			word = (word ^ uint64(b)) * fnvPrime
		}
		inWord = true
	}
	endWord()
	return out
}

// Strings returns every string value inside a JSON document (nil if it is not JSON).
func Strings(raw []byte) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(v)
	return out
}

// Store remembers fingerprints of private text in a file shared by every
// agentwall process: an 8-byte generation followed by 8-byte fingerprints,
// oldest first. Processes append to it and read each other's appends.
type Store struct {
	mu   sync.Mutex
	path string
	f    *os.File
	set  map[uint64]struct{}
	gen  uint64 // generation of the file that set mirrors; a compaction changes it
	off  int64  // how far into the file set has read
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, f: f}
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		f.Write(newGen())
	}
	if err := s.sync(); err != nil {
		f.Close()
		return nil, err
	}
	if len(s.set) > maxPrints {
		if err := s.compact(); err != nil {
			f.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.f.Close() }

func newGen() []byte { return binary.LittleEndian.AppendUint64(nil, rand.Uint64()|1) } // never 0

// sync loads what other processes appended, or everything after a compaction.
func (s *Store) sync() error {
	var hdr [8]byte
	if _, err := s.f.ReadAt(hdr[:], 0); err != nil && err != io.EOF {
		return err
	}
	if gen := binary.LittleEndian.Uint64(hdr[:]); gen != s.gen || s.set == nil {
		s.set, s.gen, s.off = map[uint64]struct{}{}, gen, 8
	}
	fi, err := s.f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size() &^ 7
	if size <= s.off {
		return nil
	}
	buf := make([]byte, size-s.off)
	if _, err := s.f.ReadAt(buf, s.off); err != nil {
		return err
	}
	for ; len(buf) > 0; buf = buf[8:] {
		s.set[binary.LittleEndian.Uint64(buf)] = struct{}{}
	}
	s.off = size
	return nil
}

// Add remembers the fingerprints of private texts.
func (s *Store) Add(texts ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sync(); err != nil {
		return err
	}
	var buf []byte
	for _, t := range texts {
		for _, fp := range Fingerprints(t) {
			if _, ok := s.set[fp]; !ok {
				s.set[fp] = struct{}{}
				buf = binary.LittleEndian.AppendUint64(buf, fp)
			}
		}
	}
	if len(buf) == 0 {
		return nil
	}
	if _, err := s.f.Write(buf); err != nil { // one write: appends from other processes never interleave
		return err
	}
	if len(s.set) > maxPrints {
		return s.compact()
	}
	return nil
}

// Contains reports whether any N-word window of the texts was seen in private data.
func (s *Store) Contains(texts ...string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.sync(); err != nil {
		return false, err
	}
	for _, t := range texts {
		for _, fp := range Fingerprints(t) {
			if _, ok := s.set[fp]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// compact rewrites the file with the newest half of the cap under a new generation.
// shortcut: not atomic, a fingerprint another process appends during the rewrite is lost; lock the file if that matters.
func (s *Store) compact() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	prints := data[min(8, len(data)):]
	prints = prints[:len(prints)&^7]
	if keep := maxPrints / 2 * 8; len(prints) > keep {
		prints = prints[len(prints)-keep:]
	}
	if err := os.WriteFile(s.path, append(newGen(), prints...), 0o600); err != nil {
		return err
	}
	return s.sync()
}
