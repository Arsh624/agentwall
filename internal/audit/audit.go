package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one line of the log.
type Entry struct {
	TS       string `json:"ts"`
	Chain    string `json:"chain"`
	Session  string `json:"session"`
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	ArgsHash string `json:"args_hash"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Log appends entries to a shared file as one private hash chain.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	chain string
	last  string
}

// Open opens the log at path for appending and starts a new chain.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		f.Close()
		return nil, err
	}
	return &Log{f: f, chain: hex.EncodeToString(id)}, nil
}

func hashEntry(e Entry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Append fills TS, Chain, PrevHash and Hash, and writes the entry as one line.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	e.Chain = l.chain
	e.PrevHash = l.last
	h, err := hashEntry(e)
	if err != nil {
		return err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	l.last = h
	return nil
}

func (l *Log) Close() error { return l.f.Close() }

// HashArgs returns the hex SHA-256 of raw.
func HashArgs(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// walk calls fn for every line (1-based) of the file; a missing file has none.
func walk(path string, fn func(n int, line []byte) error) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for n := 1; ; n++ {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if ferr := fn(n, bytes.TrimSuffix(line, []byte("\n"))); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func parse(line []byte) (Entry, error) {
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	if dec.More() {
		return e, errors.New("trailing data")
	}
	return e, nil
}

// Read returns every entry in the file, in file order.
func Read(path string) ([]Entry, error) {
	var es []Entry
	err := walk(path, func(n int, line []byte) error {
		e, err := parse(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		es = append(es, e)
		return nil
	})
	return es, err
}

// Verify checks every chain in the file and returns the number of entries checked.
func Verify(path string) (int, error) {
	last := map[string]string{}
	count := 0
	err := walk(path, func(n int, line []byte) error {
		e, err := parse(line)
		if err != nil {
			return fmt.Errorf("line %d: invalid entry: %w", n, err)
		}
		h, err := hashEntry(e)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		if h != e.Hash {
			return fmt.Errorf("line %d: hash mismatch", n)
		}
		if e.PrevHash != last[e.Chain] {
			return fmt.Errorf("line %d: prev_hash does not match previous entry of chain %s", n, e.Chain)
		}
		last[e.Chain] = e.Hash
		count++
		return nil
	})
	return count, err
}
