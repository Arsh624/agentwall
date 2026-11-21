package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
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
	MAC      string `json:"mac,omitempty"` // HMAC-SHA256 of Hash under the audit key; empty when written without one
}

// Log appends entries to a shared file as one private hash chain.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	chain string
	last  string
	key   []byte // nil: entries are not signed
}

// Open opens the log at path for appending and starts a new, unsigned chain.
func Open(path string) (*Log, error) { return OpenSigned(path, nil) }

// OpenSigned is Open with every entry signed under key, so that someone who can
// write the file but has no key cannot rebuild a chain that verifies.
func OpenSigned(path string, key []byte) (*Log, error) {
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
	return &Log{f: f, chain: hex.EncodeToString(id), key: key}, nil
}

func hashEntry(e Entry) (string, error) {
	e.Hash, e.MAC = "", ""
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
	if l.key != nil {
		e.MAC = mac(l.key, h)
	}
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

func mac(key []byte, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hash))
	return hex.EncodeToString(m.Sum(nil))
}

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

// Verify checks every hash chain in the file and returns the number of entries checked.
// It does not check signatures.
func Verify(path string) (int, error) {
	n, _, err := VerifySigned(path, nil)
	return n, err
}

// VerifySigned is Verify that also checks signatures under key (nil: none are checked).
// A chain written without a key (older logs, no vault) is counted in unsigned, not failed;
// a chain that has any signed entry must be signed throughout.
func VerifySigned(path string, key []byte) (entries, unsigned int, err error) {
	last := map[string]string{}
	signed := map[string]bool{} // chain → its first entry was signed
	count := 0
	err = walk(path, func(n int, line []byte) error {
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
		if key != nil {
			if e.PrevHash == "" {
				signed[e.Chain] = e.MAC != ""
			}
			switch {
			case e.MAC == "" && signed[e.Chain]:
				return fmt.Errorf("line %d: unsigned entry in signed chain %s", n, e.Chain)
			case e.MAC == "":
				unsigned++
			case !hmac.Equal([]byte(e.MAC), []byte(mac(key, e.Hash))):
				return fmt.Errorf("line %d: bad signature (forged, or signed with another key)", n)
			}
		}
		last[e.Chain] = e.Hash
		count++
		return nil
	})
	return count, unsigned, err
}
