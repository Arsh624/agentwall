// Package vault stores secrets and redacts them from output.
//
// Secrets live in the OS keychain. When AGENTWALL_PASSPHRASE is set (servers,
// containers, CI: places with no keychain) they live in an AES-256-GCM file
// keyed from that passphrase instead.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/zalando/go-keyring"
)

// PassphraseEnv selects the encrypted-file backend and keys it.
const PassphraseEnv = "AGENTWALL_PASSPHRASE"

var ErrNotFound = errors.New("vault: no such secret")

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type backend interface {
	load() (map[string]string, error) // every secret by name
	set(name, value string) error
}

type Vault struct{ b backend }

// Open picks the backend; it does no I/O.
func Open(stateDir string) *Vault {
	if pass := os.Getenv(PassphraseEnv); pass != "" {
		return &Vault{&fileBackend{path: filepath.Join(stateDir, "vault.enc"), passphrase: pass}}
	}
	return &Vault{keychain{}}
}

func (v *Vault) Set(name, value string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("vault: secret name %q may only use letters, digits, '.', '_' and '-'", name)
	}
	if value == "" {
		return errors.New("vault: empty secret value")
	}
	return v.b.set(name, value)
}

func (v *Vault) Get(name string) (string, error) {
	all, err := v.b.load()
	if err != nil {
		return "", err
	}
	value, ok := all[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return value, nil
}

// List returns the secret names, sorted.
func (v *Vault) List() ([]string, error) {
	all, err := v.b.load()
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, err
}

// All returns every secret by name (the redactor needs the values).
func (v *Vault) All() (map[string]string, error) { return v.b.load() }

// keychain keeps one entry per secret, plus an index entry because keychains cannot list.
type keychain struct{}

const (
	service  = "agentwall"
	indexKey = "index:names" // ':' is not allowed in secret names, so it cannot collide
)

func (keychain) names() ([]string, error) {
	idx, err := keyring.Get(service, indexKey)
	if errors.Is(err, keyring.ErrNotFound) || idx == "" {
		return nil, nil
	}
	return strings.Split(idx, "\n"), err
}

func (k keychain) load() (map[string]string, error) {
	names, err := k.names()
	all := map[string]string{}
	for _, n := range names {
		if all[n], err = keyring.Get(service, n); err != nil {
			return nil, err
		}
	}
	return all, err
}

func (k keychain) set(name, value string) error {
	if err := keyring.Set(service, name, value); err != nil {
		return err
	}
	names, err := k.names()
	if err != nil || slices.Contains(names, name) {
		return err
	}
	return keyring.Set(service, indexKey, strings.Join(append(names, name), "\n"))
}

// fileBackend keeps all secrets in one encrypted JSON file.
type fileBackend struct{ path, passphrase string }

var kdfIterations = 600_000 // PBKDF2-HMAC-SHA256, OWASP's 2023 figure

type sealed struct {
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

func (f *fileBackend) aead(salt []byte, iter int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, f.passphrase, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (f *fileBackend) load() (map[string]string, error) {
	secrets := map[string]string{}
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return secrets, nil
	}
	if err != nil {
		return nil, err
	}
	var s sealed
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("vault: %s is damaged: %w", f.path, err)
	}
	aead, err := f.aead(s.Salt, s.Iter)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, s.Nonce, s.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: cannot decrypt %s: wrong %s, or the file was modified", f.path, PassphraseEnv)
	}
	return secrets, json.Unmarshal(plain, &secrets)
}

func (f *fileBackend) set(name, value string) error {
	secrets, err := f.load() // also proves the passphrase before anything is overwritten
	if err != nil {
		return err
	}
	secrets[name] = value
	plain, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	s := sealed{KDF: "pbkdf2-hmac-sha256", Iter: kdfIterations, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	rand.Read(s.Salt) // fresh salt and nonce on every save; crypto/rand.Read never fails
	rand.Read(s.Nonce)
	aead, err := f.aead(s.Salt, s.Iter)
	if err != nil {
		return err
	}
	s.Data = aead.Seal(nil, s.Nonce, plain, nil)
	out, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path) // atomic: a crash never leaves half a vault
}
