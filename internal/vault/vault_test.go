package vault

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	kdfIterations = 10 // the real count makes every open take a noticeable fraction of a second
	os.Exit(m.Run())
}

// both backends must behave the same
func backends(t *testing.T) map[string]*Vault {
	keyring.MockInit()
	t.Setenv(PassphraseEnv, "")
	kr := Open(t.TempDir())
	t.Setenv(PassphraseEnv, "correct horse")
	file := Open(t.TempDir())
	return map[string]*Vault{"keychain": kr, "encrypted file": file}
}

func TestSetGetList(t *testing.T) {
	for name, v := range backends(t) {
		t.Run(name, func(t *testing.T) {
			if names, err := v.List(); err != nil || len(names) != 0 {
				t.Fatalf("new vault: %v, %v", names, err)
			}
			if _, err := v.Get("github"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing secret: want ErrNotFound, got %v", err)
			}
			for k, val := range map[string]string{"github": "ghp_one", "slack": "xoxb-two", "a.b-c_d": "three"} {
				if err := v.Set(k, val); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.Set("github", "ghp_replaced"); err != nil {
				t.Fatal(err)
			}
			if got, err := v.Get("github"); err != nil || got != "ghp_replaced" {
				t.Fatalf("Get = %q, %v", got, err)
			}
			if names, err := v.List(); err != nil || !reflect.DeepEqual(names, []string{"a.b-c_d", "github", "slack"}) {
				t.Fatalf("List = %v, %v", names, err)
			}
			all, err := v.All()
			if err != nil || len(all) != 3 || all["slack"] != "xoxb-two" {
				t.Fatalf("All = %v, %v", all, err)
			}
		})
	}
}

func TestBadNamesAndValuesAreRejected(t *testing.T) {
	for name, v := range backends(t) {
		t.Run(name, func(t *testing.T) {
			for _, bad := range []string{"", "has space", "a/b", "index:names", "x\ny"} {
				if err := v.Set(bad, "value"); err == nil {
					t.Fatalf("name %q must be rejected", bad)
				}
			}
			if err := v.Set("empty", ""); err == nil {
				t.Fatal("an empty value must be rejected")
			}
		})
	}
}

func TestFileVaultIsEncryptedAndNeedsThePassphrase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(PassphraseEnv, "correct horse")
	if err := Open(dir).Set("github", "ghp_supersecretvalue"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ghp_supersecretvalue") || strings.Contains(string(raw), "github") {
		t.Fatalf("vault file leaks a secret or its name: %s", raw)
	}

	if got, err := Open(dir).Get("github"); err != nil || got != "ghp_supersecretvalue" { // a later process
		t.Fatalf("reopen: %q, %v", got, err)
	}
	t.Setenv(PassphraseEnv, "wrong")
	if _, err := Open(dir).Get("github"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("a wrong passphrase must be a clear error, got %v", err)
	}
	if err := Open(dir).Set("other", "value"); err == nil {
		t.Fatal("a wrong passphrase must not overwrite the vault")
	}

	// tampering is detected (AES-GCM authenticates)
	t.Setenv(PassphraseEnv, "correct horse")
	os.WriteFile(filepath.Join(dir, "vault.enc"), []byte(strings.Replace(string(raw), `"data":"`, `"data":"AAAA`, 1)), 0o600)
	if _, err := Open(dir).Get("github"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("a modified vault must not decrypt, got %v", err)
	}
}

func TestEachSaveUsesAFreshNonce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(PassphraseEnv, "pw")
	v := Open(dir)
	v.Set("a", "same value")
	first, _ := os.ReadFile(filepath.Join(dir, "vault.enc"))
	v.Set("a", "same value")
	second, _ := os.ReadFile(filepath.Join(dir, "vault.enc"))
	if string(first) == string(second) {
		t.Fatal("saving twice produced identical ciphertext: the nonce is being reused")
	}
}
