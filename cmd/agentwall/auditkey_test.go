package main

import (
	"strings"
	"testing"

	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/firewall"
	"github.com/Arsh624/agentwall/internal/vault"
)

func TestInitCreatesTheAuditKeyAndVerifyUsesIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTWALL_HOME", home)
	t.Setenv("AGENTWALL_PASSPHRASE", "correct-horse-battery")
	t.Chdir(t.TempDir()) // no MCP config here

	if out, err := run(t, "", "init"); err != nil || !strings.Contains(out, "audit signing key") {
		t.Fatalf("init: %q %v", out, err)
	}
	key, err := vault.Open(home).Get(auditKeyName)
	if err != nil || len(key) < 32 {
		t.Fatalf("audit key: %q %v", key, err)
	}
	run(t, "", "init")
	if again, _ := vault.Open(home).Get(auditKeyName); again != key {
		t.Fatal("a second init must keep the existing key")
	}

	l, _ := audit.OpenSigned(firewall.AuditPath(home), []byte(key))
	l.Append(audit.Entry{Tool: "t", Decision: "allow"})
	l.Close()
	if out, err := run(t, "", "verify"); err != nil || !strings.Contains(out, "signatures checked") {
		t.Fatalf("verify: %q %v", out, err)
	}

	t.Setenv("AGENTWALL_PASSPHRASE", "") // no vault: the chain is still checked, and the output says signatures were not
	t.Setenv("AGENTWALL_HOME", home)
	if out, _ := run(t, "", "verify"); !strings.Contains(out, "not checked") {
		t.Fatalf("verify without a key must say so: %q", out)
	}
}
