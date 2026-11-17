package policy

import (
	"reflect"
	"testing"
)

func TestServerEnvNamesVaultSecrets(t *testing.T) {
	p, err := Parse([]byte(`
servers:
  github:
    env: {GITHUB_TOKEN: "vault:github", GH_HOST_TOKEN: "vault:gh.enterprise-1"}
  fetch: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"GITHUB_TOKEN": "github", "GH_HOST_TOKEN": "gh.enterprise-1"}
	if got := p.Env("github"); !reflect.DeepEqual(got, want) {
		t.Fatalf("Env(github) = %v, want %v", got, want)
	}
	if got := p.Env("fetch"); len(got) != 0 {
		t.Fatalf("Env(fetch) = %v, want none", got)
	}
	if got := p.Env("unknown"); len(got) != 0 {
		t.Fatalf("Env(unknown) = %v, want none", got)
	}
}

// A literal value would put a secret in the policy file, which is exactly what the vault is for.
func TestServerEnvRejectsLiteralsAndBadNames(t *testing.T) {
	for _, bad := range []string{
		`servers: {s: {env: {TOKEN: "ghp_literal"}}}`,
		`servers: {s: {env: {TOKEN: "vault:"}}}`,
		`servers: {s: {env: {TOKEN: "vault:bad name"}}}`,
		`servers: {s: {env: {"BAD NAME": "vault:x"}}}`,
		`servers: {s: {env: {"A=B": "vault:x"}}}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}
