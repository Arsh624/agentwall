package policy

import (
	"reflect"
	"testing"
)

func TestServerHeadersNameVaultSecrets(t *testing.T) {
	p, err := Parse([]byte(`servers: {github: {headers: {Authorization: "vault:gh-bearer", X-Api-Key: "vault:key"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Authorization": "gh-bearer", "X-Api-Key": "key"}
	if got := p.Headers("github"); !reflect.DeepEqual(got, want) {
		t.Fatalf("Headers(github) = %v, want %v", got, want)
	}
	if got := p.Headers("other"); len(got) != 0 {
		t.Fatalf("Headers(other) = %v, want none", got)
	}
	for _, bad := range []string{
		`servers: {s: {headers: {Authorization: "Bearer literal-token"}}}`,
		`servers: {s: {headers: {"Bad Header": "vault:x"}}}`,
		`servers: {s: {headers: {"X:Y": "vault:x"}}}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}
