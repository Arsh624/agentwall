package pin

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestDistrustNeedsApproval(t *testing.T) {
	s := Open(t.TempDir())
	tool := json.RawMessage(`{"name":"add","description":"x"}`)
	if _, err := s.Check("calc", []json.RawMessage{tool}); err != nil {
		t.Fatal(err)
	}
	if err := s.Distrust("calc", "add"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check("calc", []json.RawMessage{tool}); st[0] != Changed {
		t.Fatalf("a distrusted tool must stay hidden, got %v", st[0])
	}
	if err := s.Approve("calc", "add"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check("calc", []json.RawMessage{tool}); st[0] != Same {
		t.Fatalf("an approved tool must be trusted, got %v", st[0])
	}
	if names, _ := s.Names("calc"); !slices.Equal(names, []string{"add"}) {
		t.Fatalf("Names = %v", names)
	}
	if names, _ := s.Names("nobody"); len(names) != 0 {
		t.Fatalf("Names of an unknown server = %v", names)
	}
}
