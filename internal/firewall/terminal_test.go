package firewall

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestTerminalQuestionTimesOut(t *testing.T) {
	r, _ := io.Pipe() // a terminal no one types into
	var w bytes.Buffer
	start := time.Now()
	if askOn(r, &w, "allow x?", 50*time.Millisecond) {
		t.Fatal("no answer must be a no")
	}
	if time.Since(start) > 2*time.Second || !strings.Contains(w.String(), "denied") {
		t.Fatalf("must give up after the timeout and say so: %q", w.String())
	}
}

func TestTerminalQuestionAnswers(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "Y\r\n": true, "n\n": false, "yes\n": false, "": false} {
		if got := askOn(strings.NewReader(in), io.Discard, "allow x?", time.Second); got != want {
			t.Errorf("answer %q: got %v, want %v", in, got, want)
		}
	}
}
