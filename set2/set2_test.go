package set2

import (
	"bytes"
	"testing"
)

func TestChallengeSet(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	out := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	res := paddingPKCS7(in, 20)
	if !bytes.Equal(res, out) {
		t.Fatalf("wrongs res ex: %s got: %s\n", out, res)
	}
}
