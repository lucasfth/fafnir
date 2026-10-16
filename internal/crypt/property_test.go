package crypt

import (
	"bytes"
	"fmt"
	"maps"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

func generatedDocument(r *rand.Rand) []byte {
	var b strings.Builder
	if r.IntN(2) == 0 {
		b.WriteString("# generated\n")
	}
	for i := range r.IntN(4) + 1 {
		var v strings.Builder
		for range r.IntN(12) {
			v.WriteRune([]rune(" abc#=$ø\\\n")[r.IntN(len([]rune(" abc#=$ø\\\n")))])
		}
		fmt.Fprintf(&b, "KEY_%d=%s\n", i, strconv.Quote(v.String()))
	}
	return []byte(b.String())
}

func mutateField(t *testing.T, data []byte, field, after string) []byte {
	t.Helper()
	start := bytes.Index(data, []byte(field))
	if start < 0 {
		t.Fatalf("missing generated field %q", field)
	}
	start += len(field)
	end := start + bytes.IndexByte(data[start:], '\n')
	if end < start {
		t.Fatalf("unterminated generated field %q", field)
	}
	at := start + bytes.Index(data[start:end], []byte(after)) + len(after)
	if at < start+len(after) || at >= end {
		t.Fatalf("missing %q in generated field %q", after, field)
	}
	out := bytes.Clone(data)
	if out[at] == 'A' {
		out[at] = 'B'
	} else {
		out[at] = 'A'
	}
	return out
}

func TestGeneratedSemanticRoundTrip(t *testing.T) {
	id := identity(t)
	pub, _ := Public(id)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 16 {
		plain := generatedDocument(r)
		want, e := ParseEnv(plain)
		if e != nil {
			t.Fatalf("case %d generated invalid input: %v", i, e)
		}
		data, e := Encrypt(plain, []string{pub})
		if e != nil {
			t.Fatalf("case %d encrypt: %v", i, e)
		}
		out, e := Decrypt(data, id, []string{pub})
		if e != nil {
			t.Fatalf("case %d decrypt: %v", i, e)
		}
		got, e := ParseEnv(out)
		if e != nil || !maps.Equal(got, want) {
			t.Fatalf("case %d changed configuration semantics: %v", i, e)
		}
	}
}

func TestGeneratedWrappedKeyAndCiphertextTamperingReleaseNoPlaintext(t *testing.T) {
	id := identity(t)
	pub, _ := Public(id)
	data, e := Encrypt([]byte("SECRET=generated\n"), []string{pub})
	if e != nil {
		t.Fatal(e)
	}
	mutations := [][]byte{
		mutateField(t, data, "sops_age__list_0__map_enc=", ""),
		mutateField(t, data, "SECRET=", "data:"),
	}
	for i, bad := range mutations {
		out, e := Decrypt(bad, id, []string{pub})
		if e == nil || out != nil {
			t.Fatalf("mutation %d released plaintext", i)
		}
	}
}
