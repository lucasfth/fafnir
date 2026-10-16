package crypt

import (
	"bytes"
	"testing"
)

func TestCipherDatatypeNewlineDifferential(t *testing.T) {
	id := identity(t)
	p, _ := Public(id)
	data, e := Encrypt([]byte("TOKEN=x\n"), []string{p})
	if e != nil {
		t.Fatal(e)
	}
	bad := bytes.ReplaceAll(data, []byte(",type:str]"), []byte(`,type:bytes]\n,type:str]`))
	if out, e := Decrypt(bad, id, []string{p}); e == nil || out != nil {
		t.Fatal("parser differential accepted")
	}
}
func TestEmptyCommentAndControlBoundary(t *testing.T) {
	id := identity(t)
	p, _ := Public(id)
	data, e := Encrypt([]byte("#\nTOKEN=x\n"), []string{p})
	if e != nil {
		t.Fatal(e)
	}
	out, e := Decrypt(data, id, []string{p})
	if e != nil || !bytes.HasPrefix(out, []byte("#\n")) {
		t.Fatal("empty comment failed roundtrip", e)
	}
	if _, e = Encrypt([]byte("TOKEN='a\ab'\n"), []string{p}); e == nil {
		t.Fatal("unsupported control accepted")
	}
}
