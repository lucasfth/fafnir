package crypt

import (
	"bytes"
	"testing"
)

func TestEmptyVariableSetAuthenticated(t *testing.T) {
	id := identity(t)
	p, _ := Public(id)
	data, e := Encrypt([]byte("TOKEN=synthetic\nEMPTY=\n"), []string{p})
	if e != nil {
		t.Fatal(e)
	}
	var removed []byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(l, []byte("EMPTY=")) {
			removed = append(removed, l...)
			removed = append(removed, '\n')
		}
	}
	mutations := [][]byte{append(bytes.Clone(data), []byte("DISABLE_AUTH=\n")...), bytes.Replace(data, []byte("EMPTY="), []byte("OTHER="), 1), removed}
	for i, b := range mutations {
		v, e := Decrypt(b, id, []string{p})
		if e == nil || v != nil {
			t.Fatalf("empty-variable mutation %d authenticated", i)
		}
	}
}
func TestMalformedDatatypesRejectedWithoutPanic(t *testing.T) {
	id := identity(t)
	p, _ := Public(id)
	data, e := Encrypt([]byte("# comment\nTOKEN=x\n"), []string{p})
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"bytes", "int", "bool", "float"} {
		bad := bytes.ReplaceAll(data, []byte("type:str]"), []byte("type:"+kind+"]"))
		if out, e := Decrypt(bad, id, []string{p}); e == nil || out != nil {
			t.Fatal("invalid datatype accepted")
		}
	}
}
