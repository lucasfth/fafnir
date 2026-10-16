package crypt

import (
	"strings"
	"testing"
)

func TestAcceptedPlaintextAlwaysRestorable(t *testing.T) {
	id := identity(t)
	p, _ := Public(id)
	for _, plain := range []string{"TOKEN='a\u200bb'\n", "TOKEN='" + strings.Repeat("x\n", 400000) + "'\n"} {
		data, e := Encrypt([]byte(plain), []string{p})
		if e != nil {
			continue
		}
		out, e := Decrypt(data, id, []string{p})
		if e != nil {
			t.Fatal("accepted plaintext produced unrestorable ciphertext", e)
		}
		equalEnv(t, []byte(plain), out)
	}
}
