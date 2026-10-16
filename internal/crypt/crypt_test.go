package crypt

import (
	"bytes"
	"maps"
	"strings"
	"testing"
)

func identity(t *testing.T) string {
	t.Helper()
	v, e := GenerateIdentity()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func equalEnv(t *testing.T, a, b []byte) {
	t.Helper()
	av, e := ParseEnv(a)
	if e != nil {
		t.Fatal(e)
	}
	bv, e := ParseEnv(b)
	if e != nil {
		t.Fatal(e)
	}
	if !maps.Equal(av, bv) {
		t.Fatalf("restored configuration changed values")
	}
}
func TestRecipientsGrantAndRevoke(t *testing.T) {
	owner, coworker := identity(t), identity(t)
	op, _ := Public(owner)
	cp, _ := Public(coworker)
	plain := []byte("# comment with spaces\nEMPTY=\nMULTILINE='one\ntwo'\nUNICODE=øj\nLITERAL='a#b'\n")
	initial, e := Encrypt(plain, []string{op})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decrypt(initial, coworker, []string{op}); e == nil {
		t.Fatal("ungranted coworker decrypted")
	}
	restored, e := Decrypt(initial, owner, []string{op})
	if e != nil {
		t.Fatal("owner roundtrip", e)
	}
	equalEnv(t, plain, restored)
	if !bytes.Contains(restored, []byte("# comment with spaces")) {
		t.Fatal("comment lost")
	}
	granted, e := Rekey(initial, owner, []string{op}, []string{op, cp})
	if e != nil {
		t.Fatal(e)
	}
	restored, e = Decrypt(granted, coworker, []string{op, cp})
	if e != nil {
		t.Fatal(e)
	}
	equalEnv(t, plain, restored)
	other, e := Encrypt([]byte("TOKEN=other\n"), []string{op})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decrypt(other, coworker, []string{op}); e == nil {
		t.Fatal("ungranted environment decrypted")
	}
	revoked, e := Rekey(granted, owner, []string{op, cp}, []string{op})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decrypt(revoked, coworker, []string{op}); e == nil {
		t.Fatal("removed recipient decrypted fresh ciphertext")
	}
	if e = Inspect(granted, []string{op, cp}); e != nil {
		t.Fatal(e)
	}
	if e = Inspect(granted, []string{op}); e == nil {
		t.Fatal("unauthorized policy accepted")
	}
	if bytes.Contains(initial, []byte("comment with spaces")) || bytes.Contains(initial, []byte("one")) {
		t.Fatal("plaintext leaked")
	}
}
func TestTamperingReturnsNoPlaintext(t *testing.T) {
	id := identity(t)
	pub, _ := Public(id)
	data, e := Encrypt([]byte("# sensitive comment\nTOKEN=hidden\nSECOND=other\n"), []string{pub})
	if e != nil {
		t.Fatal(e)
	}
	withoutToken := []byte{}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("TOKEN=")) {
			withoutToken = append(withoutToken, line...)
			withoutToken = append(withoutToken, '\n')
		}
	}
	mutations := [][]byte{
		append(bytes.Clone(data), []byte("TOKEN=plaintext\n")...),
		bytes.Replace(data, []byte("TOKEN=ENC["), []byte("RENAMED=ENC["), 1),
		bytes.Replace(data, []byte("sops_mac=ENC["), []byte("sops_mac=BAD["), 1),
		bytes.Replace(data, []byte("sops_age__"), []byte("sops_hc_vault__"), 1),
		append(bytes.Clone(data), []byte("sops_hc_vault__list_0__vault_address=https://attacker.invalid\n")...),
		withoutToken, data[:len(data)/2],
		bytes.Replace(data, []byte("#ENC[AES256_GCM,data:"), []byte("#ENC[AES256_GCM,data:AAAA"), 1),
	}
	for i, bad := range mutations {
		if bytes.Equal(bad, data) {
			t.Fatalf("mutation %d made no change", i)
		}
		out, e := Decrypt(bad, id, []string{pub})
		if e == nil || out != nil {
			t.Fatalf("mutation %d released plaintext", i)
		}
	}
}
func TestParserSemanticBoundaries(t *testing.T) {
	input := []byte("# comment\nEMPTY=\nUNQUOTED=a=b # comment\nSINGLE='one\ntwo'\nDOUBLE=\"a\\nø\" # comment\nLITERAL='a#b${HOME}'\nBACKSLASH=path\\nfile\n")
	got, e := ParseEnv(input)
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]string{"EMPTY": "", "UNQUOTED": "a=b", "SINGLE": "one\ntwo", "DOUBLE": "a\nø", "LITERAL": "a#b${HOME}", "BACKSLASH": `path\nfile`}
	if !maps.Equal(got, want) {
		t.Fatal("parser changed dotenv semantics")
	}
	for _, bad := range []string{"A=1\nA=2\n", "=x\n", "A=\"unterminated\n", "A=$(touch nope)\n", "A=${HOME}\n", "sops_mac=x\n", "A=one\nmalformed\n"} {
		if _, e = ParseEnv([]byte(bad)); e == nil {
			t.Fatal("ambiguous or executable syntax accepted")
		}
	}
}
func TestRecipientAndResourceLimits(t *testing.T) {
	id := identity(t)
	pub, _ := Public(id)
	for _, r := range [][]string{nil, {pub, pub}, {"age1plugin-../../evil"}, {"ssh-ed25519 AAAA"}} {
		if ValidateRecipients(r) == nil {
			t.Fatal("invalid recipients accepted")
		}
	}
	if _, e := Encrypt(make([]byte, MaxFileSize+1), []string{pub}); e == nil {
		t.Fatal("oversized plaintext accepted")
	}
	if _, e := Decrypt(make([]byte, MaxCiphertextSize+1), id, []string{pub}); e == nil {
		t.Fatal("oversized ciphertext accepted")
	}
}
func TestErrorsDoNotExposeSecrets(t *testing.T) {
	secret := "sensitive-value"
	_, e := Encrypt([]byte("TOKEN="+secret), nil)
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("error missing or leaks plaintext")
	}
}
func FuzzParseEnv(f *testing.F) {
	for _, s := range []string{"A=1\n", "A='x\ny'\n", "A=$(nope)\n", "A=\n", "A=1\nA=2\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= MaxFileSize {
			_, _ = ParseEnv(b)
		}
	})
}
func FuzzInspect(f *testing.F) {
	id, _ := GenerateIdentity()
	pub, _ := Public(id)
	data, _ := Encrypt([]byte("A=synthetic\n"), []string{pub})
	f.Add(data)
	f.Add([]byte("sops_age__list_999999999__recipient=bad\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= MaxCiphertextSize {
			_ = Inspect(b, []string{pub})
		}
	})
}
