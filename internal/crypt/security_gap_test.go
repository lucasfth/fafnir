package crypt

import (
	"bytes"
	"testing"
)

func flipTokenByte(t *testing.T, data []byte, marker string) []byte {
	t.Helper()
	out := bytes.Clone(data)
	i := bytes.Index(out, []byte(marker))
	if i < 0 || i+len(marker) >= len(out) {
		t.Fatalf("missing marker %q", marker)
	}
	i += len(marker)
	switch out[i] {
	case 'A':
		out[i] = 'B'
	default:
		out[i] = 'A'
	}
	return out
}

func mustRejectWithoutPlaintext(t *testing.T, data []byte, identity string, recipients []string) {
	t.Helper()
	plain, err := Decrypt(data, identity, recipients)
	if err == nil || plain != nil {
		t.Fatalf("mutation released plaintext: plain=%q err=%v", plain, err)
	}
}

func TestDynamicCiphertextMutationGaps(t *testing.T) {
	owner, stranger := identity(t), identity(t)
	recipient, _ := Public(owner)
	otherRecipient, _ := Public(stranger)
	data, err := Encrypt([]byte("# synthetic authenticated comment\nTOKEN=synthetic-value\n"), []string{recipient})
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string][]byte{
		"payload":       flipTokenByte(t, data, "TOKEN=ENC[AES256_GCM,data:"),
		"iv":            flipTokenByte(t, data, ",iv:"),
		"tag":           flipTokenByte(t, data, ",tag:"),
		"mac":           flipTokenByte(t, data, "sops_mac=ENC[AES256_GCM,data:"),
		"last-modified": flipTokenByte(t, data, "sops_lastmodified="),
		"comment":       flipTokenByte(t, data, "#ENC[AES256_GCM,data:"),
		"recipient":     flipTokenByte(t, data, "sops_age__list_0__map_recipient="),
		"recipient-index-canonicalization": bytes.Replace(data,
			[]byte("sops_age__list_0__map_"), []byte("sops_age__list_00__map_"), 1),
		"unknown-metadata": append(bytes.Clone(data), []byte("sops_gcp_kms__list_0__map_resource=synthetic\n")...),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(data, mutated) {
				t.Fatal("mutation made no change")
			}
			mustRejectWithoutPlaintext(t, mutated, owner, []string{recipient})
		})
	}

	mustRejectWithoutPlaintext(t, data, stranger, []string{recipient})
	mustRejectWithoutPlaintext(t, data, owner, []string{otherRecipient})
	mustRejectWithoutPlaintext(t, data, owner, []string{recipient, otherRecipient})
}
