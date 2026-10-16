package crypt

import (
	"fmt"
	"strings"
	"testing"
)

func TestRawMetadataRejectsNoncanonicalIndices(t *testing.T) {
	for _, index := range []string{"00", "01", "0000000000000000000000000000"} {
		data := []byte(fmt.Sprintf("sops_age__list_0__map_recipient=x\nsops_age__list_%s__map_enc=x\n", index))
		if e := inspectRaw(data); e == nil {
			t.Fatal("noncanonical numeric index reached SOPS parser")
		}
	}
	var b strings.Builder
	b.WriteString("sops_age__list_0__map_recipient=x\n")
	for n := range 100 {
		fmt.Fprintf(&b, "sops_age__list_%s0__map_enc=x\n", strings.Repeat("0", n))
	}
	if e := inspectRaw([]byte(b.String())); e == nil {
		t.Fatal("duplicate decoded wrapper aliases reached SOPS parser")
	}
}
