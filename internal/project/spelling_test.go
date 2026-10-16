package project

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializationPreservesRequestedUnicodeSpelling(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	// Match Linux byte-preserving Git behavior on the macOS test host.
	gitTest(t, f.root, "config", "core.precomposeUnicode", "false")
	name := "cafe\u0301.env"
	f.put(t, name, "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: name, Encrypted: name + ".fafnir", Recipients: []string{f.recipient}})
	c, e := f.p.Config()
	if e != nil || c.Pairs[0].Plain != name {
		t.Fatal("initialization silently rewrote requested file scope", e)
	}
	ignore, e := os.ReadFile(filepath.Join(f.root, ".gitignore"))
	if e != nil || !bytes.Contains(ignore, []byte("/"+name+"\n")) {
		t.Fatal("ignore rules changed Unicode spelling")
	}
	gitTest(t, f.root, "check-ignore", "--", name)
	if e = f.p.Seal(name, f.identity, false); e != nil {
		t.Fatal("requested scope cannot be sealed", e)
	}
}
