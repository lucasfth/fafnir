package project

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)
import "github.com/lucasfth/fafnir/internal/crypt"

func cryptIdentity(t *testing.T) (string, string) {
	t.Helper()
	id, e := crypt.GenerateIdentity()
	if e != nil {
		t.Fatal(e)
	}
	pub, e := crypt.Public(id)
	if e != nil {
		t.Fatal(e)
	}
	return pub, id
}
func TestRestoreRejectsTrackedPlaintext(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if e := f.p.Seal(".env", f.identity, false); e != nil {
		t.Fatal(e)
	}
	gitTest(t, f.root, "add", "-f", ".env")
	os.Remove(filepath.Join(f.root, ".env"))
	if e := f.p.Restore(".env", f.identity, false); e == nil {
		t.Fatal("restored secrets into tracked path")
	}
	if _, e := os.Stat(filepath.Join(f.root, ".env")); !os.IsNotExist(e) {
		t.Fatal("tracked plaintext recreated")
	}
}
func TestTrackingErrorsFailClosed(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	os.WriteFile(filepath.Join(f.root, ".git", "index"), []byte("corrupt"), 0600)
	if e := f.p.Seal(".env", f.identity, false); e == nil {
		t.Fatal("sealed after failing tracking inspection")
	}
}
func TestIgnoreUnsafePathsAndNestedOverrides(t *testing.T) {
	for _, name := range []string{".env[prod]", ".env*", ".env ", ".env\n!secret"} {
		f := newFixture(t)
		if e := f.p.Init(Config{Version: 1, Pairs: []Pair{{Plain: name, Encrypted: name + ".fafnir", Recipients: []string{f.recipient}}}}); e == nil {
			t.Fatal("unsafe ignore path accepted")
		}
		f.p.Close()
	}
	f := newFixture(t)
	defer f.p.Close()
	os.Mkdir(filepath.Join(f.root, "nested"), 0700)
	f.put(t, "nested/.gitignore", "!.env\n")
	if e := f.p.Init(Config{Version: 1, Pairs: []Pair{{Plain: "nested/.env", Encrypted: "nested/.env.fafnir", Recipients: []string{f.recipient}}}}); e == nil {
		t.Fatal("nested override bypassed plaintext ignore")
	}
}
func TestStagedChecksIgnoreUnrelatedLargeObjectsAndReplacementRefs(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if e := f.p.Seal(".env", f.identity, false); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.root, "asset"), bytes.Repeat([]byte("x"), maxBlobSize+1), 0644)
	gitTest(t, f.root, "add", "asset", policyName, ".env.fafnir")
	if _, e := f.p.Check(true, ""); e != nil {
		t.Fatal("unrelated large file broke guard", e)
	}
	valid := strings.TrimSpace(string(gitTest(t, f.root, "rev-parse", ":.env.fafnir")))
	cmd := exec.Command("git", "-C", f.root, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("TOKEN=plaintext\n")
	bad, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	badID := strings.TrimSpace(string(bad))
	gitTest(t, f.root, "update-index", "--cacheinfo", "100644,"+badID+",.env.fafnir")
	gitTest(t, f.root, "replace", badID, valid)
	if _, e := f.p.Check(true, ""); e == nil {
		t.Fatal("replacement refs hid unsafe staged blob")
	}
}
func TestGrantPreflightPreservesArtifacts(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if e := f.p.Seal(".env", f.identity, false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(f.root, ".env.fafnir"))
	policy, _ := os.ReadFile(filepath.Join(f.root, policyName))
	os.Remove(filepath.Join(f.root, ".gitignore"))
	os.Symlink("/dev/null", filepath.Join(f.root, ".gitignore"))
	other, _ := cryptIdentity(t)
	if e := f.p.Grant(".env", f.identity, []string{f.recipient, other}); e == nil {
		t.Fatal("unsafe grant preflight accepted")
	}
	after, _ := os.ReadFile(filepath.Join(f.root, ".env.fafnir"))
	afterPolicy, _ := os.ReadFile(filepath.Join(f.root, policyName))
	if !bytes.Equal(before, after) || !bytes.Equal(policy, afterPolicy) {
		t.Fatal("failed grant changed artifact or policy")
	}
}
