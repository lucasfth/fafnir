package cli

import (
	"bytes"
	"context"
	"github.com/lucasfth/fafnir/internal/crypt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryAndCoworkerWorkflow(t *testing.T) {
	base := t.TempDir()
	if e := os.Chmod(base, 0700); e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(base, "repo")
	if e := os.Mkdir(repo, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("git", "init", "-q", repo)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("git init: %v %s", e, b)
	}
	state := filepath.Join(base, "alice-state")
	key := filepath.Join(base, "alice.key")
	call := func(keyfile, st string, want bool, args ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		all := append([]string{"--dir", repo, "--state-dir", st, "--key-file", keyfile}, args...)
		code := Execute(context.Background(), all, strings.NewReader(""), &out, &diag)
		if (code == 0) != want {
			t.Fatalf("command %v code %d stdout %q diagnostics %q", args, code, out.String(), diag.String())
		}
		return out.String()
	}
	call(key, state, true, "key", "create")
	alice := strings.TrimSpace(call(key, state, true, "key", "public"))
	bobKey := filepath.Join(base, "bob.key")
	bobState := filepath.Join(base, "bob-state")
	call(bobKey, bobState, true, "key", "create")
	bob := strings.TrimSpace(call(bobKey, bobState, true, "key", "public"))
	if alice == bob {
		t.Fatal("independent identities collided")
	}
	call(key, state, true, "init", "--recipient", alice, "--yes")
	plain := []byte("TOKEN='synthetic value'\nEMPTY=\nUNICODE=ravn-æ\n")
	if e := os.WriteFile(filepath.Join(repo, ".env"), plain, 0600); e != nil {
		t.Fatal(e)
	}
	call(key, state, true, "seal")
	ciphertext, e := os.ReadFile(filepath.Join(repo, ".env.fafnir"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(ciphertext, []byte("synthetic value")) {
		t.Fatal("ciphertext contains plaintext")
	}
	call(key, state, true, "check", "--decrypt")
	call(bobKey, bobState, true, "trust", "--yes")
	call(bobKey, bobState, false, "run", "--", "/bin/sh", "-c", "exit 0")
	call(key, state, true, "grant", "--recipient", bob, "--yes")
	call(bobKey, bobState, false, "run", "--", "/bin/sh", "-c", "exit 0") // changed policy needs explicit approval
	call(bobKey, bobState, true, "trust", "--yes")
	got := call(bobKey, bobState, true, "run", "--", "/bin/sh", "-c", `printf '%s|%s|%s' "$TOKEN" "$EMPTY" "$UNICODE"`)
	if got != "synthetic value||ravn-æ" {
		t.Fatalf("dotenv semantics changed: %q", got)
	}
	if e := os.Remove(filepath.Join(repo, ".env")); e != nil {
		t.Fatal(e)
	}
	call(bobKey, bobState, true, "open")
	restored, e := os.ReadFile(filepath.Join(repo, ".env"))
	if e != nil {
		t.Fatal(e)
	}
	before, be := crypt.ParseEnv(plain)
	after, ae := crypt.ParseEnv(restored)
	if be != nil || ae != nil || !maps.Equal(before, after) {
		t.Fatal("roundtrip changed dotenv values")
	}
	if e := os.WriteFile(filepath.Join(repo, ".env"), []byte("TOKEN=local-unsaved\n"), 0600); e != nil {
		t.Fatal(e)
	}
	call(bobKey, bobState, false, "open")
	call(key, state, true, "revoke", "--recipient", bob, "--yes")
	call(bobKey, bobState, true, "trust", "--yes")
	call(bobKey, bobState, false, "run", "--", "/bin/sh", "-c", "exit 0")
	call(key, state, true, "open", "--replace")
	cmd = exec.Command("git", "-C", repo, "add", "-f", ".env")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("stage: %v %s", e, b)
	}
	call(key, state, false, "check", "--staged")
}
