package project

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucasfth/fafnir/internal/crypt"
)

func TestHookHelper(t *testing.T) {
	if os.Getenv("FAFNIR_HOOK_TEST") != "1" {
		return
	}
	p, err := Open(".", os.Getenv("FAFNIR_HOOK_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Check(true, ""); err != nil {
		t.Fatal(err)
	}
	if marker := os.Getenv("FAFNIR_HOOK_MARKER"); marker != "" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(marker, []byte(cwd), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

type fixture struct {
	root, state         string
	p                   *Project
	identity, recipient string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(t.TempDir(), "fafnir-state")
	gitTest(t, root, "init", "-q")
	gitTest(t, root, "config", "user.email", "fafnir@example.invalid")
	gitTest(t, root, "config", "user.name", "Fafnir test")
	id, err := crypt.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypt.Public(id)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Open(root, state)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{root: root, state: state, p: p, identity: id, recipient: pub}
}

func (f fixture) initialize(t *testing.T, pairs ...Pair) {
	t.Helper()
	if err := f.p.Init(Config{Version: 1, Pairs: pairs}); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) put(t *testing.T, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, name), []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func gitTest(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return out
}

func TestInitMergesAdditionalPairWithoutReplacingApprovedPair(t *testing.T) {
	f := newFixture(t)
	first := Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}}
	f.initialize(t, first)
	second := Pair{Plain: ".env.production", Encrypted: ".env.production.fafnir", Recipients: []string{f.recipient}}
	if err := f.p.Init(Config{Version: 1, Pairs: []Pair{second}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.p.Config()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Pairs) != 2 || got.Pairs[0].Plain != first.Plain || got.Pairs[1].Plain != second.Plain {
		t.Fatalf("Init replaced or lost configured pairs: %#v", got.Pairs)
	}
}

func TestInitUsesOnlyLiteralIgnoreRulesAndRefusesTrackedPlaintext(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	ignore, err := os.ReadFile(filepath.Join(f.root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"/.env", "!/.env.fafnir"} {
		if !strings.Contains(string(ignore), rule) {
			t.Fatalf("missing literal ignore rule %q in %q", rule, ignore)
		}
	}
	if strings.Contains(string(ignore), "!*.fafnir") {
		t.Fatalf("broad ciphertext exception remains: %q", ignore)
	}
	gitTest(t, f.root, "add", "-f", ".env")
	if _, err := f.p.Check(true, ""); err == nil {
		t.Fatal("staged forced plaintext was accepted")
	}
}

func TestInitRejectsAlreadyTrackedPlaintext(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	gitTest(t, f.root, "add", "-f", ".env")
	if err := f.p.Init(Config{Version: 1, Pairs: []Pair{{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}}}}); err == nil {
		t.Fatal("Init approved a plaintext file already in the Git index")
	}
}

func TestPolicyChangeRequiresExplicitApproval(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	configPath := filepath.Join(f.root, policyName)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := decodeConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := crypt.GenerateIdentity()
	otherPub, _ := crypt.Public(other)
	data = bytes.Replace(data, []byte(f.recipient), []byte(otherPub), 1)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Config(); err == nil {
		t.Fatal("changed repository policy remained trusted")
	}
	if err := f.p.Approve(reviewed); err == nil {
		t.Fatal("approved policy that changed after review")
	}
	changed, err := f.p.ReadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.Approve(changed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Config(); err != nil {
		t.Fatalf("explicit approval did not restore trust: %v", err)
	}
}

func TestNormalizeConfigRejectsUnicodeAndCasePathAliasesAcrossRoles(t *testing.T) {
	f := newFixture(t)
	for _, pairs := range [][]Pair{
		{{Plain: "caf\u00e9", Encrypted: "caf\u00e9.fafnir", Recipients: []string{f.recipient}}, {Plain: "cafe\u0301", Encrypted: "cafe\u0301.fafnir", Recipients: []string{f.recipient}}},
		{{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}}, {Plain: ".ENV", Encrypted: ".ENV.fafnir", Recipients: []string{f.recipient}}},
		{{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}}, {Plain: ".env.fafnir", Encrypted: ".env.fafnir.fafnir", Recipients: []string{f.recipient}}},
	} {
		if _, err := normalizeConfig(Config{Version: 1, Pairs: pairs}); err == nil {
			t.Fatalf("accepted colliding paths: %#v", pairs)
		}
	}
}

func TestCheckDetectsNFDTrackedAliasForNFCPlaintext(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.initialize(t, Pair{Plain: "caf\u00e9", Encrypted: "caf\u00e9.fafnir", Recipients: []string{f.recipient}})
	trackedNFD := "cafe\u0301"
	f.put(t, trackedNFD, "TOKEN=synthetic\n")
	gitTest(t, f.root, "add", "-f", trackedNFD)
	if _, err := f.p.Check(true, ""); err == nil {
		t.Fatal("NFD tracked alias bypassed NFC plaintext tracking guard")
	}
}

func TestTrustStateIsPinnedOutsideRepositoryAndCorruptionFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if _, err := os.Stat(f.state); err != nil {
		t.Fatalf("trust state is not outside checkout: %v", err)
	}
	path := filepath.Join(f.state, f.p.approvalPath())
	if err := os.WriteFile(path, []byte(`{"version":1,"root":"attacker","policy":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Config(); err == nil {
		t.Fatal("tampered local approval was accepted")
	}
}

func TestSealRestoreAndOverwriteRefusalPreserveExistingFiles(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=first\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	cipherPath := filepath.Join(f.root, ".env.fafnir")
	original, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	f.put(t, ".env", "TOKEN=changed\n")
	if err := f.p.Seal(".env", f.identity, false); err == nil {
		t.Fatal("seal replaced differing ciphertext without authorization")
	}
	still, err := os.ReadFile(cipherPath)
	if err != nil || !bytes.Equal(original, still) {
		t.Fatalf("refused overwrite changed artifact: %v", err)
	}
	if err := f.p.Seal(".env", f.identity, true); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Restore(".env", f.identity, false); err == nil {
		t.Fatal("restore overwrote differing plaintext without authorization")
	}
	plain, err := os.ReadFile(filepath.Join(f.root, ".env"))
	if err != nil || string(plain) != "TOKEN=changed\n" {
		t.Fatalf("refused restore changed plaintext: %q %v", plain, err)
	}
	if err := f.p.Restore(".env", f.identity, true); err != nil {
		t.Fatal(err)
	}
	plain, err = os.ReadFile(filepath.Join(f.root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	values, err := crypt.ParseEnv(plain)
	if err != nil || values["TOKEN"] != "changed" {
		t.Fatal("restore changed dotenv value")
	}
	info, err := os.Stat(filepath.Join(f.root, ".env"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("restored plaintext mode = %v, %v", info, err)
	}
}

func TestOpenRejectsSymlinkEscapesForInputsAndDestinations(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("TOKEN=outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.root, ".env.fafnir")); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Seal(".env", f.identity, true); err == nil {
		t.Fatal("Seal followed a symlink destination")
	}
	if err := os.Remove(filepath.Join(f.root, ".env.fafnir")); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.root, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.root, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Restore(".env", f.identity, true); err == nil {
		t.Fatal("Restore followed a symlink destination")
	}
}

func TestGrantIsScopedAndRequiresArtifactPolicyPairConsistency(t *testing.T) {
	f := newFixture(t)
	other, err := crypt.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := crypt.Public(other)
	if err != nil {
		t.Fatal(err)
	}
	f.put(t, ".env", "TOKEN=production\n")
	f.put(t, ".env.dev", "TOKEN=development\n")
	f.initialize(t,
		Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}},
		Pair{Plain: ".env.dev", Encrypted: ".env.dev.fafnir", Recipients: []string{f.recipient}},
	)
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Seal(".env.dev", f.identity, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(f.root, ".env.dev.fafnir"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.Grant(".env", f.identity, []string{f.recipient, otherPub}); err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.Decrypt(mustRead(t, filepath.Join(f.root, ".env.fafnir")), other, []string{f.recipient, otherPub}); err != nil {
		t.Fatalf("new recipient cannot decrypt granted artifact: %v", err)
	}
	if _, err := crypt.Decrypt(mustRead(t, filepath.Join(f.root, ".env.dev.fafnir")), other, []string{f.recipient}); err == nil {
		t.Fatal("grant leaked to another file")
	}
	after, err := os.ReadFile(filepath.Join(f.root, ".env.dev.fafnir"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unselected artifact changed: %v", err)
	}
	cfg, err := f.p.Config()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Pairs[0].Recipients) != 2 || len(cfg.Pairs[1].Recipients) != 1 {
		t.Fatalf("unexpected recipient policy: %#v", cfg.Pairs)
	}
	if err := f.p.Grant(".env", f.identity, []string{f.recipient}); err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.Decrypt(mustRead(t, filepath.Join(f.root, ".env.fafnir")), other, []string{f.recipient}); err == nil {
		t.Fatal("removed recipient can decrypt newly rotated artifact")
	}
}

func TestCheckUsesStagedBlobAndDetectsStagedPolicyMismatch(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	gitTest(t, f.root, "add", ".gitignore", policyName)
	gitTest(t, f.root, "add", ".env.fafnir")
	if messages, err := f.p.Check(true, f.identity); err != nil {
		t.Fatalf("valid staged snapshot: %v %v", messages, err)
	}
	// Stage ciphertext for one plaintext, then leave a different working artifact and plaintext.
	good := mustRead(t, filepath.Join(f.root, ".env.fafnir"))
	f.put(t, ".env", "TOKEN=changed\n")
	if err := f.p.Seal(".env", f.identity, true); err != nil {
		t.Fatal(err)
	}
	if messages, err := f.p.Check(true, f.identity); err == nil || !strings.Contains(strings.Join(messages, " "), "sync") {
		t.Fatalf("staged/working plaintext mismatch not reported: %v %v", messages, err)
	}
	// Force the index blob back to the original ciphertext. Check must inspect the blob, not the working file.
	// Keep the original staged ciphertext object while the worktree remains different.
	cmd := exec.Command("git", "-C", f.root, "hash-object", "-w", "--stdin")
	cmd.Stdin = bytes.NewReader(good)
	hash, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	gitTest(t, f.root, "update-index", "--cacheinfo", "100644,"+strings.TrimSpace(string(hash))+",.env.fafnir")
	if messages, err := f.p.Check(true, f.identity); err == nil || !strings.Contains(strings.Join(messages, " "), "sync") {
		t.Fatalf("staged blob was not compared against plaintext: %v %v", messages, err)
	}
	// An untrusted staged policy must not pass merely because the working tree contains the approved copy.
	gitTest(t, f.root, "add", "-f", policyName)
	policy, err := os.ReadFile(filepath.Join(f.root, policyName))
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypt.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := crypt.Public(other)
	if err != nil {
		t.Fatal(err)
	}
	policy = bytes.Replace(policy, []byte(f.recipient), []byte(otherPub), 1)
	objCmd := exec.Command("git", "hash-object", "-w", "--stdin")
	objCmd.Dir = f.root
	objCmd.Stdin = bytes.NewReader(policy)
	ph, err := objCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	gitTest(t, f.root, "update-index", "--cacheinfo", "100644,"+strings.TrimSpace(string(ph))+","+policyName)
	if _, err := f.p.Check(true, ""); err == nil {
		t.Fatal("staged changed policy was not rejected")
	}
}
func TestSharedLinkedWorktreeHookUsesCommittingWorktreeAndRejectsIndexOverride(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	f.put(t, ".env", "TOKEN=synthetic\n")
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	gitTest(t, f.root, "config", "user.email", "fafnir@example.invalid")
	gitTest(t, f.root, "config", "user.name", "Fafnir test")
	gitTest(t, f.root, "add", policyName, ".gitignore", ".env.fafnir")
	gitTest(t, f.root, "commit", "-m", "initialize policy")
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "fafnir-hook")
	script := "#!/bin/sh\n[ \"$1\" = --dir ] && [ \"$2\" = . ] || exit 41\n[ \"$3\" = --state-dir ] || exit 42\nshift 4\nexec " + shellQuote(helper) + " -test.run=^TestHookHelper$\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.p.InstallHook(executable); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	gitTest(t, f.root, "worktree", "add", "-q", "-b", "linked", linked)
	gitTest(t, linked, "config", "user.email", "fafnir@example.invalid")
	linkedProject, err := Open(linked, f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer linkedProject.Close()
	gitTest(t, linked, "config", "user.name", "Fafnir test")
	if err := os.WriteFile(filepath.Join(linked, "probe.txt"), []byte("probe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, linked, "add", "probe.txt")
	cmd := exec.Command("git", "-C", linked, "commit", "-m", "unapproved")
	cmd.Env = append(os.Environ(), "FAFNIR_HOOK_TEST=1", "FAFNIR_HOOK_STATE="+f.state)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("linked worktree committed without its own approval: %s", out)
	}
	reviewed, err := linkedProject.ReadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := linkedProject.Approve(reviewed); err != nil {
		t.Fatal(err)
	}
	gitTest(t, linked, "add", "probe.txt")
	marker := filepath.Join(t.TempDir(), "hook-root")
	cmd = exec.Command("git", "-C", linked, "commit", "-m", "approved")
	cmd.Env = append(os.Environ(), "FAFNIR_HOOK_TEST=1", "FAFNIR_HOOK_STATE="+f.state, "FAFNIR_HOOK_MARKER="+marker)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("linked worktree hook refused valid probe: %v %s", err, out)
	}
	got, err := os.ReadFile(marker)
	linkedReal, _ := filepath.EvalSymlinks(linked)
	if err != nil || strings.TrimSpace(string(got)) != linkedReal {
		t.Fatalf("hook did not use committing worktree: %q %v", got, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linked, ".env"), []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, linked, "add", "-f", ".env")
	cmd = exec.Command("git", "-C", linked, "commit", "-m", "plaintext")
	cmd.Env = append(os.Environ(), "FAFNIR_HOOK_TEST=1", "FAFNIR_HOOK_STATE="+f.state)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("unapproved linked worktree committed forced plaintext: %s", out)
	}
	gitTest(t, linked, "reset", "-q", "HEAD", "--", ".env")
	originalIndex := strings.TrimSpace(string(gitTest(t, linked, "rev-parse", "--path-format=absolute", "--git-path", "index")))
	indexData, readErr := os.ReadFile(originalIndex)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := os.WriteFile(filepath.Join(linked, "forced-index"), indexData, 0600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("git", "-C", linked, "commit", "--allow-empty", "-m", "index override")
	cmd.Env = append(os.Environ(), "FAFNIR_HOOK_TEST=1", "FAFNIR_HOOK_STATE="+f.state, "GIT_INDEX_FILE="+filepath.Join(linked, "forced-index"))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("hook accepted forced index override: %s", out)
	}
}

func TestInstallHookQuotesExecutableAndRefusesExistingHook(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	executable := filepath.Join(t.TempDir(), "fafnir's binary")
	if err := os.WriteFile(executable, []byte("not executed"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.p.InstallHook(executable); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(f.root, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hook)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "--state-dir '") || !strings.Contains(text, "--dir .") || !strings.Contains(text, "GIT_INDEX_FILE") || !strings.Contains(text, "check --staged") || !strings.Contains(text, "fafnir'\\''s binary") || strings.Contains(text, "--dir '"+f.root) {
		t.Fatalf("unsafe or incomplete fixed hook: %q", text)
	}
	if err := f.p.InstallHook(executable); err == nil {
		t.Fatal("existing hook was overwritten")
	}
}

func TestStatePathAndConfiguredPairsCannotEscapeRoot(t *testing.T) {
	f := newFixture(t)
	for _, pair := range []Pair{
		{Plain: "../outside", Encrypted: "../outside.fafnir", Recipients: []string{f.recipient}},
		{Plain: ".env", Encrypted: "elsewhere.fafnir", Recipients: []string{f.recipient}},
		{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient, f.recipient}},
	} {
		if err := f.p.Init(Config{Version: 1, Pairs: []Pair{pair}}); err == nil {
			t.Fatalf("unsafe policy pair accepted: %#v", pair)
		}
	}
	outside := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f.root, link); err == nil {
		t.Fatal("symlinked local state directory accepted")
	}
}

func TestStagedPlaintextIsDetectedEvenWhenWorktreeIsClean(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	gitTest(t, f.root, "add", "-f", ".env")
	if _, err := f.p.Check(true, ""); err == nil {
		t.Fatal("forced staged plaintext passed check")
	}
}

func TestAtomicWritePreservesTargetOnPreconditionFailure(t *testing.T) {
	f := newFixture(t)
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if err := f.p.Seal(".env", f.identity, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, ".env.fafnir")
	before := mustRead(t, path)
	if err := f.p.Seal(".env", "invalid identity", true); err == nil {
		t.Fatal("invalid identity unexpectedly sealed")
	}
	after := mustRead(t, path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed seal replaced previous ciphertext")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTrustDigestIsCanonicalAndRootBound(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	before, err := f.p.Config()
	if err != nil {
		t.Fatal(err)
	}
	otherRoot := t.TempDir()
	gitTest(t, otherRoot, "init", "-q")
	other, err := Open(otherRoot, f.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Config(); err == nil {
		t.Fatal("approval crossed repository root")
	}
	encoded, err := os.ReadFile(filepath.Join(f.root, policyName))
	if err != nil {
		t.Fatal(err)
	}
	var formatted bytes.Buffer
	if err := jsonIndent(&formatted, encoded); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, policyName), formatted.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := f.p.Config()
	if err != nil {
		t.Fatalf("format-only policy edit unexpectedly changed semantic trust: %v", err)
	}
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatal("config changed during canonicalization")
	}
}

// jsonIndent is local to avoid broadening production API just for the test.
func jsonIndent(dst *bytes.Buffer, src []byte) error {
	var value any
	if err := json.Unmarshal(src, &value); err != nil {
		return err
	}
	return json.NewEncoder(dst).Encode(value)
}
