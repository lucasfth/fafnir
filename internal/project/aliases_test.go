package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaseAliasTrackedPlaintextRefused(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.put(t, ".env", "TOKEN=synthetic\n")
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	if e := f.p.Seal(".env", f.identity, false); e != nil {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(f.root, ".env"))
	f.put(t, ".ENV", "TOKEN=template\n")
	gitTest(t, f.root, "add", "-f", ".ENV")
	os.Remove(filepath.Join(f.root, ".ENV"))
	if e := f.p.Restore(".env", f.identity, false); e == nil {
		t.Fatal("case alias bypassed tracked plaintext gate")
	}
	if _, e := f.p.Check(true, ""); e == nil {
		t.Fatal("case alias bypassed staged guard")
	}
}
func TestFailedAdditionalInitPreservesPolicyAndRetries(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	os.Mkdir(filepath.Join(f.root, "nested"), 0700)
	f.put(t, "nested/.gitignore", "!.env\n")
	second := Config{Version: 1, Pairs: []Pair{{Plain: "nested/.env", Encrypted: "nested/.env.fafnir", Recipients: []string{f.recipient}}}}
	if e := f.p.Init(second); e == nil {
		t.Fatal("nested override accepted")
	}
	c, e := f.p.Config()
	if e != nil || len(c.Pairs) != 1 {
		t.Fatal("failed init broke existing trusted policy", e)
	}
	os.Remove(filepath.Join(f.root, "nested/.gitignore"))
	if e = f.p.Init(second); e != nil {
		t.Fatal("normal retry failed", e)
	}
}
func TestHookRefusesXDGGlobalConfiguration(t *testing.T) {
	f := newFixture(t)
	defer f.p.Close()
	f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
	xdg := t.TempDir()
	os.Mkdir(filepath.Join(xdg, "git"), 0700)
	os.WriteFile(filepath.Join(xdg, "git", "config"), []byte("[core]\n hooksPath = /dev/null\n"), 0600)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())
	exe := filepath.Join(t.TempDir(), "fafnir")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700)
	if e := f.p.InstallHook(exe); e == nil {
		t.Fatal("ignored XDG hook configuration")
	}
}
