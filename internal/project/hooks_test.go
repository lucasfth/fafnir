package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHookRefusesNondefaultHooksPath(t *testing.T) {
	for _, value := range []string{"custom-hooks", "/dev/null"} {
		t.Run(value, func(t *testing.T) {
			f := newFixture(t)
			defer f.p.Close()
			f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
			gitTest(t, f.root, "config", "core.hooksPath", value)
			exe := filepath.Join(t.TempDir(), "fafnir-test")
			if e := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
				t.Fatal(e)
			}
			if e := f.p.InstallHook(exe); e == nil {
				t.Fatal("reported installed hook Git would not execute")
			}
		})
	}
}
