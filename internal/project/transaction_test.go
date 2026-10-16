package project

import (
	"bytes"
	"encoding/json"
	"github.com/lucasfth/fafnir/internal/crypt"
	"os"
	"path/filepath"
	"testing"
)

func TestInterruptedAccessChangeRollsBackOnNextOperation(t *testing.T) {
	for _, boundary := range []string{"journal", "artifact", "policy", "approval"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			defer f.p.Close()
			f.put(t, ".env", "TOKEN=synthetic\n")
			f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
			if e := f.p.Seal(".env", f.identity, false); e != nil {
				t.Fatal(e)
			}
			oldCipher, _ := os.ReadFile(filepath.Join(f.root, ".env.fafnir"))
			oldPolicy, _ := os.ReadFile(filepath.Join(f.root, policyName))
			oldApproval, _, _ := f.p.readApproval()
			other, _ := cryptIdentity(t)
			newCipher, e := crypt.Rekey(oldCipher, f.identity, []string{f.recipient}, []string{f.recipient, other})
			if e != nil {
				t.Fatal(e)
			}
			newConfig, e := f.p.Config()
			if e != nil {
				t.Fatal(e)
			}
			newConfig.Pairs[0].Recipients = append(newConfig.Pairs[0].Recipients, other)
			newPolicy, _ := json.MarshalIndent(newConfig, "", "  ")
			newPolicy = append(newPolicy, '\n')
			tx := accessTransaction{Root: f.p.rootPath, Artifact: ".env.fafnir", OldCipher: oldCipher, NewCipher: newCipher, OldPolicy: oldPolicy, NewPolicy: newPolicy, OldApproval: oldApproval}
			if e = f.p.saveTransaction(tx); e != nil {
				t.Fatal(e)
			}
			if boundary != "journal" {
				if e = f.p.atomicWrite(".env.fafnir", newCipher, 0600, oldCipher, true); e != nil {
					t.Fatal(e)
				}
			}
			if boundary == "policy" || boundary == "approval" {
				if e = f.p.atomicWrite(policyName, newPolicy, 0600, oldPolicy, true); e != nil {
					t.Fatal(e)
				}
			}
			if boundary == "approval" {
				if e = f.p.saveApproval(newConfig, oldApproval, true); e != nil {
					t.Fatal(e)
				}
			}
			p, e := Open(f.root, f.state)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if _, e = p.Config(); e != nil {
				t.Fatal("recovery failed", e)
			}
			restored, _ := os.ReadFile(filepath.Join(f.root, ".env.fafnir"))
			if !bytes.Equal(restored, oldCipher) {
				t.Fatal("previous artifact not recovered")
			}
			if _, e = p.Decrypt(".env", f.identity); e != nil {
				t.Fatal("owner lost decryption after recovery", e)
			}
		})
	}
}
