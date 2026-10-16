package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInterruptedInitializationAllowsOrdinaryRetry(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "first", true: "additional"}[existing], func(t *testing.T) {
			f := newFixture(t)
			defer f.p.Close()
			var oldPolicy, oldApproval []byte
			var next Config
			if existing {
				f.initialize(t, Pair{Plain: ".env", Encrypted: ".env.fafnir", Recipients: []string{f.recipient}})
				oldPolicy, _ = os.ReadFile(filepath.Join(f.root, policyName))
				oldApproval, _, _ = f.p.readApproval()
				next, _ = f.p.Config()
			} else {
				next = Config{Version: 1}
			}
			pair := Pair{Plain: ".env.extra", Encrypted: ".env.extra.fafnir", Recipients: []string{f.recipient}}
			next.Pairs = append(next.Pairs, pair)
			newPolicy, _ := json.MarshalIndent(next, "", "  ")
			newPolicy = append(newPolicy, '\n')
			if e := f.p.saveTransaction(accessTransaction{Root: f.p.rootPath, Initialize: true, OldPolicy: oldPolicy, NewPolicy: newPolicy, OldApproval: oldApproval}); e != nil {
				t.Fatal(e)
			}
			if e := f.p.atomicWrite(policyName, newPolicy, 0600, oldPolicy, existing); e != nil {
				t.Fatal(e)
			}
			p, e := Open(f.root, f.state)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if e = p.Init(Config{Version: 1, Pairs: []Pair{pair}}); e != nil {
				t.Fatal("ordinary init retry failed after interruption", e)
			}
		})
	}
}
