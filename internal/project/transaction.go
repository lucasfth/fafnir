package project

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// accessTransaction contains ciphertext/public policy only, never plaintext secrets.
// The journal lives in the approved external private state directory.
type accessTransaction struct {
	Root        string `json:"root"`
	Artifact    string `json:"artifact"`
	OldCipher   []byte `json:"old_cipher"`
	NewCipher   []byte `json:"new_cipher"`
	OldPolicy   []byte `json:"old_policy"`
	NewPolicy   []byte `json:"new_policy"`
	OldApproval []byte `json:"old_approval"`
	Initialize  bool   `json:"initialize,omitempty"`
}

func (p *Project) journalName() string { return p.lockName + ".transaction" }
func (p *Project) saveTransaction(tx accessTransaction) error {
	data, e := json.Marshal(tx)
	if e != nil {
		return safeError()
	}
	return p.atomicStateWrite(p.journalName(), data, nil, false)
}

// recoverTransaction rolls back interrupted access changes. Never overwrite an
// unrelated edit: such a conflict retains the journal and stops all operations.
func (p *Project) recoverTransaction() error {
	name := p.journalName()
	st, e := p.state.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 24<<20 {
		return safeError()
	}
	f, e := p.state.Open(name)
	if e != nil {
		return safeError()
	}
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		f.Close()
		return safeError()
	}
	data, e := io.ReadAll(io.LimitReader(f, 24<<20+1))
	f.Close()
	if e != nil || len(data) > 24<<20 {
		return safeError()
	}
	var tx accessTransaction
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&tx) != nil || tx.Root != p.rootPath || (!tx.Initialize && !safeRel(tx.Artifact)) {
		return safeError()
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return safeError()
	}
	if tx.Initialize {
		return p.recoverInitialization(tx, name)
	}
	oldConfig, e := decodeConfig(tx.OldPolicy)
	if e != nil {
		return safeError()
	}
	newConfig, e := decodeConfig(tx.NewPolicy)
	if e != nil {
		return safeError()
	}
	if len(oldConfig.Pairs) != len(newConfig.Pairs) {
		return safeError()
	}
	var approvalData approval
	if json.Unmarshal(tx.OldApproval, &approvalData) != nil || approvalData.Root != p.rootPath {
		return safeError()
	}
	digest, e := configDigest(oldConfig)
	if e != nil || approvalData.Digest != digest {
		return safeError()
	}
	curCipher, _, e := p.readFile(tx.Artifact, maxBlobSize, false)
	if e != nil || !bytes.Equal(curCipher, tx.OldCipher) && !bytes.Equal(curCipher, tx.NewCipher) {
		return safeError()
	}
	curPolicy, _, e := p.readFile(policyName, maxPolicySize, false)
	if e != nil || !bytes.Equal(curPolicy, tx.OldPolicy) && !bytes.Equal(curPolicy, tx.NewPolicy) {
		return safeError()
	}
	currentApproval, exists, e := p.readApproval()
	if e != nil || !exists {
		return safeError()
	}
	if !bytes.Equal(curCipher, tx.OldCipher) {
		if e = p.atomicWrite(tx.Artifact, tx.OldCipher, 0600, curCipher, true); e != nil {
			return e
		}
	}
	if !bytes.Equal(curPolicy, tx.OldPolicy) {
		if e = p.atomicWrite(policyName, tx.OldPolicy, 0600, curPolicy, true); e != nil {
			return e
		}
	}
	if !bytes.Equal(currentApproval, tx.OldApproval) {
		if e = p.atomicStateWrite(p.approvalPath(), tx.OldApproval, currentApproval, true); e != nil {
			return e
		}
	}
	if e = p.state.Remove(name); e != nil {
		return safeError()
	}
	return syncDirectory(p.state, ".")
}

func (p *Project) recoverInitialization(tx accessTransaction, name string) error {
	if _, e := decodeConfig(tx.NewPolicy); e != nil {
		return e
	}
	current, _, exists, e := p.readOptional(policyName, maxPolicySize, false)
	if e != nil {
		return e
	}
	if exists && !bytes.Equal(current, tx.OldPolicy) && !bytes.Equal(current, tx.NewPolicy) {
		return safeError()
	}
	approvalBytes, hasApproval, e := p.readApproval()
	if e != nil {
		return e
	}
	if len(tx.OldPolicy) > 0 {
		old, e := decodeConfig(tx.OldPolicy)
		if e != nil {
			return e
		}
		if !exists {
			return safeError()
		}
		if !bytes.Equal(current, tx.OldPolicy) {
			if e = p.atomicWrite(policyName, tx.OldPolicy, 0600, current, true); e != nil {
				return e
			}
		}
		if !hasApproval {
			return safeError()
		}
		var a approval
		if json.Unmarshal(tx.OldApproval, &a) != nil {
			return safeError()
		}
		digest, e := configDigest(old)
		if e != nil || a.Root != p.rootPath || a.Digest != digest {
			return safeError()
		}
		if !bytes.Equal(approvalBytes, tx.OldApproval) {
			if e = p.atomicStateWrite(p.approvalPath(), tx.OldApproval, approvalBytes, true); e != nil {
				return e
			}
		}
	} else {
		if exists {
			if e = p.root.Remove(policyName); e != nil {
				return safeError()
			}
			if e = syncDirectory(p.root, "."); e != nil {
				return e
			}
		}
		if hasApproval {
			if e = p.state.Remove(p.approvalPath()); e != nil {
				return safeError()
			}
			if e = syncDirectory(p.state, "."); e != nil {
				return e
			}
		}
	}
	if e = p.state.Remove(name); e != nil {
		return safeError()
	}
	return syncDirectory(p.state, ".")
}
