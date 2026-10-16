// Package project provides rooted, locally approved repository-secret operations.
package project

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/lucasfth/fafnir/internal/crypt"
	"golang.org/x/text/unicode/norm"
)

const policyName = ".fafnir.json"
const maxPolicySize = 1 << 20
const maxBlobSize = crypt.MaxCiphertextSize

// Pair binds one ignored plaintext dotenv path to its sole ciphertext artifact.
type Pair struct {
	Plain      string   `json:"plain"`
	Encrypted  string   `json:"encrypted"`
	Recipients []string `json:"recipients"`
}

// Config is the public, repository-stored access policy.
type Config struct {
	Version int    `json:"version"`
	Pairs   []Pair `json:"pairs"`
}

type approval struct {
	Version int    `json:"version"`
	Root    string `json:"root"`
	Digest  string `json:"digest"`
}

// Project binds operations to one canonical Git root and one external state directory.
type Project struct {
	rootPath  string
	statePath string
	root      *os.Root
	state     *os.Root
	lockName  string
	mu        sync.Mutex
}

var gitPath string
var gitPathOnce sync.Once
var validObjectID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func safeError() error {
	return errors.New("project operation failed; verify repository policy, paths, and local trust")
}

// Open locates the repository using Git with a minimal environment and returns a
// root capability; all configured file reads and writes remain beneath that root.
func Open(dir, stateDir string) (*Project, error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, safeError()
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return nil, safeError()
	}
	out, err := runGitAt(abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, safeError()
	}
	rootPath, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, safeError()
	}
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return nil, safeError()
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, safeError()
	}
	if stateDir == "" {
		root.Close()
		return nil, safeError()
	}
	stateAbs, err := filepath.Abs(stateDir)
	if err != nil {
		root.Close()
		return nil, safeError()
	}
	if err = ensurePrivateDirectory(stateAbs); err != nil {
		root.Close()
		return nil, safeError()
	}
	stateReal, err := filepath.EvalSymlinks(stateAbs)
	if err != nil {
		root.Close()
		return nil, safeError()
	}
	rel, err := filepath.Rel(rootPath, stateReal)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		root.Close()
		return nil, safeError()
	}
	stateRoot, err := os.OpenRoot(stateReal)
	if err != nil {
		root.Close()
		return nil, safeError()
	}
	sum := sha256.Sum256([]byte(rootPath))
	return &Project{rootPath: rootPath, statePath: stateReal, root: root, state: stateRoot, lockName: hex.EncodeToString(sum[:])}, nil
}

// Close releases repository and external state root capabilities.
func (p *Project) Close() error {
	if p == nil {
		return nil
	}
	err := p.root.Close()
	if stateErr := p.state.Close(); err == nil {
		err = stateErr
	}
	return err
}

func gitExecutable() (string, error) {
	gitPathOnce.Do(func() {
		for _, candidate := range []string{"/usr/bin/git", "/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"} {
			st, err := os.Stat(candidate)
			if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
				gitPath = candidate
				return
			}
		}
	})
	if gitPath == "" {
		return "", safeError()
	}
	return gitPath, nil
}

func gitEnv() []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=", "LC_ALL=C"}
}

func runGitAt(dir string, args ...string) ([]byte, error) {
	exe, err := gitExecutable()
	if err != nil {
		return nil, err
	}
	all := []string{"-c", "core.hooksPath=/dev/null", "--no-pager", "-C", dir}
	all = append(all, args...)
	cmd := exec.Command(exe, all...)
	cmd.Env = gitEnv()
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, safeError()
	}
	return out.Bytes(), nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 32<<20 {
		return 0, safeError()
	}
	return b.Buffer.Write(p)
}

func (p *Project) withLock(fn func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return withFileLock(p.statePath, p.lockName, func() error {
		if e := p.recoverTransaction(); e != nil {
			return e
		}
		return fn()
	})
}

func withFileLock(stateDir, name string, fn func() error) error {
	path := filepath.Join(stateDir, name+".lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return safeError()
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return safeError()
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return safeError()
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}
func ensurePrivateDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return safeError()
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if errors.Is(err, os.ErrNotExist) {
		if err = ensurePrivateDirectory(filepath.Dir(abs)); err != nil {
			return err
		}
		parent, err = filepath.EvalSymlinks(filepath.Dir(abs))
	}
	if err != nil {
		return safeError()
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return safeError()
	}
	defer root.Close()
	name := filepath.Base(abs)
	st, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err = root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return safeError()
		}
		st, err = root.Lstat(name)
	}
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return safeError()
	}
	return nil
}

func (p *Project) checkRelParents(rel string) error {
	if !safeRel(rel) {
		return safeError()
	}
	parts := strings.Split(filepath.FromSlash(rel), string(filepath.Separator))
	cur := ""
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		st, err := p.root.Lstat(cur)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return safeError()
		}
	}
	return nil
}

func safeRel(v string) bool {
	if v == "" || strings.ContainsAny(v, "\\:\x00") || filepath.IsAbs(v) || strings.HasPrefix(v, "/") {
		return false
	}
	if strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\t*?[]!#") {
		return false
	}
	if filepath.ToSlash(filepath.Clean(filepath.FromSlash(v))) != v || v == "." {
		return false
	}
	for _, c := range strings.Split(v, "/") {
		if c == "" || c == "." || c == ".." || strings.HasPrefix(c, ".git") && c == ".git" {
			return false
		}
	}
	return true
}

func normalizeConfig(c Config) (Config, error) {
	if c.Version != 1 || len(c.Pairs) == 0 || len(c.Pairs) > 128 {
		return Config{}, safeError()
	}
	out := Config{Version: 1, Pairs: make([]Pair, len(c.Pairs))}
	seenPaths := make([]string, 0, len(c.Pairs)*2)
	for i, p := range c.Pairs {
		if !safeRel(p.Plain) || !safeRel(p.Encrypted) || p.Encrypted != p.Plain+".fafnir" || strings.EqualFold(p.Plain, policyName) || strings.EqualFold(p.Encrypted, policyName) || strings.HasPrefix(strings.ToLower(p.Plain), ".git/") || strings.HasPrefix(strings.ToLower(p.Encrypted), ".git/") || pathAlias(seenPaths, p.Plain) || pathAlias(seenPaths, p.Encrypted) || strings.EqualFold(p.Plain, p.Encrypted) {
			return Config{}, safeError()
		}
		if crypt.ValidateRecipients(p.Recipients) != nil {
			return Config{}, safeError()
		}
		seenPaths = append(seenPaths, p.Plain, p.Encrypted)
		out.Pairs[i] = Pair{Plain: p.Plain, Encrypted: p.Encrypted, Recipients: append([]string(nil), p.Recipients...)}
		sort.Strings(out.Pairs[i].Recipients)
	}
	sort.Slice(out.Pairs, func(i, j int) bool { return out.Pairs[i].Plain < out.Pairs[j].Plain })
	return out, nil
}

func pathAlias(paths []string, path string) bool {
	for _, candidate := range paths {
		if strings.EqualFold(norm.NFC.String(candidate), norm.NFC.String(path)) {
			return true
		}
	}
	return false
}

func (p *Project) readFile(rel string, limit int64, private bool) ([]byte, os.FileInfo, error) {
	if p.checkRelParents(rel) != nil {
		return nil, nil, safeError()
	}
	info, err := p.root.Lstat(rel)
	if err != nil {
		return nil, nil, safeError()
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, nil, safeError()
	}
	f, err := p.root.OpenFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, safeError()
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, safeError()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, nil, safeError()
	}
	return data, info, nil
}

func (p *Project) readOptional(rel string, limit int64, private bool) ([]byte, os.FileInfo, bool, error) {
	if p.checkRelParents(rel) != nil {
		return nil, nil, false, safeError()
	}
	info, err := p.root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, nil, false, safeError()
	}
	data, info, err := p.readFile(rel, limit, private)
	return data, info, err == nil, err
}

func decodeConfig(data []byte) (Config, error) {
	if len(data) == 0 || len(data) > maxPolicySize {
		return Config{}, safeError()
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if dec.Decode(&c) != nil {
		return Config{}, safeError()
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return Config{}, safeError()
	}
	return normalizeConfig(c)
}

func canonicalConfig(c Config) ([]byte, error) {
	n, err := normalizeConfig(c)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(n)
	if err != nil {
		return nil, safeError()
	}
	return b, nil
}

func configDigest(c Config) (string, error) {
	b, err := canonicalConfig(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ReadPolicy parses and validates repository-controlled policy but deliberately
// does not assert local trust. Use only to display a policy before explicit approval.
func (p *Project) ReadPolicy() (Config, error) {
	b, _, err := p.readFile(policyName, maxPolicySize, false)
	if err != nil {
		return Config{}, safeError()
	}
	return decodeConfig(b)
}

func (p *Project) configUnlocked() (Config, error) {
	c, err := p.ReadPolicy()
	if err != nil {
		return Config{}, err
	}
	if err = p.checkApproval(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Config returns a policy only if it matches this machine's external approval.
func (p *Project) Config() (Config, error) {
	var c Config
	err := p.withLock(func() error { var e error; c, e = p.configUnlocked(); return e })
	if err != nil {
		return Config{}, safeError()
	}
	return c, nil
}

func (p *Project) approvalPath() string { return p.lockName + ".json" }
func (p *Project) readApproval() ([]byte, bool, error) {
	name := p.approvalPath()
	info, err := p.state.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return nil, false, safeError()
	}
	f, err := p.state.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, false, safeError()
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, safeError()
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, false, safeError()
	}
	return data, true, nil
}

func (p *Project) checkApproval(c Config) error {
	data, exists, err := p.readApproval()
	if err != nil || !exists {
		return safeError()
	}
	var a approval
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&a) != nil || a.Version != 1 || a.Root != p.rootPath {
		return safeError()
	}
	digest, err := configDigest(c)
	if err != nil || a.Digest != digest {
		return safeError()
	}
	return nil
}

func (p *Project) saveApproval(c Config, expected []byte, exists bool) error {
	digest, err := configDigest(c)
	if err != nil {
		return err
	}
	data, err := json.Marshal(approval{Version: 1, Root: p.rootPath, Digest: digest})
	if err != nil {
		return safeError()
	}
	data = append(data, '\n')
	return p.atomicStateWrite(p.approvalPath(), data, expected, exists)
}

func (p *Project) locatePair(c Config, plain string) (int, Pair, error) {
	if !safeRel(plain) {
		return -1, Pair{}, safeError()
	}
	for i, pair := range c.Pairs {
		if pair.Plain == plain {
			return i, pair, nil
		}
	}
	return -1, Pair{}, safeError()
}

func (p *Project) ensureNotTracked(plain string) error {
	tracked, e := p.trackedPaths()
	if e != nil || trackedAlias(tracked, plain) {
		return safeError()
	}
	return nil
}

func (p *Project) trackedPaths() (map[string]bool, error) {
	out, err := runGitAt(p.rootPath, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, safeError()
	}
	tracked := make(map[string]bool)
	for _, entry := range bytes.Split(out, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		tab := bytes.IndexByte(entry, '\t')
		if tab < 0 {
			return nil, safeError()
		}
		path := string(entry[tab+1:])
		tracked[path] = true
	}
	return tracked, nil
}

func trackedAlias(tracked map[string]bool, path string) bool {
	for candidate := range tracked {
		if strings.EqualFold(norm.NFC.String(candidate), norm.NFC.String(path)) {
			return true
		}
	}
	return false
}

func (p *Project) updateIgnore(c Config) error {
	var data []byte
	var old []byte
	exists := false
	old, _, exists, err := p.readOptional(".gitignore", maxPolicySize, false)
	if err != nil {
		return err
	}
	if exists {
		data = append(data, old...)
	}
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "!*.fafnir" || trim == "!**/*.fafnir" || strings.HasPrefix(trim, "# fafnir managed ") || trim == "# fafnir managed end" {
			continue
		}
		kept = append(kept, line)
	}
	for len(kept) > 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	if len(kept) > 0 {
		kept = append(kept, "")
	}
	kept = append(kept, "# fafnir managed paths")
	for _, pair := range c.Pairs {
		kept = append(kept, "/"+pair.Plain)
	}
	for _, pair := range c.Pairs {
		kept = append(kept, "!/"+pair.Encrypted)
	}
	kept = append(kept, "# fafnir managed end", "")
	mode := os.FileMode(0644)
	if exists {
		info, e := p.root.Lstat(".gitignore")
		if e != nil {
			return safeError()
		}
		mode = info.Mode().Perm()
	}
	if err = p.atomicWrite(".gitignore", []byte(strings.Join(kept, "\n")), mode, old, exists); err != nil {
		return err
	}
	for _, pair := range c.Pairs {
		if _, err = runGitAt(p.rootPath, "check-ignore", "--no-index", "--", pair.Plain); err != nil {
			return safeError()
		}
		out, e := runGitAt(p.rootPath, "check-ignore", "--no-index", "-v", "--", pair.Encrypted)
		if e == nil {
			fields := strings.SplitN(string(out), "\t", 2)
			if len(fields) < 2 || !strings.Contains(fields[0], ":!") {
				return safeError()
			}
		}
	}
	return nil
}

// Init adds explicitly requested pairs to the existing trusted policy, writes
// exact ignore exceptions, then pins the new policy in external local state.
func (p *Project) Init(c Config) error {
	return p.withLock(func() error {
		if c.Version != 1 || len(c.Pairs) == 0 {
			return safeError()
		}
		for _, pair := range c.Pairs {
			if err := p.ensureNotTracked(pair.Plain); err != nil {
				return err
			}
		}
		requested, err := normalizeConfig(c)
		if err != nil {
			return err
		}
		oldRaw, _, hasPolicy, err := p.readOptional(policyName, maxPolicySize, false)
		if err != nil {
			return err
		}
		var current Config
		oldApproval, hasApproval, err := p.readApproval()
		if err != nil {
			return err
		}
		if hasPolicy {
			current, err = decodeConfig(oldRaw)
			if err != nil {
				return err
			}
			if !hasApproval || p.checkApproval(current) != nil {
				return safeError()
			}
		} else if hasApproval {
			return safeError()
		} else {
			current = Config{Version: 1}
		}
		byPlain := make(map[string]Pair, len(current.Pairs)+len(requested.Pairs))
		for _, pair := range current.Pairs {
			byPlain[pair.Plain] = pair
		}
		for _, pair := range requested.Pairs {
			if existing, ok := byPlain[pair.Plain]; ok {
				if existing.Encrypted != pair.Encrypted || !sameStrings(existing.Recipients, pair.Recipients) {
					return safeError()
				}
				continue
			}
			byPlain[pair.Plain] = pair
		}
		merged := Config{Version: 1, Pairs: make([]Pair, 0, len(byPlain))}
		for _, pair := range byPlain {
			merged.Pairs = append(merged.Pairs, pair)
		}
		merged, err = normalizeConfig(merged)
		if err != nil {
			return err
		}
		newRaw, err := json.MarshalIndent(merged, "", "  ")
		if err != nil {
			return safeError()
		}
		newRaw = append(newRaw, '\n')
		if err = p.updateIgnore(merged); err != nil {
			return err
		}
		tx := accessTransaction{Root: p.rootPath, Initialize: true, OldPolicy: oldRaw, NewPolicy: newRaw, OldApproval: oldApproval}
		if err = p.saveTransaction(tx); err != nil {
			return err
		}
		if !hasPolicy || !bytes.Equal(oldRaw, newRaw) {
			if err = p.atomicWrite(policyName, newRaw, 0600, oldRaw, hasPolicy); err != nil {
				_ = p.recoverTransaction()
				return err
			}
		}
		if err = p.saveApproval(merged, oldApproval, hasApproval); err != nil {
			_ = p.recoverTransaction()
			return err
		}
		if err = p.state.Remove(p.journalName()); err != nil {
			return safeError()
		}
		return syncDirectory(p.state, ".")
	})
}

// Approve records the policy only when it still matches the policy the caller reviewed.
func (p *Project) Approve(reviewed Config) error {
	return p.withLock(func() error {
		c, err := p.ReadPolicy()
		if err != nil {
			return err
		}
		expected, err := configDigest(reviewed)
		if err != nil {
			return err
		}
		actual, err := configDigest(c)
		if err != nil || actual != expected {
			return safeError()
		}
		old, exists, err := p.readApproval()
		if err != nil {
			return err
		}
		return p.saveApproval(c, old, exists)
	})
}

func sameStrings(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func (p *Project) filePair(plain string) (Config, Pair, error) {
	c, err := p.configUnlocked()
	if err != nil {
		return Config{}, Pair{}, err
	}
	_, pair, err := p.locatePair(c, plain)
	return c, pair, err
}

func (p *Project) Seal(plain, identity string, replace bool) error {
	return p.withLock(func() error {
		c, pair, err := p.filePair(plain)
		if err != nil {
			return err
		}
		_ = c
		if err = p.ensureNotTracked(plain); err != nil {
			return err
		}
		plainData, _, err := p.readFile(pair.Plain, crypt.MaxFileSize, false)
		if err != nil {
			return err
		}
		cipherData, err := crypt.Encrypt(plainData, pair.Recipients)
		if err != nil {
			return safeError()
		}
		if _, err := crypt.Decrypt(cipherData, identity, pair.Recipients); err != nil {
			return safeError()
		}
		old, _, exists, err := p.readOptional(pair.Encrypted, maxBlobSize, false)
		if err != nil {
			return err
		}
		if exists && bytes.Equal(old, cipherData) {
			return nil
		}
		if exists && !replace {
			return safeError()
		}
		return p.atomicWrite(pair.Encrypted, cipherData, 0600, old, exists)
	})
}

func (p *Project) decryptUnlocked(plain, identity string) ([]byte, Pair, error) {
	_, pair, err := p.filePair(plain)
	if err != nil {
		return nil, Pair{}, err
	}
	cipherData, _, err := p.readFile(pair.Encrypted, maxBlobSize, false)
	if err != nil {
		return nil, Pair{}, err
	}
	decrypted, err := crypt.Decrypt(cipherData, identity, pair.Recipients)
	if err != nil {
		return nil, Pair{}, safeError()
	}
	return decrypted, pair, nil
}

// Decrypt authenticates a selected artifact before returning any plaintext bytes.
func (p *Project) Decrypt(plain, identity string) ([]byte, error) {
	var result []byte
	err := p.withLock(func() error {
		data, _, e := p.decryptUnlocked(plain, identity)
		if e == nil {
			result = append([]byte(nil), data...)
		}
		return e
	})
	if err != nil {
		return nil, safeError()
	}
	return result, nil
}

func (p *Project) Restore(plain, identity string, replace bool) error {
	return p.withLock(func() error {
		if err := p.ensureNotTracked(plain); err != nil {
			return err
		}
		data, pair, err := p.decryptUnlocked(plain, identity)
		if err != nil {
			return err
		}
		old, _, exists, err := p.readOptional(pair.Plain, crypt.MaxFileSize, true)
		if err != nil {
			return err
		}
		if exists && bytes.Equal(old, data) {
			return nil
		}
		if exists && !replace {
			return safeError()
		}
		return p.atomicWrite(pair.Plain, data, 0600, old, exists)
	})
}

// Grant replaces the selected pair's complete recipient list and rekeys only its artifact.
func (p *Project) Grant(plain, identity string, recipients []string) error {
	return p.withLock(func() error {
		if crypt.ValidateRecipients(recipients) != nil {
			return safeError()
		}
		oldConfig, pair, err := p.filePair(plain)
		if err != nil {
			return err
		}
		if _, _, _, err = p.readOptional(".gitignore", maxPolicySize, false); err != nil {
			return err
		}
		oldCipher, _, err := p.readFile(pair.Encrypted, maxBlobSize, false)
		if err != nil {
			return err
		}
		if _, err = crypt.Decrypt(oldCipher, identity, pair.Recipients); err != nil {
			return safeError()
		}
		newCipher, err := crypt.Rekey(oldCipher, identity, pair.Recipients, recipients)
		if err != nil {
			return safeError()
		}
		if err = crypt.Inspect(newCipher, recipients); err != nil {
			return safeError()
		}
		idx, _, _ := p.locatePair(oldConfig, plain)
		newConfig := oldConfig
		newConfig.Pairs = append([]Pair(nil), oldConfig.Pairs...)
		newConfig.Pairs[idx].Recipients = append([]string(nil), recipients...)
		newConfig, err = normalizeConfig(newConfig)
		if err != nil {
			return err
		}
		oldPolicy, _, _, err := p.readOptional(policyName, maxPolicySize, false)
		if err != nil {
			return err
		}
		oldApproval, hasApproval, err := p.readApproval()
		if err != nil || !hasApproval {
			return safeError()
		}
		newPolicy, err := json.MarshalIndent(newConfig, "", "  ")
		if err != nil {
			return safeError()
		}
		newPolicy = append(newPolicy, '\n')
		tx := accessTransaction{Root: p.rootPath, Artifact: pair.Encrypted, OldCipher: oldCipher, NewCipher: newCipher, OldPolicy: oldPolicy, NewPolicy: newPolicy, OldApproval: oldApproval}
		if err = p.saveTransaction(tx); err != nil {
			return err
		}
		if err = p.atomicWrite(pair.Encrypted, newCipher, 0600, oldCipher, true); err != nil {
			_ = p.recoverTransaction()
			return err
		}
		if err = p.atomicWrite(policyName, newPolicy, 0600, oldPolicy, true); err != nil {
			_ = p.recoverTransaction()
			return err
		}
		if err = p.saveApproval(newConfig, oldApproval, true); err != nil {
			_ = p.recoverTransaction()
			return err
		}
		if err = p.state.Remove(p.journalName()); err != nil {
			return safeError()
		}
		return syncDirectory(p.state, ".")
	})
}

func (p *Project) stagedEntries() (map[string][]byte, error) {
	c, e := p.configUnlocked()
	if e != nil {
		return nil, e
	}
	wanted := map[string]bool{policyName: true}
	for _, pair := range c.Pairs {
		wanted[pair.Encrypted] = true
	}
	out, e := runGitAt(p.rootPath, "ls-files", "--stage", "-z")
	if e != nil {
		return nil, e
	}
	entries := map[string][]byte{}
	for _, entry := range bytes.Split(out, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		meta, path, ok := strings.Cut(string(entry), "\t")
		if !ok {
			return nil, safeError()
		}
		if !wanted[path] {
			continue
		}
		parts := strings.Fields(meta)
		if len(parts) != 3 || parts[0] != "100644" && parts[0] != "100755" || parts[2] != "0" || !validObjectID.MatchString(parts[1]) {
			return nil, safeError()
		}
		if _, ok := entries[path]; ok {
			return nil, safeError()
		}
		size, e := runGitAt(p.rootPath, "cat-file", "-s", parts[1])
		if e != nil {
			return nil, e
		}
		n, e := strconv.ParseInt(strings.TrimSpace(string(size)), 10, 64)
		if e != nil || n < 0 || n > maxBlobSize {
			return nil, safeError()
		}
		blob, e := runGitAt(p.rootPath, "cat-file", "blob", parts[1])
		if e != nil || len(blob) > maxBlobSize {
			return nil, safeError()
		}
		entries[path] = blob
	}
	return entries, nil
}

func (p *Project) Check(staged bool, identity string) ([]string, error) {
	var messages []string
	err := p.withLock(func() error {
		c, err := p.configUnlocked()
		if err != nil {
			return err
		}
		tracked, err := p.trackedPaths()
		if err != nil {
			return err
		}
		for _, pair := range c.Pairs {
			if trackedAlias(tracked, pair.Plain) {
				messages = append(messages, "tracked plaintext: "+pair.Plain)
			}
		}
		if len(messages) > 0 {
			return safeError()
		}
		var snapshot map[string][]byte
		if staged {
			snapshot, err = p.stagedEntries()
			if err != nil {
				return err
			}
			policyData, ok := snapshot[policyName]
			if !ok {
				return safeError()
			}
			stagedConfig, e := decodeConfig(policyData)
			if e != nil {
				return safeError()
			}
			stagedDigest, e := configDigest(stagedConfig)
			if e != nil {
				return safeError()
			}
			trustedDigest, e := configDigest(c)
			if e != nil || stagedDigest != trustedDigest {
				return safeError()
			}
			messages = append(messages, "checking staged Git blobs; working files are not substitutes")
		} else {
			snapshot = make(map[string][]byte, len(c.Pairs))
			for _, pair := range c.Pairs {
				data, _, e := p.readFile(pair.Encrypted, maxBlobSize, false)
				if e != nil {
					return e
				}
				snapshot[pair.Encrypted] = data
			}
			messages = append(messages, "checking working-tree ciphertext structure and local policy")
		}
		for _, pair := range c.Pairs {
			cipherData, ok := snapshot[pair.Encrypted]
			if !ok {
				return safeError()
			}
			if err = crypt.Inspect(cipherData, pair.Recipients); err != nil {
				return safeError()
			}
			if identity == "" {
				continue
			}
			plainData, e := crypt.Decrypt(cipherData, identity, pair.Recipients)
			if e != nil {
				return safeError()
			}
			workPlain, _, exists, e := p.readOptional(pair.Plain, crypt.MaxFileSize, true)
			if e != nil {
				return e
			}
			if !exists {
				continue
			}
			plainEnv, e := crypt.ParseEnv(plainData)
			if e != nil {
				return safeError()
			}
			workEnv, e := crypt.ParseEnv(workPlain)
			if e != nil {
				return safeError()
			}
			if !maps.Equal(plainEnv, workEnv) {
				messages = append(messages, "sync mismatch: "+pair.Plain+" and "+pair.Encrypted)
				return safeError()
			}
		}
		if identity != "" {
			messages = append(messages, "ciphertext authenticated and synchronized with local plaintext")
		} else {
			messages = append(messages, "structure-only check; provide an identity to authenticate and compare plaintext")
		}
		return nil
	})
	if err != nil {
		return messages, safeError()
	}
	return messages, nil
}

// InstallHook installs only a fixed command invocation and refuses any existing hook.
func (p *Project) InstallHook(executable string) error {
	return p.withLock(func() error {
		c, err := p.configUnlocked()
		if err != nil {
			return err
		}
		_ = c
		if err = p.defaultHooksOnly(); err != nil {
			return err
		}
		exe, err := filepath.Abs(executable)
		if err != nil {
			return safeError()
		}
		st, err := os.Lstat(exe)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
			return safeError()
		}
		common, err := runGitAt(p.rootPath, "rev-parse", "--path-format=absolute", "--git-common-dir")
		if err != nil {
			return safeError()
		}
		gitDir := strings.TrimSpace(string(common))
		if !filepath.IsAbs(gitDir) {
			gitDir = filepath.Join(p.rootPath, gitDir)
		}
		gitDir, err = filepath.EvalSymlinks(gitDir)
		if err != nil {
			return safeError()
		}
		hooks := filepath.Join(gitDir, "hooks")
		if err = ensureHookDirectory(hooks); err != nil {
			return safeError()
		}
		path := filepath.Join(hooks, "pre-commit")
		if _, err = os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return safeError()
		}
		state := shellQuote(p.statePath)
		bin := shellQuote(exe)
		body := []byte("#!/bin/sh\ngit_dir=$(git rev-parse --absolute-git-dir) || exit 1\nexpected_index=$git_dir/index\nif [ -n \"${GIT_INDEX_FILE-}\" ]; then supplied_index=$(cd \"$(dirname \"$GIT_INDEX_FILE\")\" && pwd -P)/$(basename \"$GIT_INDEX_FILE\") || exit 1; [ \"$supplied_index\" = \"$expected_index\" ] || exit 1; fi\nexec " + bin + " --dir . --state-dir " + state + " check --staged\n")
		if err = writeNewHook(path, body); err != nil {
			return safeError()
		}
		return nil
	})
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func ensureHookDirectory(path string) error {
	parent := filepath.Dir(path)
	if st, err := os.Lstat(parent); err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return safeError()
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return safeError()
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}

func writeNewHook(path string, data []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0700)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, e := f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

func (p *Project) atomicWrite(rel string, data []byte, mode os.FileMode, expected []byte, exists bool) error {
	if p.checkRelParents(rel) != nil {
		return safeError()
	}
	current, _, nowExists, err := p.readOptional(rel, maxBlobSize, false)
	if err != nil {
		return err
	}
	if nowExists != exists || (exists && !bytes.Equal(current, expected)) {
		return safeError()
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return safeError()
	}
	tmp := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(rel)), ".fafnir-tmp-"+hex.EncodeToString(nonce[:])))
	if filepath.Dir(filepath.FromSlash(rel)) == "." {
		tmp = ".fafnir-tmp-" + hex.EncodeToString(nonce[:])
	}
	f, err := p.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return safeError()
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = p.root.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return safeError()
	}
	if err = f.Sync(); err != nil {
		return safeError()
	}
	if err = f.Close(); err != nil {
		return safeError()
	}
	latest, _, latestExists, err := p.readOptional(rel, maxBlobSize, false)
	if err != nil || latestExists != exists || (exists && !bytes.Equal(latest, expected)) {
		return safeError()
	}
	if exists {
		if err = p.root.Rename(tmp, rel); err != nil {
			return safeError()
		}
	} else {
		if err = p.root.Link(tmp, rel); err != nil {
			return safeError()
		}
		if err = p.root.Remove(tmp); err != nil {
			return safeError()
		}
	}
	if err = syncDirectory(p.root, filepath.Dir(rel)); err != nil {
		return err
	}
	ok = true
	return nil
}

func (p *Project) atomicStateWrite(rel string, data, expected []byte, exists bool) error {
	if !safeRel(rel) {
		return safeError()
	}
	current, err := p.state.ReadFile(rel)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return safeError()
	}
	nowExists := err == nil
	if nowExists != exists || (exists && !bytes.Equal(current, expected)) {
		return safeError()
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return safeError()
	}
	tmp := ".fafnir-tmp-" + hex.EncodeToString(nonce[:])
	f, err := p.state.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return safeError()
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		p.state.Remove(tmp)
		return safeError()
	}
	if err = f.Sync(); err != nil {
		f.Close()
		p.state.Remove(tmp)
		return safeError()
	}
	if err = f.Close(); err != nil {
		p.state.Remove(tmp)
		return safeError()
	}
	latest, err := p.state.ReadFile(rel)
	latestExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		p.state.Remove(tmp)
		return safeError()
	}
	if latestExists != exists || (exists && !bytes.Equal(latest, expected)) {
		p.state.Remove(tmp)
		return safeError()
	}
	if err = p.state.Rename(tmp, rel); err != nil {
		p.state.Remove(tmp)
		return safeError()
	}
	return syncDirectory(p.state, ".")
}

func (p *Project) defaultHooksOnly() error {
	exe, e := gitExecutable()
	if e != nil {
		return e
	}
	cmd := exec.Command(exe, "--no-pager", "-C", p.rootPath, "config", "--get", "core.hooksPath")
	// Read config only; this command cannot execute hooks. Include the user's global
	// config so a global hooksPath is not silently hidden by the inspection sandbox.
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="}
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil
	}
	return errors.New("custom or unreadable core.hooksPath; hook installation refused")
}

func syncDirectory(root *os.Root, path string) error {
	f, e := root.Open(path)
	if e != nil {
		return safeError()
	}
	defer f.Close()
	if e = f.Sync(); e != nil {
		return safeError()
	}
	return nil
}
