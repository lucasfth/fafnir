package custody

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testIdentity(t *testing.T) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("generate synthetic identity")
	}
	return identity.String()
}

func TestFileStoreRoundTripAndDelete(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "identity")
	store := NewFile(path)
	identity := testIdentity(t)
	if _, err := store.Get(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: got %v, want ErrNotFound", err)
	}
	if err := store.Set(identity); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get()
	if err != nil || got != identity {
		t.Fatalf("Get = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat identity", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions = %04o, want 0600", info.Mode().Perm())
	}
	if err := store.Set(identity); err != nil {
		t.Fatalf("setting identical identity: %v", err)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get deleted: got %v, want ErrNotFound", err)
	}
}

func TestFileStoreDoesNotReplaceDifferentIdentity(t *testing.T) {
	store := NewFile(filepath.Join(privateTempDir(t), "identity"))
	first, second := testIdentity(t), testIdentity(t)
	if err := store.Set(first); err != nil {
		t.Fatal("initial Set", err)
	}
	if err := store.Set(second); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Set different identity: got %v, want ErrAlreadyExists", err)
	}
	got, err := store.Get()
	if err != nil || got != first {
		t.Fatalf("identity changed: got %q, %v", got, err)
	}
}

func TestFileStoreRejectsSymlink(t *testing.T) {
	dir := privateTempDir(t)
	target := filepath.Join(dir, "target")
	identity := testIdentity(t)
	if err := os.WriteFile(target, []byte(identity), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "identity")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	store := NewFile(link)
	if _, err := store.Get(); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Get symlink: got %v, want ErrUnsafePath", err)
	}
	if err := store.Set(testIdentity(t)); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Set symlink: got %v, want ErrUnsafePath", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != identity {
		t.Fatalf("symlink target changed: got %q, %v", got, err)
	}
}

func TestFileStoreAllowsResolvedPrivateParent(t *testing.T) {
	dir := privateTempDir(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	store := NewFile(filepath.Join(alias, "identity"))
	identity := testIdentity(t)
	if err := store.Set(identity); err != nil {
		t.Fatalf("Set through platform parent alias: %v", err)
	}
	if got, err := store.Get(); err != nil || got != identity {
		t.Fatalf("Get through platform parent alias: matched=%t, err=%v", got == identity, err)
	}
}

func TestFileStoreRejectsMalformedOrOversizedIdentityWithoutLeaking(t *testing.T) {
	for name, contents := range map[string]string{
		"malformed": "not-an-age-identity\n",
		"oversized": strings.Repeat("x", maxIdentityBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "identity")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := NewFile(path).Get()
			if err == nil {
				t.Fatal("Get accepted invalid identity")
			}
			if strings.Contains(err.Error(), contents) {
				t.Fatal("error contains identity input")
			}
		})
	}
}

func TestFileStoreRejectsInsecureFilePermissions(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "identity")
	if err := os.WriteFile(path, []byte(testIdentity(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFile(path).Get(); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("Get insecure file: got %v, want ErrInsecurePermissions", err)
	}
}

func TestFileStoreRejectsInsecureParentPermissions(t *testing.T) {
	parent := privateTempDir(t)
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := NewFile(filepath.Join(parent, "identity")).Set(testIdentity(t)); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("Set with insecure parent: got %v, want ErrInsecurePermissions", err)
	}
}
func TestFileStoreRejectsRepositoryAncestors(t *testing.T) {
	for _, name := range []string{"indexed-missing", "new-unignored"} {
		t.Run(name, func(t *testing.T) {
			root := privateTempDir(t)
			git := filepath.Join(root, ".git")
			if err := os.Mkdir(git, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(git, "index"), []byte("synthetic-index"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "nested", "backup")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			err := NewFile(path).Set(testIdentity(t))
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Set in repository: got %v, want ErrUnsafePath", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("repository export path was created: %v", err)
			}
		})
	}
}

func TestKeychainRoundTripOptIn(t *testing.T) {
	if os.Getenv("FAFNIR_TEST_KEYCHAIN") != "1" {
		t.Skip("set FAFNIR_TEST_KEYCHAIN=1 to use the native keychain")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("generate random test account")
	}
	store := NewKeychain("fafnir-test-" + hex.EncodeToString(random[:]))
	defer func() {
		if err := store.Delete(); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("delete disposable keychain item: %v", err)
		}
	}()
	identity := testIdentity(t)
	if err := store.Set(identity); err != nil {
		t.Fatal("Set disposable keychain item", err)
	}
	got, err := store.Get()
	if err != nil || got != identity {
		t.Fatalf("Get disposable keychain item: matched=%t, err=%v", got == identity, err)
	}
}
