package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/lucasfth/fafnir/internal/crypt"
	"github.com/lucasfth/fafnir/internal/custody"
)

func testIdentity(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestNoninteractiveDoesNotPrompt(t *testing.T) {
	var out, diag bytes.Buffer
	code := Execute(context.Background(), nil, strings.NewReader(""), &out, &diag)
	if code == 0 || !strings.Contains(diag.String(), "command") {
		t.Fatalf("code=%d diagnostics=%q", code, diag.String())
	}
	if out.Len() != 0 {
		t.Fatal("UI polluted stdout")
	}
}

func TestSecretArgumentsAreNotEchoed(t *testing.T) {
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--private-key", "secret-sentinel"}, strings.NewReader(""), &out, &diag)
	if code == 0 || strings.Contains(diag.String(), "secret-sentinel") {
		t.Fatalf("unsafe arguments: %d %q", code, diag.String())
	}
}

func TestHelpDocumentsPublicPrivateBoundary(t *testing.T) {
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"help"}, strings.NewReader(""), &out, &diag)
	if code != 0 || !strings.Contains(out.String(), "public") || !strings.Contains(out.String(), "private") {
		t.Fatalf("help: %d %q %q", code, out.String(), diag.String())
	}
}

func TestKeyCreateRejectsInsecurePublicCacheBeforeStoringIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "identity")
	if err := os.WriteFile(key+".pub", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--key-file", key, "key", "create"}, strings.NewReader(""), &out, &diag)
	if code == 0 {
		t.Fatal("key create accepted a permissive public cache")
	}
	if _, err := os.Lstat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private identity was partially stored: %v", err)
	}
}

func TestKeyCreateRejectsSymlinkedPublicCacheParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(alias, "identity")
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--key-file", key, "key", "create"}, strings.NewReader(""), &out, &diag)
	if code == 0 {
		t.Fatal("key create accepted symlinked cache parent")
	}
	if _, err := os.Lstat(filepath.Join(target, "identity")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private identity was partially stored: %v", err)
	}
}

func TestKeyPublicRejectsPermissiveCacheFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "identity")
	id := testIdentity(t)
	public, err := crypt.Public(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key+".pub", []byte(public+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--key-file", key, "key", "public"}, strings.NewReader(""), &out, &diag)
	if code == 0 {
		t.Fatal("key public accepted permissive cache file")
	}
}

func TestKeyPublicDoesNotNeedPrivateIdentityUnlock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id := testIdentity(t)
	public, err := crypt.Public(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.pub"), []byte(public+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--key-file", filepath.Join(dir, "identity"), "key", "public"}, strings.NewReader(""), &out, &diag)
	if code != 0 || strings.TrimSpace(out.String()) != public {
		t.Fatalf("public key read depended on private identity: code=%d output=%q diagnostics=%q", code, out.String(), diag.String())
	}
}

func TestKeyCreateDoesNotPublishPublicCacheWhenStoreRejectsIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "identity")
	first := testIdentity(t)
	if err := custody.NewFile(key).Set(first); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--key-file", key, "key", "create"}, strings.NewReader(""), &out, &diag)
	if code == 0 {
		t.Fatal("key create replaced an existing different identity")
	}
	got, err := custody.NewFile(key).Get()
	if err != nil || got != first {
		t.Fatalf("existing identity changed: matched=%t err=%v", got == first, err)
	}
	if _, err := os.Lstat(key + ".pub"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public cache published for rejected identity: %v", err)
	}
}
