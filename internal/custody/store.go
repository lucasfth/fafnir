package custody

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucasfth/fafnir/internal/crypt"
)

const maxIdentityBytes = 1024

var (
	ErrNotFound            = errors.New("identity not found")
	ErrAlreadyExists       = errors.New("a different identity is already stored")
	ErrLocked              = errors.New("identity storage is locked")
	ErrAuthentication      = errors.New("identity storage authentication failed")
	ErrUnavailable         = errors.New("identity storage is unavailable")
	ErrBackend             = errors.New("identity storage operation failed")
	ErrInvalidIdentity     = errors.New("invalid age identity")
	ErrUnsafePath          = errors.New("unsafe identity storage path")
	ErrInsecurePermissions = errors.New("identity file permissions are not private")
)

type Store interface {
	Get() (string, error)
	Set(string) error
	Delete() error
}

type fileStore struct{ path string }

func NewFile(path string) Store { return fileStore{path: path} }

func validateIdentity(identity string) error {
	if len(identity) == 0 || len(identity) > maxIdentityBytes || strings.ContainsAny(identity, "\r\n\x00") {
		return ErrInvalidIdentity
	}
	if _, err := crypt.Public(identity); err != nil {
		return ErrInvalidIdentity
	}
	return nil
}

func inGitWorktree(parent string) bool {
	for dir := parent; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		if _, headErr := os.Stat(filepath.Join(dir, "HEAD")); headErr == nil {
			if objects, err := os.Stat(filepath.Join(dir, "objects")); err == nil && objects.IsDir() {
				if refs, err := os.Stat(filepath.Join(dir, "refs")); err == nil && refs.IsDir() {
					return true
				}
			}
		}
		up := filepath.Dir(dir)
		if up == dir {
			return false
		}
	}
}

func (s fileStore) root() (*os.Root, string, error) {
	absolute, err := filepath.Abs(s.path)
	if err != nil || filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return nil, "", ErrUnsafePath
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, "", ErrUnsafePath
	}
	if inGitWorktree(parent) {
		return nil, "", ErrUnsafePath
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return nil, "", ErrUnsafePath
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, "", ErrInsecurePermissions
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, "", ErrUnsafePath
	}
	return root, filepath.Base(absolute), nil
}

func ValidateFilePath(path string) error {
	root, _, err := (fileStore{path: path}).root()
	if err != nil {
		return err
	}
	return root.Close()
}
func (s fileStore) existing(root *os.Root, name string) (string, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", ErrBackend
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		return "", ErrInsecurePermissions
	}
	file, err := root.Open(name)
	if err != nil {
		return "", ErrBackend
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", ErrUnsafePath
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityBytes+1))
	if err != nil {
		return "", ErrBackend
	}
	if len(data) > maxIdentityBytes {
		return "", ErrInvalidIdentity
	}
	identity := string(data)
	if err := validateIdentity(identity); err != nil {
		return "", err
	}
	return identity, nil
}

func (s fileStore) Get() (string, error) {
	root, name, err := s.root()
	if err != nil {
		return "", err
	}
	defer root.Close()
	return s.existing(root, name)
}

func (s fileStore) Set(identity string) error {
	if err := validateIdentity(identity); err != nil {
		return err
	}
	root, name, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	current, err := s.existing(root, name)
	if err == nil {
		if current == identity {
			return nil
		}
		return ErrAlreadyExists
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrBackend
	}
	temporary := ".fafnir-identity-" + hex.EncodeToString(random[:])
	temp, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrBackend
	}
	defer root.Remove(temporary)
	if _, err := temp.WriteString(identity); err != nil {
		temp.Close()
		return ErrBackend
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return ErrBackend
	}
	if err := temp.Close(); err != nil {
		return ErrBackend
	}
	if err := root.Link(temporary, name); err != nil {
		if errors.Is(err, os.ErrExist) {
			stored, readErr := s.existing(root, name)
			if readErr == nil && stored == identity {
				return nil
			}
			if readErr == nil {
				return ErrAlreadyExists
			}
			return readErr
		}
		return ErrBackend
	}
	return nil
}

func (s fileStore) Delete() error {
	root, name, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := s.existing(root, name); err != nil {
		return err
	}
	if err := root.Remove(name); err != nil {
		return ErrBackend
	}
	return nil
}
