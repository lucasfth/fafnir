//go:build !darwin

package custody

import (
	"errors"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

const keychainService = "github.com/lucasfth/fafnir/age-identity"

type keychainStore struct{ account string }

func NewKeychain(account string) Store { return keychainStore{account: account} }

func mapKeyringError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unsupported platform") {
		return ErrUnavailable
	}
	if strings.Contains(message, "locked") || strings.Contains(message, "unlock") {
		return ErrLocked
	}
	if strings.Contains(message, "denied") || strings.Contains(message, "cancel") || strings.Contains(message, "authentication") || strings.Contains(message, "auth failed") {
		return ErrAuthentication
	}
	if runtime.GOOS == "linux" || strings.Contains(message, "unavailable") || strings.Contains(message, "no such") || strings.Contains(message, "not running") || strings.Contains(message, "connection refused") {
		return ErrUnavailable
	}
	return ErrBackend
}

func (s keychainStore) Get() (string, error) {
	identity, err := keyring.Get(keychainService, s.account)
	if err != nil {
		return "", mapKeyringError(err)
	}
	if err := validateIdentity(identity); err != nil {
		return "", err
	}
	return identity, nil
}

func (s keychainStore) Set(identity string) error {
	if err := validateIdentity(identity); err != nil {
		return err
	}
	current, err := keyring.Get(keychainService, s.account)
	if err == nil {
		if current == identity {
			return nil
		}
		return ErrAlreadyExists
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return mapKeyringError(err)
	}
	if err := keyring.Set(keychainService, s.account, identity); err != nil {
		if runtime.GOOS == "windows" {
			if current, getErr := keyring.Get(keychainService, s.account); getErr == nil {
				if current == identity {
					return nil
				}
				return ErrAlreadyExists
			}
		}
		return mapKeyringError(err)
	}
	return nil
}

func (s keychainStore) Delete() error {
	return mapKeyringError(keyring.Delete(keychainService, s.account))
}
