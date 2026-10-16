//go:build darwin && cgo

package custody

import (
	"errors"

	keychain "github.com/keybase/go-keychain"
)

const keychainService = "github.com/lucasfth/fafnir/age-identity"

type keychainStore struct{ account string }

func NewKeychain(account string) Store { return keychainStore{account: account} }

func (s keychainStore) query() keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetAccount(s.account)
	return item
}

func mapKeychainError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, keychain.ErrorItemNotFound):
		return ErrNotFound
	case errors.Is(err, keychain.ErrorInteractionNotAllowed):
		return ErrLocked
	case errors.Is(err, keychain.ErrorAuthFailed), errors.Is(err, keychain.ErrorUserCanceled), errors.Is(err, keychain.ErrorNoAccessForItem):
		return ErrAuthentication
	case errors.Is(err, keychain.ErrorNotAvailable), errors.Is(err, keychain.ErrorNoSuchKeychain), errors.Is(err, keychain.ErrorInvalidKeychain):
		return ErrUnavailable
	default:
		return ErrBackend
	}
}

func (s keychainStore) Get() (string, error) {
	secret, err := keychain.GetGenericPassword(keychainService, s.account, "", "")
	if err != nil {
		return "", mapKeychainError(err)
	}
	if secret == nil {
		return "", ErrNotFound
	}
	identity := string(secret)
	if err := validateIdentity(identity); err != nil {
		return "", err
	}
	return identity, nil
}

func (s keychainStore) Set(identity string) error {
	if err := validateIdentity(identity); err != nil {
		return err
	}
	item := s.query()
	item.SetReturnData(true)
	item.SetMatchLimit(keychain.MatchLimitOne)
	if existing, err := keychain.QueryItem(item); err == nil && len(existing) > 0 {
		if string(existing[0].Data) == identity {
			return nil
		}
		return ErrAlreadyExists
	} else if err != nil && !errors.Is(err, keychain.ErrorItemNotFound) {
		return mapKeychainError(err)
	}
	add := s.query()
	add.SetData([]byte(identity))
	if err := keychain.AddItem(add); errors.Is(err, keychain.ErrorDuplicateItem) {
		return ErrAlreadyExists
	} else {
		return mapKeychainError(err)
	}
}

func (s keychainStore) Delete() error {
	return mapKeychainError(keychain.DeleteGenericPasswordItem(keychainService, s.account))
}
