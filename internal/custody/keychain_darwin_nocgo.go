//go:build darwin && !cgo

package custody

type unavailableKeychainStore struct{ account string }

func NewKeychain(account string) Store { return unavailableKeychainStore{account: account} }

func (s unavailableKeychainStore) Get() (string, error) { return "", ErrUnavailable }
func (s unavailableKeychainStore) Set(string) error     { return ErrUnavailable }
func (s unavailableKeychainStore) Delete() error        { return ErrUnavailable }
