//go:build windows

package secrets

import "fmt"

type OSKeychainStore struct{}

func NewOSKeychainStore(string) (*OSKeychainStore, error) {
	return &OSKeychainStore{}, nil
}

func (s *OSKeychainStore) Kind() string { return "os-keychain" }
func (s *OSKeychainStore) Set(string, string, string) error {
	return fmt.Errorf("Windows Credential Manager adapter is not implemented yet")
}
func (s *OSKeychainStore) Get(string, string) (string, bool, error) {
	return "", false, fmt.Errorf("Windows Credential Manager adapter is not implemented yet")
}
func (s *OSKeychainStore) Delete(string, string) error {
	return fmt.Errorf("Windows Credential Manager adapter is not implemented yet")
}
