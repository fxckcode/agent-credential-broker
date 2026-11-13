//go:build windows

package secrets

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	credMaxBlobSize         = 5 * 512
)

type windowsFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type windowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windowsFiletime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32   = syscall.NewLazyDLL("advapi32.dll")
	credWrite  = advapi32.NewProc("CredWriteW")
	credRead   = advapi32.NewProc("CredReadW")
	credDelete = advapi32.NewProc("CredDeleteW")
	credFree   = advapi32.NewProc("CredFree")
)

type OSKeychainStore struct {
	service string
}

func NewOSKeychainStore(service string) (*OSKeychainStore, error) {
	if err := validateIdentifier(service, "service"); err != nil {
		return nil, err
	}
	return &OSKeychainStore{service: service}, nil
}

func (s *OSKeychainStore) Kind() string { return "os-keychain-windows-credential-manager" }

func (s *OSKeychainStore) target(profile, credential string) (*uint16, error) {
	if _, err := key(profile, credential); err != nil {
		return nil, err
	}
	return syscall.UTF16PtrFromString(s.service + "/" + profile + "/" + credential)
}

func (s *OSKeychainStore) Set(profile, credential, value string) error {
	if err := ValidateValue(value); err != nil {
		return err
	}
	if len([]byte(value)) > credMaxBlobSize {
		return fmt.Errorf("Windows Credential Manager supports credential blobs up to %d bytes", credMaxBlobSize)
	}
	target, err := s.target(profile, credential)
	if err != nil {
		return err
	}
	blob := []byte(value)
	username, err := syscall.UTF16PtrFromString(profile + ":" + credential)
	if err != nil {
		return err
	}
	credentialValue := windowsCredential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Persist:            credPersistLocalMachine,
		UserName:           username,
	}
	result, _, callErr := credWrite.Call(uintptr(unsafe.Pointer(&credentialValue)), 0)
	if result == 0 {
		return fmt.Errorf("CredWriteW failed: %w", callErr)
	}
	return nil
}

func (s *OSKeychainStore) Get(profile, credential string) (string, bool, error) {
	target, err := s.target(profile, credential)
	if err != nil {
		return "", false, err
	}
	var result *windowsCredential
	status, _, callErr := credRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&result)))
	if status == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_NOT_FOUND {
			return "", false, nil
		}
		return "", false, fmt.Errorf("CredReadW failed: %w", callErr)
	}
	defer credFree.Call(uintptr(unsafe.Pointer(result)))
	if result.CredentialBlobSize == 0 || result.CredentialBlob == nil {
		return "", false, nil
	}
	blob := unsafe.Slice(result.CredentialBlob, result.CredentialBlobSize)
	value := string(blob)
	if err := ValidateValue(value); err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *OSKeychainStore) Delete(profile, credential string) error {
	target, err := s.target(profile, credential)
	if err != nil {
		return err
	}
	status, _, callErr := credDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	if status == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_NOT_FOUND {
			return nil
		}
		return fmt.Errorf("CredDeleteW failed: %w", callErr)
	}
	return nil
}
