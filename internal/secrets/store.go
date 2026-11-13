package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Store interface {
	Kind() string
	Set(profile, credential, value string) error
	Get(profile, credential string) (string, bool, error)
	Delete(profile, credential string) error
}

func validateIdentifier(value, label string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q", label, value)
	}
	return nil
}

func ValidateValue(value string) error {
	if value == "" {
		return fmt.Errorf("secret must be non-empty")
	}
	if len([]byte(value)) > 8192 {
		return fmt.Errorf("secret exceeds maximum allowed length (8192 bytes)")
	}
	if strings.IndexFunc(value, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("secret contains forbidden control characters or newlines")
	}
	return nil
}

func key(profile, credential string) (string, error) {
	if err := validateIdentifier(profile, "profile"); err != nil {
		return "", err
	}
	if err := validateIdentifier(credential, "credential"); err != nil {
		return "", err
	}
	return profile + ":" + credential, nil
}

func Fingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:12]
}
