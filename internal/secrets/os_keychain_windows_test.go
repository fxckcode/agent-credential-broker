//go:build windows

package secrets

import "testing"

func TestWindowsCredentialManagerRoundTrip(t *testing.T) {
	store, err := NewOSKeychainStore("agent-cred-ci")
	if err != nil {
		t.Fatal(err)
	}
	const profile = "ci-profile"
	const credential = "ci-credential"
	const value = "synthetic-windows-secret-1234"
	if err := store.Set(profile, credential, value); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Delete(profile, credential) }()
	loaded, found, err := store.Get(profile, credential)
	if err != nil {
		t.Fatal(err)
	}
	if !found || loaded != value {
		t.Fatalf("credential round-trip failed: found=%v", found)
	}
}
