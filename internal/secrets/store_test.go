package secrets

import (
	"path/filepath"
	"testing"
)

func TestMemoryStoreValidatesAndRoundTripsWithoutPrinting(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Set("github", "token", "synthetic-secret-1234"); err != nil {
		t.Fatal(err)
	}
	value, ok, err := store.Get("github", "token")
	if err != nil || !ok || value != "synthetic-secret-1234" {
		t.Fatalf("Get() = %q, %v, %v", value, ok, err)
	}
	if err := store.Set("github", "token", "bad\nsecret"); err == nil {
		t.Fatal("expected control character rejection")
	}
}

func TestDevFileStoreRequiresAcknowledgementAndRoundTrips(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "dev-secrets")
	if _, err := NewDevFileStore(directory, false); err == nil {
		t.Fatal("expected explicit acknowledgement requirement")
	}
	store, err := NewDevFileStore(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("github", "token", "synthetic-secret-1234"); err != nil {
		t.Fatal(err)
	}
	value, ok, err := store.Get("github", "token")
	if err != nil || !ok || value != "synthetic-secret-1234" {
		t.Fatalf("Get() = %q, %v, %v", value, ok, err)
	}
}
