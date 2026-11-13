package policystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fxckcode/agent-credential-broker/internal/policy"
)

func TestStoreRoundTripAndRejectsUnknownFields(t *testing.T) {
	directory := t.TempDir()
	store, err := New(filepath.Join(directory, ".agent-cred", "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := store.SaveProfile(policy.Profile{
		Name: "github", Credential: policy.Credential{Name: "token", Scheme: "bearer"},
		AllowedHosts: []string{"api.github.com"}, AllowedMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetProfile("github")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != profile.Name || loaded.TimeoutMS != 10000 {
		t.Fatalf("loaded profile = %+v", loaded)
	}

	data, err := os.ReadFile(store.FilePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("policy file is empty")
	}
	if err := os.WriteFile(store.FilePath(), []byte(`{"profiles":{"github":{"name":"github","credential":{"name":"token","scheme":"bearer"},"allowedHosts":["api.github.com"],"allowedMethods":["GET"],"unknown":true}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadProfiles(); err == nil {
		t.Fatal("expected unknown profile field to be rejected")
	}
}

func TestInitWorkspaceCreatesNonSecretPolicy(t *testing.T) {
	path, err := InitWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
