package policystore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fxckcode/agent-credential-broker/internal/filestore"
	"github.com/fxckcode/agent-credential-broker/internal/policy"
)

type fileModel struct {
	Version  int                        `json:"version"`
	Profiles map[string]json.RawMessage `json:"profiles"`
}

type Store struct {
	filePath string
}

func New(filePath string) (*Store, error) {
	if filePath == "" {
		return nil, fmt.Errorf("policy store requires a file path")
	}
	return &Store{filePath: filepath.Clean(filePath)}, nil
}

func (s *Store) LoadProfiles() (map[string]policy.Profile, error) {
	data, exists, err := filestore.ReadFileIfExists(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", s.filePath, err)
	}
	if !exists {
		return map[string]policy.Profile{}, nil
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("malformed policy file %q: %w", s.filePath, err)
	}
	for key := range raw {
		if key != "version" && key != "profiles" {
			return nil, fmt.Errorf("malformed policy file %q: unknown root field %q", s.filePath, key)
		}
	}
	version := 1
	if value, ok := raw["version"]; ok {
		if err := json.Unmarshal(value, &version); err != nil || version != 1 {
			return nil, fmt.Errorf("unsupported policy file version in %q", s.filePath)
		}
	}
	profiles := map[string]json.RawMessage{}
	if value, ok := raw["profiles"]; ok {
		if err := json.Unmarshal(value, &profiles); err != nil {
			return nil, fmt.Errorf("malformed policy file %q: profiles must be an object map", s.filePath)
		}
	}
	validated := make(map[string]policy.Profile, len(profiles))
	for key, value := range profiles {
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		var profile policy.Profile
		if err := decoder.Decode(&profile); err != nil {
			return nil, fmt.Errorf("invalid profile %q: %w", key, err)
		}
		if profile.Name == "" {
			profile.Name = key
		}
		clean, err := policy.ValidateProfile(profile)
		if err != nil {
			return nil, err
		}
		if clean.Name != key {
			return nil, fmt.Errorf("policy key mismatch: key %q does not match profile.name %q", key, clean.Name)
		}
		validated[key] = clean
	}
	return validated, nil
}

func (s *Store) GetProfile(name string) (policy.Profile, error) {
	profiles, err := s.LoadProfiles()
	if err != nil {
		return policy.Profile{}, err
	}
	profile, ok := profiles[name]
	if !ok {
		return policy.Profile{}, fmt.Errorf("profile %q not found in policy store (%s)", name, s.filePath)
	}
	return profile, nil
}

func (s *Store) SaveProfile(profile policy.Profile) (policy.Profile, error) {
	clean, err := policy.ValidateProfile(profile)
	if err != nil {
		return policy.Profile{}, err
	}
	profiles, err := s.LoadProfiles()
	if err != nil {
		return policy.Profile{}, err
	}
	if profiles == nil {
		profiles = map[string]policy.Profile{}
	}
	profiles[clean.Name] = clean
	payload, err := json.MarshalIndent(struct {
		Version  int                       `json:"version"`
		Profiles map[string]policy.Profile `json:"profiles"`
	}{Version: 1, Profiles: profiles}, "", "  ")
	if err != nil {
		return policy.Profile{}, fmt.Errorf("encode policy file: %w", err)
	}
	payload = append(payload, '\n')
	if err := filestore.WriteAtomicPrivate(s.filePath, payload); err != nil {
		return policy.Profile{}, err
	}
	return clean, nil
}

func (s *Store) FilePath() string { return s.filePath }

func InitWorkspace(root string) (string, error) {
	directory := filepath.Join(root, ".agent-cred")
	if err := filestore.EnsurePrivateDir(directory); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "profiles.json")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	store, err := New(path)
	if err != nil {
		return "", err
	}
	_, err = store.SaveProfile(policy.Profile{
		Name: "example-github-readonly", Description: "Read-only GitHub API profile for issue and pull-request metadata",
		Credential:   policy.Credential{Name: "github_pat_readonly", Scheme: "bearer"},
		AllowedHosts: []string{"api.github.com"}, AllowedMethods: []string{"GET"},
		AllowedPathPrefixes: []string{"/repos/", "/rate_limit"},
	})
	return path, err
}
