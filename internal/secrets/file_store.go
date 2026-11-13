package secrets

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/fxckcode/agent-credential-broker/internal/filestore"
)

type MemoryStore struct {
	mu     sync.RWMutex
	values map[string]string
}

func NewMemoryStore() *MemoryStore  { return &MemoryStore{values: map[string]string{}} }
func (s *MemoryStore) Kind() string { return "memory-test-only" }

func (s *MemoryStore) Set(profile, credential, value string) error {
	entry, err := key(profile, credential)
	if err != nil {
		return err
	}
	if err := ValidateValue(value); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[entry] = value
	return nil
}

func (s *MemoryStore) Get(profile, credential string) (string, bool, error) {
	entry, err := key(profile, credential)
	if err != nil {
		return "", false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[entry]
	return value, ok, nil
}

func (s *MemoryStore) Delete(profile, credential string) error {
	entry, err := key(profile, credential)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, entry)
	return nil
}

type DevFileStore struct {
	path string
}

func NewDevFileStore(directory string, acknowledged bool) (*DevFileStore, error) {
	if !acknowledged {
		return nil, fmt.Errorf("dev file store requires explicit acknowledgement")
	}
	if directory == "" {
		return nil, fmt.Errorf("dev file store directory is required")
	}
	if err := filestore.EnsurePrivateDir(directory); err != nil {
		return nil, err
	}
	return &DevFileStore{path: filepath.Join(directory, "secrets.dev.json")}, nil
}

func (s *DevFileStore) Kind() string { return "dev-file-test-only" }

func (s *DevFileStore) read() (map[string]string, error) {
	data, exists, err := filestore.ReadFileIfExists(s.path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return map[string]string{}, nil
	}
	values := map[string]string{}
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("corrupted dev file store: %w", err)
	}
	return values, nil
}

func (s *DevFileStore) write(values map[string]string) error {
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	return filestore.WriteAtomicPrivate(s.path, append(data, '\n'))
}

func (s *DevFileStore) Set(profile, credential, value string) error {
	entry, err := key(profile, credential)
	if err != nil {
		return err
	}
	if err := ValidateValue(value); err != nil {
		return err
	}
	values, err := s.read()
	if err != nil {
		return err
	}
	values[entry] = value
	return s.write(values)
}

func (s *DevFileStore) Get(profile, credential string) (string, bool, error) {
	entry, err := key(profile, credential)
	if err != nil {
		return "", false, err
	}
	values, err := s.read()
	if err != nil {
		return "", false, err
	}
	value, ok := values[entry]
	if ok {
		if err := ValidateValue(value); err != nil {
			return "", false, err
		}
	}
	return value, ok, nil
}

func (s *DevFileStore) Delete(profile, credential string) error {
	entry, err := key(profile, credential)
	if err != nil {
		return err
	}
	values, err := s.read()
	if err != nil {
		return err
	}
	delete(values, entry)
	return s.write(values)
}
