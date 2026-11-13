package filestore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil && runtimeIsPOSIX() {
		return fmt.Errorf("restrict private directory: %w", err)
	}
	return nil
}

func WriteAtomicPrivate(filePath string, content []byte) error {
	if err := EnsurePrivateDir(filepath.Dir(filePath)); err != nil {
		return err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("create temporary file suffix: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp-%d-%x", filePath, os.Getpid(), random)
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create atomic temporary file: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write atomic temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync atomic temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close atomic temporary file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil && runtimeIsPOSIX() {
		return fmt.Errorf("restrict atomic temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("replace atomic file: %w", err)
	}
	ok = true
	return nil
}

func ReadFileIfExists(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func runtimeIsPOSIX() bool {
	return os.PathSeparator == '/'
}
