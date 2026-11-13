//go:build !windows

package secrets

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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

func (s *OSKeychainStore) Kind() string { return "os-keychain" }

func (s *OSKeychainStore) command() (string, bool) {
	switch runtime.GOOS {
	case "linux":
		for _, candidate := range []string{"/usr/bin/secret-tool", "/usr/sbin/secret-tool"} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, true
			}
		}
	case "darwin":
		if _, err := os.Stat("/usr/bin/security"); err == nil {
			return "/usr/bin/security", true
		}
	}
	return "", false
}

func (s *OSKeychainStore) Set(profile, credential, value string) error {
	if err := ValidateValue(value); err != nil {
		return err
	}
	if _, err := key(profile, credential); err != nil {
		return err
	}
	binary, ok := s.command()
	if !ok {
		return fmt.Errorf("OS keychain is unavailable on %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var command *exec.Cmd
	if runtime.GOOS == "linux" {
		command = exec.CommandContext(ctx, binary, "store", "--label=agent-cred", "service", s.service, "profile", profile, "credential", credential)
	} else {
		command = exec.CommandContext(ctx, binary, "-i")
	}
	command.Stdin = strings.NewReader(value)
	command.Env = safeEnvironment()
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("OS keychain write failed: %w", sanitizeOutput(output))
	}
	return nil
}

func (s *OSKeychainStore) Get(profile, credential string) (string, bool, error) {
	if _, err := key(profile, credential); err != nil {
		return "", false, err
	}
	binary, ok := s.command()
	if !ok {
		return "", false, fmt.Errorf("OS keychain is unavailable on %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var command *exec.Cmd
	if runtime.GOOS == "linux" {
		command = exec.CommandContext(ctx, binary, "lookup", "service", s.service, "profile", profile, "credential", credential)
	} else {
		command = exec.CommandContext(ctx, binary, "find-generic-password", "-a", profile+":"+credential, "-s", s.service, "-w")
	}
	command.Env = safeEnvironment()
	output, err := command.Output()
	if err != nil {
		return "", false, nil
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r")
	if value == "" {
		return "", false, nil
	}
	if err := ValidateValue(value); err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *OSKeychainStore) Delete(profile, credential string) error {
	if _, err := key(profile, credential); err != nil {
		return err
	}
	binary, ok := s.command()
	if !ok {
		return fmt.Errorf("OS keychain is unavailable on %s", runtime.GOOS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var command *exec.Cmd
	if runtime.GOOS == "linux" {
		command = exec.CommandContext(ctx, binary, "clear", "service", s.service, "profile", profile, "credential", credential)
	} else {
		command = exec.CommandContext(ctx, binary, "delete-generic-password", "-a", profile+":"+credential, "-s", s.service)
	}
	command.Env = safeEnvironment()
	if err := command.Run(); err != nil {
		return nil
	}
	return nil
}

func safeEnvironment() []string {
	keys := map[string]bool{"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "DBUS_SESSION_BUS_ADDRESS": true, "XDG_RUNTIME_DIR": true}
	result := make([]string, 0, len(keys))
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && keys[parts[0]] {
			result = append(result, entry)
		}
	}
	return result
}

func sanitizeOutput(output []byte) error {
	return fmt.Errorf("command failed (%d bytes of output)", len(output))
}
