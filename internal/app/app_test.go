package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run() code = %d", code)
	}
	if strings.TrimSpace(stdout.String()) != Version {
		t.Fatalf("version output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunDoctorDoesNotInspectSecrets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"doctor"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run() code = %d", code)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("doctor output is not JSON: %v", err)
	}
	if result["secretValues"] != "not inspected" {
		t.Fatalf("secret inspection contract changed: %#v", result["secretValues"])
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"exec"}, &stdout, &stderr); code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
