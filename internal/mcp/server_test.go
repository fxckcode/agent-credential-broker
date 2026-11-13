package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxckcode/agent-credential-broker/internal/broker"
	"github.com/fxckcode/agent-credential-broker/internal/policy"
	"github.com/fxckcode/agent-credential-broker/internal/policystore"
	"github.com/fxckcode/agent-credential-broker/internal/secrets"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	store, err := policystore.New(t.TempDir() + "/profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveProfile(policy.Profile{Name: "github", Credential: policy.Credential{Name: "token", Scheme: "bearer"}, AllowedHosts: []string{"api.github.com"}, AllowedMethods: []string{"GET"}}); err != nil {
		t.Fatal(err)
	}
	service, err := broker.New(store, secrets.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestServeInitializeAndListTools(t *testing.T) {
	server := testServer(t)
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n")
	var output bytes.Buffer
	if err := server.Serve(input, &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("frames = %d, output = %s", len(lines), output.String())
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &response); err != nil {
		t.Fatal(err)
	}
	result := response["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %d", len(tools))
	}
}

func TestServeNotificationHasNoResponse(t *testing.T) {
	server := testServer(t)
	var output bytes.Buffer
	if err := server.Serve(strings.NewReader("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"), &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("notification response = %q", output.String())
	}
}

var _ = context.Background
