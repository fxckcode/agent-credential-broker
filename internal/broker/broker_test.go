package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxckcode/agent-credential-broker/internal/policy"
	"github.com/fxckcode/agent-credential-broker/internal/policystore"
	"github.com/fxckcode/agent-credential-broker/internal/secrets"
)

func TestExecuteAttachesCredentialAndRedactsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer synthetic-secret-1234" {
			t.Fatalf("authorization header was not attached")
		}
		_, _ = writer.Write([]byte("token=synthetic-secret-1234"))
	}))
	defer server.Close()

	policies, err := policystore.New(t.TempDir() + "/profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.SaveProfile(policy.Profile{
		Name: "local", Credential: policy.Credential{Name: "token", Scheme: "bearer"},
		AllowedHosts: []string{"127.0.0.1"}, AllowedMethods: []string{"GET"},
		AllowedPathPrefixes: []string{"/"}, AllowHTTPLocalhost: true,
	}); err != nil {
		t.Fatal(err)
	}
	store := secrets.NewMemoryStore()
	if err := store.Set("local", "token", "synthetic-secret-1234"); err != nil {
		t.Fatal(err)
	}
	service, err := New(policies, store)
	if err != nil {
		t.Fatal(err)
	}

	response, err := service.Execute(context.Background(), Request{Profile: "local", Method: "GET", URL: server.URL, AllowHTTPLocalhost: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(response.Body, "synthetic-secret-1234") {
		t.Fatalf("secret leaked: %q", response.Body)
	}
	if !strings.Contains(response.Body, "REDACTED") {
		t.Fatalf("response was not redacted: %q", response.Body)
	}
}

func TestExecuteRejectsCredentialOverride(t *testing.T) {
	policies, err := policystore.New(t.TempDir() + "/profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.SaveProfile(policy.Profile{
		Name: "api", Credential: policy.Credential{Name: "token", Scheme: "header", HeaderName: "X-API-Key"},
		AllowedHosts: []string{"api.example.com"}, AllowedMethods: []string{"GET"}, AllowedPathPrefixes: []string{"/"},
	}); err != nil {
		t.Fatal(err)
	}
	store := secrets.NewMemoryStore()
	if err := store.Set("api", "token", "synthetic-secret-1234"); err != nil {
		t.Fatal(err)
	}
	service, err := New(policies, store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Execute(context.Background(), Request{Profile: "api", Method: "GET", URL: "https://api.example.com/", Headers: map[string]string{"X-API-Key": "attacker"}})
	if err == nil || !strings.Contains(err.Error(), "override") {
		t.Fatalf("error = %v", err)
	}
}
