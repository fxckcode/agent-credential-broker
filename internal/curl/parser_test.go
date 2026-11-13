package curl

import "testing"

func TestParseSafeRequest(t *testing.T) {
	request, err := Parse([]string{"--profile", "github", "-X", "POST", "--json", "{\"title\":\"test\"}", "-H", "Accept: application/json", "https://api.github.com/repos/example/issues"})
	if err != nil {
		t.Fatal(err)
	}
	if request.Method != "POST" || request.Profile != "github" || request.Headers["Content-Type"] != "application/json" {
		t.Fatalf("request = %+v", request)
	}
}

func TestParseRejectsSecretInjectionAndFileReads(t *testing.T) {
	for _, args := range [][]string{
		{"--profile", "github", "-u", "user:secret", "https://api.github.com"},
		{"--profile", "github", "-d", "@secret.txt", "https://api.github.com"},
		{"--profile", "github", "-K", "config", "https://api.github.com"},
		{"--profile", "github", "-H", "Authorization: Bearer secret", "https://api.github.com"},
	} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("expected rejection for %#v", args)
		}
	}
}
