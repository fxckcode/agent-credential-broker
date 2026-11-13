package policy

import "testing"

func TestValidateProfileNormalizesAndAppliesDefaults(t *testing.T) {
	profile, err := ValidateProfile(Profile{
		Name:           "github-issues",
		Credential:     Credential{Name: "github_token", Scheme: "bearer"},
		AllowedHosts:   []string{"API.GITHUB.COM", "api.github.com"},
		AllowedMethods: []string{"get", "GET"},
	})
	if err != nil {
		t.Fatalf("ValidateProfile() error = %v", err)
	}
	if profile.Credential.HeaderName != "Authorization" {
		t.Fatalf("default header = %q", profile.Credential.HeaderName)
	}
	if profile.TimeoutMS != 10000 || profile.MaxResponseBytes != 262144 {
		t.Fatalf("defaults not applied: %+v", profile)
	}
	if len(profile.AllowedHosts) != 1 || profile.AllowedHosts[0] != "api.github.com" {
		t.Fatalf("hosts not normalized: %#v", profile.AllowedHosts)
	}
	if len(profile.AllowedMethods) != 1 || profile.AllowedMethods[0] != "GET" {
		t.Fatalf("methods not normalized: %#v", profile.AllowedMethods)
	}
}

func TestValidateProfileRejectsWildcardAndQueryAuth(t *testing.T) {
	base := Profile{
		Name:           "bad-profile",
		Credential:     Credential{Name: "token", Scheme: "bearer"},
		AllowedHosts:   []string{"*.example.com"},
		AllowedMethods: []string{"GET"},
	}
	if _, err := ValidateProfile(base); err == nil {
		t.Fatal("expected wildcard host to be rejected")
	}

	base.AllowedHosts = []string{"api.example.com"}
	base.Credential.Scheme = "query"
	if _, err := ValidateProfile(base); err == nil {
		t.Fatal("expected query credential scheme to be rejected")
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "fc00::1", "224.0.0.1"} {
		if !IsPrivateOrReservedIP(address) {
			t.Errorf("IsPrivateOrReservedIP(%q) = false", address)
		}
	}
	if IsPrivateOrReservedIP("1.1.1.1") {
		t.Fatal("public IP was classified as private")
	}
}
