package redaction

import "testing"

func TestTextRedactsSecretVariantsAndPatterns(t *testing.T) {
	redactor, err := New([]string{"synthetic-secret-1234"}, []string{`internal-[0-9]+`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := "raw=synthetic-secret-1234 pattern=internal-42"
	output := redactor.Text(input)
	if output == input || contains(output, "synthetic-secret-1234") || contains(output, "internal-42") {
		t.Fatalf("secret or pattern leaked: %q", output)
	}
}

func TestHeadersRedactSensitiveValues(t *testing.T) {
	redactor, err := New([]string{"token-value-1234"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	output := redactor.Headers(map[string][]string{
		"Authorization": {"Bearer token-value-1234"},
		"Content-Type":  {"application/json"},
	})
	if output["authorization"] != redactedHeader {
		t.Fatalf("authorization = %q", output["authorization"])
	}
	if output["content-type"] != "application/json" {
		t.Fatalf("content-type = %q", output["content-type"])
	}
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
