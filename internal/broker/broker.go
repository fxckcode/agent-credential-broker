package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fxckcode/agent-credential-broker/internal/policy"
	"github.com/fxckcode/agent-credential-broker/internal/policystore"
	"github.com/fxckcode/agent-credential-broker/internal/redaction"
	"github.com/fxckcode/agent-credential-broker/internal/secrets"
	"github.com/fxckcode/agent-credential-broker/internal/transport"
)

type Broker struct {
	policies *policystore.Store
	secrets  secrets.Store
	mu       sync.Mutex
	requests map[string][]time.Time
}

type Request struct {
	Profile            string
	Method             string
	URL                string
	Headers            map[string]string
	Body               string
	Timeout            time.Duration
	AllowHTTPLocalhost bool
}

type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Profile string            `json:"profile"`
}

type ConnectionResult struct {
	OK      bool   `json:"ok"`
	Profile string `json:"profile"`
	Status  int    `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
}

func New(policies *policystore.Store, store secrets.Store) (*Broker, error) {
	if policies == nil || store == nil {
		return nil, fmt.Errorf("broker requires policy and secret stores")
	}
	return &Broker{policies: policies, secrets: store, requests: map[string][]time.Time{}}, nil
}

func (b *Broker) ListProfiles() ([]policy.Profile, error) {
	profiles, err := b.policies.LoadProfiles()
	if err != nil {
		return nil, err
	}
	result := make([]policy.Profile, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, profile)
	}
	return result, nil
}

func (b *Broker) InspectProfile(name string) (policy.Profile, error) {
	return b.policies.GetProfile(name)
}

func (b *Broker) TestConnection(ctx context.Context, profileName string, allowHTTP bool) ConnectionResult {
	profile, err := b.policies.GetProfile(profileName)
	if err != nil {
		return ConnectionResult{Profile: profileName, Error: err.Error()}
	}
	if profile.TestRequest == nil {
		return ConnectionResult{Profile: profile.Name, Error: "profile has no testRequest"}
	}
	result, err := b.Execute(ctx, Request{Profile: profile.Name, Method: profile.TestRequest.Method, URL: profile.TestRequest.URL, AllowHTTPLocalhost: allowHTTP})
	if err != nil {
		return ConnectionResult{Profile: profile.Name, Error: err.Error()}
	}
	validStatus := false
	for _, expected := range profile.TestRequest.ExpectedStatuses {
		if result.Status == expected {
			validStatus = true
			break
		}
	}
	if !validStatus {
		return ConnectionResult{Profile: profile.Name, Status: result.Status, Error: fmt.Sprintf("unexpected HTTP status %d", result.Status)}
	}
	return ConnectionResult{OK: true, Profile: profile.Name, Status: result.Status}
}

func (b *Broker) Execute(ctx context.Context, input Request) (Response, error) {
	profile, err := b.policies.GetProfile(input.Profile)
	if err != nil {
		return Response{}, err
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if !contains(profile.AllowedMethods, method) {
		return Response{}, fmt.Errorf("method %q is not allowed by profile %q", method, profile.Name)
	}
	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Hostname() == "" {
		return Response{}, fmt.Errorf("invalid target URL")
	}
	if parsed.User != nil {
		return Response{}, fmt.Errorf("URL userinfo is forbidden")
	}
	host := strings.ToLower(parsed.Hostname())
	loopback := transport.IsLoopbackHost(parsed.String())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback && profile.AllowHTTPLocalhost && input.AllowHTTPLocalhost) {
		return Response{}, fmt.Errorf("non-HTTPS URL is denied by default")
	}
	if !contains(profile.AllowedHosts, host) {
		return Response{}, fmt.Errorf("host %q is not allowed by profile %q", host, profile.Name)
	}
	pathValue := parsed.Path
	if pathValue == "" {
		pathValue = "/"
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || strings.Contains(pathValue, "..") || strings.Contains(decodedPath, "..") || strings.ContainsAny(decodedPath, "\x00\r\n") {
		return Response{}, fmt.Errorf("path traversal sequence detected")
	}
	if !hasAllowedPrefix(pathValue, profile.AllowedPathPrefixes) {
		return Response{}, fmt.Errorf("URL path %q is not allowed by profile %q", pathValue, profile.Name)
	}
	if len([]byte(input.Body)) > profile.MaxRequestBytes {
		return Response{}, fmt.Errorf("request body exceeds profile limit")
	}
	secret, found, err := b.secrets.Get(profile.Name, profile.Credential.Name)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return Response{}, fmt.Errorf("secret %q is not present in the configured store", profile.Credential.Name)
	}
	if err := b.checkRate(profile); err != nil {
		return Response{}, err
	}
	outbound := make(http.Header)
	outbound.Set("User-Agent", "agent-cred-go/0.3.0")
	for name, value := range input.Headers {
		if strings.EqualFold(name, profile.Credential.HeaderName) || strings.EqualFold(name, "proxy-authorization") {
			return Response{}, fmt.Errorf("caller cannot override credential headers")
		}
		outbound.Set(name, value)
	}
	credentialName, credentialValue, err := credentialHeader(profile.Credential, secret)
	if err != nil {
		return Response{}, err
	}
	outbound.Set(credentialName, credentialValue)
	if input.Body != "" && outbound.Get("Content-Length") == "" {
		outbound.Set("Content-Length", fmt.Sprintf("%d", len([]byte(input.Body))))
	}
	timeout := time.Duration(profile.TimeoutMS) * time.Millisecond
	if input.Timeout > 0 && input.Timeout < timeout {
		timeout = input.Timeout
	}
	raw, err := transport.Send(ctx, parsed.String(), method, outbound, bytes.NewBufferString(input.Body), timeout, profile.MaxResponseBytes, loopback)
	if err != nil {
		return Response{}, err
	}
	redactor, err := redaction.New([]string{secret}, profile.RedactPatterns, append(profile.RedactHeaders, profile.Credential.HeaderName))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: raw.Status, Headers: redactor.Headers(raw.Headers), Body: redactor.Text(raw.Body), Profile: profile.Name}, nil
}

func credentialHeader(config policy.Credential, secret string) (string, string, error) {
	switch config.Scheme {
	case "bearer":
		prefix := config.Prefix
		if prefix == "" {
			prefix = "Bearer "
		}
		return config.HeaderName, prefix + secret, nil
	case "basic":
		value := secret
		if !strings.Contains(value, ":") {
			value = ":" + value
		}
		return config.HeaderName, "Basic " + base64.StdEncoding.EncodeToString([]byte(value)), nil
	case "header":
		return config.HeaderName, config.Prefix + secret, nil
	default:
		return "", "", fmt.Errorf("unsupported credential scheme %q", config.Scheme)
	}
}

func (b *Broker) checkRate(profile policy.Profile) error {
	now := time.Now()
	cutoff := now.Add(-time.Duration(profile.RateLimit.WindowMS) * time.Millisecond)
	b.mu.Lock()
	defer b.mu.Unlock()
	recent := b.requests[profile.Name][:0]
	for _, timestamp := range b.requests[profile.Name] {
		if timestamp.After(cutoff) {
			recent = append(recent, timestamp)
		}
	}
	if len(recent) >= profile.RateLimit.MaxRequests {
		b.requests[profile.Name] = recent
		return fmt.Errorf("rate limit exceeded for profile %q", profile.Name)
	}
	b.requests[profile.Name] = append(recent, now)
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasAllowedPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
