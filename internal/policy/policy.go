package policy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type Profile struct {
	Name                string       `json:"name"`
	Description         string       `json:"description,omitempty"`
	Credential          Credential   `json:"credential"`
	AllowedHosts        []string     `json:"allowedHosts"`
	AllowedMethods      []string     `json:"allowedMethods"`
	AllowedPathPrefixes []string     `json:"allowedPathPrefixes,omitempty"`
	AllowHTTPLocalhost  bool         `json:"allowHttpLocalhost,omitempty"`
	TimeoutMS           int          `json:"timeoutMs,omitempty"`
	MaxRequestBytes     int          `json:"maxRequestBytes,omitempty"`
	MaxResponseBytes    int          `json:"maxResponseBytes,omitempty"`
	RateLimit           RateLimit    `json:"rateLimit,omitempty"`
	RedactPatterns      []string     `json:"redactPatterns,omitempty"`
	RedactHeaders       []string     `json:"redactHeaders,omitempty"`
	TestRequest         *TestRequest `json:"testRequest,omitempty"`
}

type Credential struct {
	Name       string `json:"name"`
	Scheme     string `json:"scheme"`
	HeaderName string `json:"headerName,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
}

type RateLimit struct {
	MaxRequests int `json:"maxRequests"`
	WindowMS    int `json:"windowMs"`
}

type TestRequest struct {
	Method           string `json:"method"`
	URL              string `json:"url"`
	ExpectedStatuses []int  `json:"expectedStatuses"`
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var headerPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
var hostPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var validMethods = map[string]bool{
	"GET": true, "HEAD": true, "OPTIONS": true, "POST": true,
	"PUT": true, "PATCH": true, "DELETE": true,
}

var validSchemes = map[string]bool{"bearer": true, "basic": true, "header": true}

func ValidateProfile(raw Profile) (Profile, error) {
	if !namePattern.MatchString(raw.Name) {
		return Profile{}, fmt.Errorf("policy validation failed: profile name must match %s", namePattern.String())
	}
	if len(raw.Description) > 500 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): description must be <= 500 chars", raw.Name)
	}
	if !namePattern.MatchString(raw.Credential.Name) {
		return Profile{}, fmt.Errorf("policy validation failed (%s): credential name is invalid", raw.Name)
	}
	if !validSchemes[raw.Credential.Scheme] {
		return Profile{}, fmt.Errorf("policy validation failed (%s): unsupported credential scheme %q", raw.Name, raw.Credential.Scheme)
	}
	if raw.Credential.HeaderName == "" {
		raw.Credential.HeaderName = "Authorization"
	}
	if !headerPattern.MatchString(raw.Credential.HeaderName) {
		return Profile{}, fmt.Errorf("policy validation failed (%s): credential header name is invalid", raw.Name)
	}
	if strings.ContainsAny(raw.Credential.Prefix, "\r\n\x00") || len(raw.Credential.Prefix) > 32 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): credential prefix is invalid", raw.Name)
	}
	if len(raw.AllowedHosts) == 0 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): allowedHosts must not be empty", raw.Name)
	}
	raw.AllowedHosts = normalizeHosts(raw.AllowedHosts)
	for _, host := range raw.AllowedHosts {
		if strings.Contains(host, "*") || !hostPattern.MatchString(host) {
			return Profile{}, fmt.Errorf("policy validation failed (%s): invalid exact host %q", raw.Name, host)
		}
	}
	if len(raw.AllowedMethods) == 0 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): allowedMethods must not be empty", raw.Name)
	}
	raw.AllowedMethods = normalizeMethods(raw.AllowedMethods)
	for _, method := range raw.AllowedMethods {
		if !validMethods[method] {
			return Profile{}, fmt.Errorf("policy validation failed (%s): invalid HTTP method %q", raw.Name, method)
		}
	}
	if len(raw.AllowedPathPrefixes) == 0 {
		raw.AllowedPathPrefixes = []string{"/"}
	}
	for _, prefix := range raw.AllowedPathPrefixes {
		if !strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\r\n\x00") {
			return Profile{}, fmt.Errorf("policy validation failed (%s): invalid path prefix %q", raw.Name, prefix)
		}
	}
	if raw.TimeoutMS == 0 {
		raw.TimeoutMS = 10000
	}
	if raw.TimeoutMS < 100 || raw.TimeoutMS > 120000 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): timeoutMs is outside bounds", raw.Name)
	}
	if raw.MaxRequestBytes == 0 {
		raw.MaxRequestBytes = 65536
	}
	if raw.MaxRequestBytes < 0 || raw.MaxRequestBytes > 10*1024*1024 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): maxRequestBytes is outside bounds", raw.Name)
	}
	if raw.MaxResponseBytes == 0 {
		raw.MaxResponseBytes = 262144
	}
	if raw.MaxResponseBytes < 1 || raw.MaxResponseBytes > 10*1024*1024 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): maxResponseBytes is outside bounds", raw.Name)
	}
	if raw.RateLimit.MaxRequests == 0 {
		raw.RateLimit = RateLimit{MaxRequests: 30, WindowMS: 60000}
	}
	if raw.RateLimit.MaxRequests < 1 || raw.RateLimit.MaxRequests > 10000 || raw.RateLimit.WindowMS < 100 || raw.RateLimit.WindowMS > 86400000 {
		return Profile{}, fmt.Errorf("policy validation failed (%s): rateLimit is outside bounds", raw.Name)
	}
	for i, header := range raw.RedactHeaders {
		raw.RedactHeaders[i] = strings.ToLower(header)
	}
	return deduplicateProfile(raw), nil
}

func normalizeHosts(hosts []string) []string {
	result := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, host := range hosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

func normalizeMethods(methods []string) []string {
	result := make([]string, 0, len(methods))
	seen := map[string]bool{}
	for _, method := range methods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

func deduplicateProfile(profile Profile) Profile {
	profile.RedactHeaders = normalizeHosts(profile.RedactHeaders)
	return profile
}

func IsPrivateOrReservedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() {
		return true
	}
	if parsed.To4() != nil {
		v4 := parsed.To4()
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}
