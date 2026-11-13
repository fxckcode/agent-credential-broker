package redaction

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	redactedSecret  = "[REDACTED_SECRET]"
	redactedPattern = "[REDACTED_PATTERN]"
	redactedHeader  = "[REDACTED_HEADER]"
)

var builtinPatterns = []*regexp.Regexp{
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{12,255}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{12,255}`),
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{12,255}`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,512}`),
}

var defaultSensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true,
	"set-cookie": true, "x-api-key": true, "x-auth-token": true,
}

type Redactor struct {
	secretVariants  []string
	patterns        []*regexp.Regexp
	sensitiveHeader map[string]bool
}

func New(secrets, customPatterns, redactHeaders []string) (*Redactor, error) {
	variants := map[string]bool{}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		variants[secret] = true
		variants[url.QueryEscape(secret)] = true
		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		variants[encoded] = true
		variants[strings.TrimRight(encoded, "=")] = true
		urlEncoded := base64.RawURLEncoding.EncodeToString([]byte(secret))
		variants[urlEncoded] = true
		basic := base64.StdEncoding.EncodeToString([]byte(":" + secret))
		variants[basic] = true
		variants[strings.TrimRight(basic, "=")] = true
	}
	secretList := make([]string, 0, len(variants))
	for variant := range variants {
		if len(variant) >= 4 {
			secretList = append(secretList, variant)
		}
	}
	sort.Slice(secretList, func(i, j int) bool { return len(secretList[i]) > len(secretList[j]) })

	patterns := append([]*regexp.Regexp{}, builtinPatterns...)
	for _, expression := range customPatterns {
		if expression == "" {
			continue
		}
		compiled, err := regexp.Compile(expression)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, compiled)
	}

	sensitive := map[string]bool{}
	for header := range defaultSensitiveHeaders {
		sensitive[header] = true
	}
	for _, header := range redactHeaders {
		if strings.TrimSpace(header) != "" {
			sensitive[strings.ToLower(strings.TrimSpace(header))] = true
		}
	}
	return &Redactor{secretVariants: secretList, patterns: patterns, sensitiveHeader: sensitive}, nil
}

func (r *Redactor) Text(input string) string {
	output := input
	for _, variant := range r.secretVariants {
		output = strings.ReplaceAll(output, variant, redactedSecret)
	}
	for _, pattern := range r.patterns {
		output = pattern.ReplaceAllString(output, redactedPattern)
	}
	return output
}

func (r *Redactor) Headers(headers map[string][]string) map[string]string {
	output := make(map[string]string, len(headers))
	for key, values := range headers {
		value := strings.Join(values, ", ")
		lowerKey := strings.ToLower(key)
		if r.sensitiveHeader[lowerKey] {
			output[lowerKey] = redactedHeader
			continue
		}
		output[lowerKey] = r.Text(value)
	}
	return output
}
