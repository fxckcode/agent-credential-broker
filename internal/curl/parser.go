package curl

import (
	"fmt"
	"strconv"
	"strings"
)

type Request struct {
	Profile            string
	Method             string
	URL                string
	Headers            map[string]string
	Body               string
	IncludeHeaders     bool
	Silent             bool
	TimeoutSeconds     float64
	AllowHTTPLocalhost bool
}

var rejected = map[string]string{
	"-K":                 "config files are unsupported",
	"--config":           "config files are unsupported",
	"-L":                 "automatic redirects are unsupported",
	"--location":         "automatic redirects are unsupported",
	"--location-trusted": "redirect credential forwarding is forbidden",
	"-u":                 "inline credentials are forbidden",
	"--user":             "inline credentials are forbidden",
	"--oauth2-bearer":    "inline bearer tokens are forbidden",
	"-k":                 "TLS verification cannot be disabled",
	"--insecure":         "TLS verification cannot be disabled",
	"-o":                 "direct file output is unsupported",
	"--output":           "direct file output is unsupported",
	"-O":                 "remote file output is unsupported",
	"--remote-name":      "remote file output is unsupported",
	"-F":                 "multipart file uploads are unsupported",
	"--form":             "multipart file uploads are unsupported",
	"-T":                 "file uploads are unsupported",
	"--upload-file":      "file uploads are unsupported",
	"-x":                 "custom proxies are unsupported",
	"--proxy":            "custom proxies are unsupported",
	"-v":                 "verbose traces are unsupported",
	"--verbose":          "verbose traces are unsupported",
	"--trace":            "traces are unsupported",
	"--trace-ascii":      "traces are unsupported",
}

func Parse(args []string) (Request, error) {
	request := Request{Headers: map[string]string{}}
	for index := 0; index < len(args); index++ {
		token := args[index]
		if reason, ok := rejected[token]; ok {
			return Request{}, fmt.Errorf("unsupported curl flag %q: %s", token, reason)
		}
		next := func() (string, error) {
			index++
			if index >= len(args) {
				return "", fmt.Errorf("missing value after %s", token)
			}
			return args[index], nil
		}
		switch token {
		case "--profile":
			value, err := next()
			if err != nil {
				return Request{}, err
			}
			request.Profile = value
		case "-X", "--request":
			value, err := next()
			if err != nil {
				return Request{}, err
			}
			request.Method = strings.ToUpper(value)
		case "-H", "--header":
			value, err := next()
			if err != nil {
				return Request{}, err
			}
			name, headerValue, err := parseHeader(value)
			if err != nil {
				return Request{}, err
			}
			request.Headers[name] = headerValue
		case "-d", "--data", "--data-raw", "--data-binary", "--json":
			value, err := next()
			if err != nil {
				return Request{}, err
			}
			if token != "--data-raw" && strings.HasPrefix(value, "@") {
				return Request{}, fmt.Errorf("@file body syntax is unsupported")
			}
			request.Body = value
			if token == "--json" && request.Headers["Content-Type"] == "" {
				request.Headers["Content-Type"] = "application/json"
			}
		case "-i", "--include":
			request.IncludeHeaders = true
		case "-s", "--silent", "-S", "--show-error", "-sS":
			request.Silent = true
		case "-m", "--max-time":
			value, err := next()
			if err != nil {
				return Request{}, err
			}
			seconds, parseErr := strconv.ParseFloat(value, 64)
			if parseErr != nil || seconds <= 0 || seconds > 120 {
				return Request{}, fmt.Errorf("invalid timeout value %q", value)
			}
			request.TimeoutSeconds = seconds
		case "--allow-http-localhost":
			request.AllowHTTPLocalhost = true
		default:
			if strings.HasPrefix(token, "-") {
				return Request{}, fmt.Errorf("unsupported or unknown curl option %q", token)
			}
			if request.URL != "" {
				return Request{}, fmt.Errorf("multiple URLs are unsupported")
			}
			request.URL = token
		}
	}
	if request.Profile == "" {
		return Request{}, fmt.Errorf("missing required --profile")
	}
	if request.URL == "" {
		return Request{}, fmt.Errorf("missing target URL")
	}
	if request.Method == "" {
		if request.Body != "" {
			request.Method = "POST"
		} else {
			request.Method = "GET"
		}
	}
	return request, nil
}

func parseHeader(value string) (string, string, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", "", fmt.Errorf("header contains forbidden control characters")
	}
	separator := strings.IndexByte(value, ':')
	if separator <= 0 {
		return "", "", fmt.Errorf("invalid header %q", value)
	}
	name := strings.TrimSpace(value[:separator])
	headerValue := strings.TrimSpace(value[separator+1:])
	if len(name) > 64 || strings.ContainsAny(name, " \t") {
		return "", "", fmt.Errorf("invalid header name %q", name)
	}
	if strings.EqualFold(name, "authorization") || strings.EqualFold(name, "proxy-authorization") {
		return "", "", fmt.Errorf("caller credential headers are forbidden")
	}
	return name, headerValue, nil
}
