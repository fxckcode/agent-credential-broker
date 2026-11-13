package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fxckcode/agent-credential-broker/internal/policy"
)

type Response struct {
	Status  int
	Headers http.Header
	Body    string
}

func Send(ctx context.Context, target string, method string, headers http.Header, body io.Reader, timeout time.Duration, maxResponseBytes int, allowLoopback bool) (Response, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return Response{}, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Hostname() == "" {
		return Response{}, fmt.Errorf("URL hostname is required")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowLoopback) {
		return Response{}, fmt.Errorf("only HTTPS URLs are allowed unless loopback HTTP is explicitly enabled")
	}
	if maxResponseBytes < 1 {
		return Response{}, fmt.Errorf("maxResponseBytes must be positive")
	}
	if timeout <= 0 {
		return Response{}, fmt.Errorf("timeout must be positive")
	}

	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DialContext:       pinnedDialer(allowLoopback),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return Response{}, fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header = headers.Clone()
	response, err := client.Do(request)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, int64(maxResponseBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Response{}, fmt.Errorf("read HTTP response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return Response{}, fmt.Errorf("response size exceeded policy maxResponseBytes (%d bytes)", maxResponseBytes)
	}
	return Response{Status: response.StatusCode, Headers: response.Header.Clone(), Body: string(data)}, nil
}

func pinnedDialer(allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("host %q has no addresses", host)
		}
		for _, resolved := range ips {
			if policy.IsPrivateOrReservedIP(resolved.IP.String()) && !(allowLoopback && resolved.IP.IsLoopback()) {
				return nil, fmt.Errorf("SSRF guard blocked connection to private/reserved IP address %q for host %q", resolved.IP.String(), host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func PortForURL(target string, defaultPort int) (string, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.Port() != "" {
		return parsed.Port(), nil
	}
	if defaultPort <= 0 {
		return "", fmt.Errorf("default port must be positive")
	}
	return strconv.Itoa(defaultPort), nil
}

func IsLoopbackHost(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
