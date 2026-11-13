package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fxckcode/agent-credential-broker/internal/broker"
	"github.com/fxckcode/agent-credential-broker/internal/curl"
	"github.com/fxckcode/agent-credential-broker/internal/mcp"
	"github.com/fxckcode/agent-credential-broker/internal/policystore"
	"github.com/fxckcode/agent-credential-broker/internal/secrets"
)

const Version = "0.3.0"

type contextOptions struct {
	cwd           string
	policyFile    string
	storeType     string
	allowDevStore bool
	allowHTTP     bool
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printHelp(stdout)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}
	command := args[0]
	options, rest, err := parseOptions(args[1:])
	if err != nil {
		return writeError(stderr, err)
	}
	switch command {
	case "init":
		return runInit(options, stdout, stderr)
	case "doctor":
		return runDoctor(options, stdout, stderr)
	case "import":
		return runImport(options, rest, stdout, stderr)
	case "list":
		return runList(options, stdout, stderr)
	case "inspect":
		return runInspect(options, rest, stdout, stderr)
	case "request":
		return runRequest(options, rest, stdout, stderr)
	case "curl":
		return runCurl(options, rest, stdout, stderr)
	case "mcp":
		return runMCP(options, stdout, stderr)
	case "exec", "run":
		return writeError(stderr, errors.New("generic secret-injecting exec is rejected by design; use request, curl, or MCP"))
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q; run `agent-cred help`\n", command)
		return 2
	}
}

func printHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, "agent-cred — capability-based credential broker")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Usage: agent-cred <command> [options]")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Commands:")
	_, _ = fmt.Fprintln(w, "  init       Initialize local non-secret policy storage")
	_, _ = fmt.Fprintln(w, "  import     Import a credential into the OS keychain")
	_, _ = fmt.Fprintln(w, "  list       List profile metadata without secrets")
	_, _ = fmt.Fprintln(w, "  inspect    Inspect one profile policy")
	_, _ = fmt.Fprintln(w, "  request    Perform an allowlisted HTTP request")
	_, _ = fmt.Fprintln(w, "  curl       Safe curl-compatible request (coming next)")
	_, _ = fmt.Fprintln(w, "  doctor     Check local broker capabilities")
	_, _ = fmt.Fprintln(w, "  mcp        Run the MCP server over stdio (coming next)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Global options:")
	_, _ = fmt.Fprintln(w, "  --cwd <dir>                 Workspace directory")
	_, _ = fmt.Fprintln(w, "  --policy-file <path>        Override profiles.json")
	_, _ = fmt.Fprintln(w, "  --store <type>              os-keychain (default) or dev-file")
	_, _ = fmt.Fprintln(w, "  --allow-dev-store           Explicitly allow dev-file storage")
	_, _ = fmt.Fprintln(w, "  --allow-http-localhost      Allow explicit loopback HTTP")
}

func parseOptions(args []string) (contextOptions, []string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return contextOptions{}, nil, err
	}
	options := contextOptions{cwd: cwd, storeType: os.Getenv("AGENT_CRED_STORE"), allowDevStore: os.Getenv("AGENT_CRED_ALLOW_DEV_STORE") == "1"}
	if options.storeType == "" {
		options.storeType = "os-keychain"
	}
	remaining := []string{}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		next := func() (string, error) {
			index++
			if index >= len(args) {
				return "", fmt.Errorf("missing value after %s", arg)
			}
			return args[index], nil
		}
		switch arg {
		case "--cwd":
			value, nextErr := next()
			if nextErr != nil {
				return options, nil, nextErr
			}
			options.cwd, err = filepath.Abs(value)
			if err != nil {
				return options, nil, err
			}
		case "--policy-file":
			value, nextErr := next()
			if nextErr != nil {
				return options, nil, nextErr
			}
			options.policyFile, err = filepath.Abs(value)
			if err != nil {
				return options, nil, err
			}
		case "--store":
			value, nextErr := next()
			if nextErr != nil {
				return options, nil, nextErr
			}
			options.storeType = value
		case "--allow-dev-store":
			options.allowDevStore = true
		case "--allow-http-localhost":
			options.allowHTTP = true
		default:
			remaining = append(remaining, arg)
		}
	}
	if options.policyFile == "" {
		options.policyFile = filepath.Join(options.cwd, ".agent-cred", "profiles.json")
	}
	return options, remaining, nil
}

func createStore(options contextOptions) (secrets.Store, error) {
	if options.storeType == "dev-file" {
		return secrets.NewDevFileStore(filepath.Join(options.cwd, ".agent-cred", "dev-secrets"), options.allowDevStore)
	}
	if options.storeType != "os-keychain" {
		return nil, fmt.Errorf("unsupported secret store %q", options.storeType)
	}
	return secrets.NewOSKeychainStore("agent-cred")
}

func createBroker(options contextOptions) (*broker.Broker, error) {
	policies, err := policystore.New(options.policyFile)
	if err != nil {
		return nil, err
	}
	store, err := createStore(options)
	if err != nil {
		return nil, err
	}
	return broker.New(policies, store)
}

func runInit(options contextOptions, stdout, stderr io.Writer) int {
	path, err := policystore.InitWorkspace(options.cwd)
	if err != nil {
		return writeError(stderr, err)
	}
	if err := writeJSON(stdout, map[string]any{"status": "initialized", "policyFile": path}); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func runDoctor(options contextOptions, stdout, stderr io.Writer) int {
	store, err := createStore(options)
	if err != nil {
		return writeError(stderr, err)
	}
	policies, err := policystore.New(options.policyFile)
	if err != nil {
		return writeError(stderr, err)
	}
	profiles, profileErr := policies.LoadProfiles()
	policyStatus := "valid"
	if profileErr != nil {
		policyStatus = "invalid"
	}
	result := map[string]any{
		"healthy":        profileErr == nil,
		"runtime":        "go",
		"goVersion":      runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"implementation": "native-go",
		"secretValues":   "not inspected",
		"secretStore":    store.Kind(),
		"policyFile":     options.policyFile,
		"policyStatus":   policyStatus,
		"profileCount":   len(profiles),
	}
	if profileErr != nil {
		result["error"] = profileErr.Error()
	}
	if err := writeJSON(stdout, result); err != nil {
		return writeError(stderr, err)
	}
	if profileErr != nil {
		return 1
	}
	return 0
}

func runList(options contextOptions, stdout, stderr io.Writer) int {
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	profiles, err := service.ListProfiles()
	if err != nil {
		return writeError(stderr, err)
	}
	metadata := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		metadata = append(metadata, map[string]any{"name": profile.Name, "description": profile.Description, "allowedHosts": profile.AllowedHosts, "allowedMethods": profile.AllowedMethods})
	}
	if err := writeJSON(stdout, map[string]any{"profiles": metadata}); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func runInspect(options contextOptions, args []string, stdout, stderr io.Writer) int {
	profile, err := requiredValue(args, "--profile")
	if err != nil {
		return writeError(stderr, err)
	}
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	value, err := service.InspectProfile(profile)
	if err != nil {
		return writeError(stderr, err)
	}
	if err := writeJSON(stdout, map[string]any{"policy": value}); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func runImport(options contextOptions, args []string, stdout, stderr io.Writer) int {
	profile, err := requiredValue(args, "--profile")
	if err != nil {
		return writeError(stderr, err)
	}
	envPath, err := requiredValue(args, "--env-file")
	if err != nil {
		return writeError(stderr, err)
	}
	mappings := positionalAfterFlags(args, "--profile", "--env-file")
	if len(mappings) == 0 {
		return writeError(stderr, errors.New("import requires KEY=credential-name mappings"))
	}
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	_ = service
	store, err := createStore(options)
	if err != nil {
		return writeError(stderr, err)
	}
	values, err := readEnvFile(filepath.Join(options.cwd, envPath))
	if err != nil {
		return writeError(stderr, err)
	}
	imported := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		parts := strings.SplitN(mapping, "=", 2)
		if len(parts) != 2 {
			return writeError(stderr, fmt.Errorf("invalid mapping %q", mapping))
		}
		value, ok := values[parts[0]]
		if !ok {
			return writeError(stderr, fmt.Errorf("environment key %q not found", parts[0]))
		}
		if err := store.Set(profile, parts[1], value); err != nil {
			return writeError(stderr, err)
		}
		imported = append(imported, parts[0]+"="+parts[1])
	}
	if err := writeJSON(stdout, map[string]any{"status": "imported", "profile": profile, "mappings": imported}); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func runRequest(options contextOptions, args []string, stdout, stderr io.Writer) int {
	profile, err := requiredValue(args, "--profile")
	if err != nil {
		return writeError(stderr, err)
	}
	method, err := requiredValue(args, "--method")
	if err != nil {
		return writeError(stderr, err)
	}
	target, err := requiredValue(args, "--url")
	if err != nil {
		return writeError(stderr, err)
	}
	body, _ := optionalValue(args, "--body")
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	result, err := service.Execute(context.Background(), broker.Request{Profile: profile, Method: method, URL: target, Body: body, AllowHTTPLocalhost: options.allowHTTP})
	if err != nil {
		return writeError(stderr, err)
	}
	if err := writeJSON(stdout, result); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func runCurl(options contextOptions, args []string, stdout, stderr io.Writer) int {
	request, err := curl.Parse(args)
	if err != nil {
		return writeError(stderr, err)
	}
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	var timeout time.Duration
	if request.TimeoutSeconds > 0 {
		timeout = time.Duration(request.TimeoutSeconds * float64(time.Second))
	}
	result, err := service.Execute(context.Background(), broker.Request{
		Profile: request.Profile, Method: request.Method, URL: request.URL,
		Headers: request.Headers, Body: request.Body, Timeout: timeout,
		AllowHTTPLocalhost: request.AllowHTTPLocalhost || options.allowHTTP,
	})
	if err != nil {
		return writeError(stderr, err)
	}
	if request.IncludeHeaders {
		for name, value := range result.Headers {
			_, _ = fmt.Fprintf(stdout, "%s: %s\n", name, value)
		}
		_, _ = fmt.Fprintln(stdout)
	}
	_, _ = fmt.Fprint(stdout, result.Body)
	if result.Body != "" && !strings.HasSuffix(result.Body, "\n") {
		_, _ = fmt.Fprintln(stdout)
	}
	return 0
}

func runMCP(options contextOptions, stdout, stderr io.Writer) int {
	service, err := createBroker(options)
	if err != nil {
		return writeError(stderr, err)
	}
	server, err := mcp.New(service)
	if err != nil {
		return writeError(stderr, err)
	}
	if err := server.Serve(os.Stdin, stdout); err != nil {
		return writeError(stderr, err)
	}
	return 0
}

func requiredValue(args []string, key string) (string, error) {
	value, ok := optionalValue(args, key)
	if !ok || value == "" {
		return "", fmt.Errorf("missing required %s", key)
	}
	return value, nil
}
func optionalValue(args []string, key string) (string, bool) {
	for index, arg := range args {
		if arg == key && index+1 < len(args) {
			return args[index+1], true
		}
	}
	return "", false
}
func positionalAfterFlags(args []string, flags ...string) []string {
	excluded := map[string]bool{}
	for _, flag := range flags {
		excluded[flag] = true
	}
	result := []string{}
	for index := 0; index < len(args); index++ {
		if excluded[args[index]] {
			index++
			continue
		}
		if !strings.HasPrefix(args[index], "-") {
			result = append(result, args[index])
		}
	}
	return result
}

func readEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env file line")
		}
		values[parts[0]] = strings.Trim(strings.TrimSuffix(parts[1], "\r"), "\"'")
	}
	return values, nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
func writeError(w io.Writer, err error) int {
	_, _ = fmt.Fprintf(w, "error: %s\n", err.Error())
	return 1
}
