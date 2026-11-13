package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

const Version = "0.3.0-dev"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printHelp(stdout)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}
	if args[0] == "doctor" {
		return runDoctor(stdout)
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q; run `agent-cred help`\n", args[0])
	return 2
}

func printHelp(w io.Writer) {
	_, _ = fmt.Fprintln(w, "agent-cred — capability-based credential broker")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Usage: agent-cred <command>")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Commands:")
	_, _ = fmt.Fprintln(w, "  init       Initialize local non-secret policy storage")
	_, _ = fmt.Fprintln(w, "  import     Import a credential into the OS keychain")
	_, _ = fmt.Fprintln(w, "  request    Perform an allowlisted HTTP request")
	_, _ = fmt.Fprintln(w, "  curl       Perform a safe curl-compatible request")
	_, _ = fmt.Fprintln(w, "  doctor     Check local broker capabilities")
	_, _ = fmt.Fprintln(w, "  mcp        Run the MCP server over stdio")
}

func runDoctor(w io.Writer) int {
	result := map[string]any{
		"healthy":        true,
		"runtime":        "go",
		"goVersion":      runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"secretValues":   "not inspected",
		"implementation": "native-go",
	}
	if _, err := os.Stat(".agent-cred"); err == nil {
		result["policyDirectory"] = "present"
	} else if os.IsNotExist(err) {
		result["policyDirectory"] = "missing"
	} else {
		result["healthy"] = false
		result["policyDirectory"] = "unreadable"
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintf(w, "doctor output failed: %v\n", err)
		return 1
	}
	return 0
}
