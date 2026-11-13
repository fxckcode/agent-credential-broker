# Agent Credential Broker — Go Migration

Objective: replace the Node.js implementation with a native Go executable while preserving the verified CLI/MCP security contract.
Branch: main (implementation will use reviewable work-unit commits)
Delivery strategy: ask-on-risk
Test runner: `go test ./...`; existing Node implementation remains the behavioral oracle until parity is verified.

## Specs

### S1 — Native executable
The project must provide a native `agent-cred` executable for Linux, Windows, and macOS without requiring Node.js or npm at runtime.

Acceptance: `go build ./cmd/agent-cred` succeeds; cross-compilation commands produce binaries for `linux/amd64`, `windows/amd64`, and `darwin/arm64`.
Checks: `go test ./...`; `go build ./cmd/agent-cred`; cross-build smoke checks.

### S2 — Preserve the security contract
The Go implementation must preserve the existing capability-based boundary: no generic secret-injecting `exec`; no raw secret in argv, environment, prompts, logs, audit output, or MCP responses; explicit policy; HTTPS and SSRF protection; bounded requests; redaction; deny-by-default.

Acceptance: existing synthetic security scenarios have Go equivalents and pass.
Checks: Go unit/integration tests plus differential comparison against the Node oracle.

### S3 — Preserve CLI and MCP interfaces
The Go implementation must preserve the current command names and stdio MCP behavior unless a documented incompatibility is proven.

Acceptance: `init`, `import`, `request`, `curl`, `doctor`, and `mcp` remain available; MCP tools remain metadata-only or brokered/redacted.
Checks: CLI contract tests and MCP JSON-RPC lifecycle tests.

### S4 — Cross-platform credential storage
Credential storage must use OS-native adapters where available and an explicitly acknowledged synthetic test adapter only for tests/demo.

Acceptance: Linux Secret Service, macOS Keychain, and Windows Credential Manager adapters are isolated behind one internal interface; tests never require live credentials.
Checks: adapter unit tests and Windows CI.

## Tasks

- T1 — Define Go module, executable layout, and protocol/domain types; route: inline; status: complete; commit: `d3585df` + `3abb45f`.
- T2 — Port policy, atomic storage, redaction, and HTTP transport with security tests; route: inline; status: complete; commit: `4848fbc` + `273c2ef` + `6c64374`.
- T3 — Port OS credential-store adapters and CLI commands; route: inline; status: in progress; commit: none.
- T4 — Port MCP stdio server and compatibility tests; route: inline; status: pending; commit: none.
- T5 — Run Node-vs-Go differential checks, cross-builds, agent smoke tests, and publish native release; route: inline; status: pending; commit: none.

## Log

L1 — User request: "no me ugsta mucho la idea de que esté en js, porque no golang o rust que me permite generar ejecutables?"

L2 — Decision: use Go for the native implementation because the project needs portable executables, stdio MCP, Windows support, and a lower migration/maintenance cost than Rust. Keep the current Node implementation as a temporary behavioral oracle until Go parity is proven.
