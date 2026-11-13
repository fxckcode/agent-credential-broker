# Changelog

All notable changes to `agent-cred` are documented here.

## [0.3.1] - 2026-11-13

### Fixed

- Added a Windows-only Credential Manager round-trip test that writes, reads, and deletes a synthetic credential in the Windows CI runner.
- Removed Go module cache configuration from CI because this repository has no `go.sum`; this eliminates the non-failing cache warning.

## [0.3.0] - 2026-11-13

### Added

- Native Go executable; Node.js is no longer required at runtime.
- Cross-platform build targets for Linux, Windows, and macOS.
- Windows Credential Manager adapter through the native Windows credential APIs.
- Linux Secret Service and macOS Keychain adapters behind a common Go interface.
- Native Go policy validation, atomic policy storage, SSRF-aware HTTP transport, redaction, rate limiting, and request bounds.
- Native Go CLI commands: `init`, `import`, `list`, `inspect`, `request`, `curl`, and `doctor`.
- Native Go MCP stdio server with four brokered tools.
- Differential migration boundary retaining the Node implementation as a temporary behavioral oracle.

### Security

- Generic secret-injecting `exec` remains rejected by design.
- Credentials never enter agent argv, environment, prompts, repository files, or MCP responses.
- MCP API responses are explicitly framed as untrusted external data.

## [0.2.1] - 2026-11-13

### Added

- Cross-platform verification workflow for Linux and Windows runners.
- Local container verification path for Node 22.
- Agent compatibility smoke-test documentation for OpenCode, Cursor Agent, Pi, Agy, Claude Code, and Codex.
- Explicit release guidance for headless agents and GUI-only Cursor installations.

### Security

- The Windows path validates the same no-secret-injection contract; it does not weaken the same-UID boundary.

## [0.1.1] - 2026-11-13

### Fixed

- Corrected local CLI examples so they do not imply that the package is already published to npm.

## [0.1.0] - 2026-11-13

### Added

- Capability-based credential broker for coding agents.
- CLI commands for initialization, import, policy inspection, HTTP requests, safe curl compatibility, connection tests, and diagnostics.
- Stdio MCP server with metadata-only and brokered HTTP tools.
- Linux Secret Service and macOS Keychain adapters.
- Explicit development-only file secret store for synthetic tests.
- Exact host, method, path, timeout, size, rate, HTTPS, and SSRF controls.
- Response and audit redaction for common credential encodings.
- `rsc-harness` integration skill and security documentation.
- Node 22 CI, security-boundary tests, local demo, and MIT license.
