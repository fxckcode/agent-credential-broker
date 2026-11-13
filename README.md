# `agent-cred` — Capability-Based Credential Broker & MCP Server for Coding Agents

[![CI](https://github.com/fxckcode/agent-credential-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/fxckcode/agent-credential-broker/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/fxckcode/agent-credential-broker?display_name=tag&sort=semver)](https://github.com/fxckcode/agent-credential-broker/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)

**Let agents use approved APIs without handing them your secrets.**

`agent-cred` is a local, capability-based credential broker with a CLI and MCP server for coding agents, software factories, and `rsc-harness`. It performs policy-approved HTTP requests while keeping raw credentials out of prompts, environment variables, process arguments, repository files, and returned output.

> [!IMPORTANT]
> **Security Truth (Same-UID Boundary)**
> No user-space software can prevent arbitrary code running with your OS user privileges (`UID`) from reading a secret if that secret is injected into its environment or `stdin`, or if the untrusted process can invoke the OS keychain directly.
> Therefore, `agent-cred` **does not provide a generic `exec` command that injects secrets**. Safe access is capability-based: the broker attaches the credential inside its own process, enforces strict host/method/path allowlists, and redacts secret material before returning the response.

---

## Quick Start

```bash
# 1. Build and verify the native executable
go test ./...
go build -o agent-cred ./cmd/agent-cred

# 2. Initialize non-secret policy skeleton (.agent-cred/profiles.json, .env.example, .gitignore)
./agent-cred init

# 3. Import a synthetic test credential (human runs this in their own terminal; never prints secret)
cp .env.example .env.local
./agent-cred import \
  --profile example-github-readonly \
  --env-file .env.local \
  GITHUB_READONLY_TOKEN=github_pat_readonly
rm .env.local

# 4. Inspect profile policy metadata (no secrets returned)
./agent-cred inspect --profile example-github-readonly

# 5. Execute a policy-checked HTTPS request
./agent-cred request \
  --profile example-github-readonly \
  --method GET \
  --url https://api.github.com/rate_limit
```

Run the local synthetic verification suite:

```bash
go test ./...
go vet ./...
```

---

## Project status

`agent-cred` is the native Go release (`0.3.0`) for safe local HTTP capabilities for coding agents. Read the [changelog](./CHANGELOG.md), [roadmap](./ROADMAP.md), and [security policy](./SECURITY.md) before adopting it for production credentials.

---

## Core Capabilities & Architecture

| Module | File | Responsibility |
| :--- | :--- | :--- |
| **Policy** | [`internal/policy`](./internal/policy) | Validates explicit non-secret profiles and deny-by-default request policy. |
| **Secret stores** | [`internal/secrets`](./internal/secrets) | Uses Linux Secret Service, macOS Keychain, Windows Credential Manager, or an explicitly acknowledged test-only store. |
| **Broker** | [`internal/broker`](./internal/broker) | Attaches credentials internally, enforces host/method/path/size/rate policies, and returns redacted responses. |
| **Transport** | [`internal/transport`](./internal/transport) | Performs bounded HTTP requests with HTTPS enforcement, DNS/IP SSRF checks, timeouts, and no redirects. |
| **Redaction** | [`internal/redaction`](./internal/redaction) | Removes raw and common encoded secret forms from response data and headers. |
| **CLI** | [`cmd/agent-cred`](./cmd/agent-cred) | Native executable for policy initialization, credential import, requests, safe curl, diagnostics, and MCP. |
| **MCP** | [`internal/mcp`](./internal/mcp) | Implements the stdio JSON-RPC server and four brokered tools. |
| **Legacy oracle** | [`src`](./src) | Temporary Node implementation retained for differential behavior checks during migration. |

---

## CLI Examples (Synthetic Credentials Only)

### 1. Non-Secret Profile Policy (`.agent-cred/profiles.json`)

```json
{
  "version": 1,
  "profiles": {
    "example-github-readonly": {
      "name": "example-github-readonly",
      "description": "Read-only GitHub API profile for issue and PR metadata",
      "credential": {
        "name": "github_pat_readonly",
        "scheme": "bearer",
        "headerName": "Authorization"
      },
      "allowedHosts": ["api.github.com"],
      "allowedMethods": ["GET"],
      "allowedPathPrefixes": ["/repos/", "/rate_limit"],
      "allowHttpLocalhost": false,
      "timeoutMs": 10000,
      "maxRequestBytes": 4096,
      "maxResponseBytes": 262144,
      "rateLimit": {
        "maxRequests": 30,
        "windowMs": 60000
      },
      "redactPatterns": ["gh[pousr]_[A-Za-z0-9_]+", "github_pat_[A-Za-z0-9_]+"],
      "redactHeaders": ["authorization", "x-github-sso"],
      "testRequest": {
        "method": "GET",
        "url": "https://api.github.com/rate_limit",
        "expectedStatuses": [200]
      }
    }
  }
}
```

### 2. Importing Synthetic Credentials for Tests

```bash
# Create a temporary synthetic env file (never use live tokens in repo files)
printf 'GITHUB_TOKEN=SYNTH_FAKE_TOKEN_FOR_LOCAL_TESTING_ONLY_12345\n' > .env.test

# Import into OS keychain (or add --store dev-file --allow-dev-store in headless CI tests)
./agent-cred import \
  --profile example-github-readonly \
  --env-file .env.test \
  GITHUB_TOKEN=github_pat_readonly

rm .env.test
```

### 3. Safe `curl` Compatibility Mode (`agent-cred curl`)

`agent-cred curl` parses a safe subset of `curl` flags (`--profile`, `-X`, `-H`, `-d`, `--json`, `-i`, `-s`, `-m`) without a shell and attaches credentials inside the broker:

```bash
./agent-cred curl \
  --profile example-github-readonly \
  -X GET \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/rate_limit
```

**Rejected `curl` flags (fail closed by design):**
- `-K` / `--config` (arbitrary file read / directive injection)
- `-d @file` (arbitrary local file read/exfiltration)
- `-L` / `--location` / `--location-trusted` (credential leak across redirect hops)
- `-u` / `--user` / `--oauth2-bearer` (secrets in `argv` / process table)
- `-o` / `-O` / `-D` / `-c` (unredacted file writes)
- `-F` / `-T` (file upload exfiltration)
- `-k` / `--insecure` (disabling TLS verification)
- `-x` / `--proxy` (proxy credential interception)
- `-v` / `--verbose` / `--trace` / `--trace-ascii` (header secret leakage)

---

## MCP Client Configuration

Start the stdio MCP server via `agent-cred mcp` (or `node /path/to/agent-credential-broker/bin/agent-cred.js mcp`).

### Claude Code / Cursor / Gemini CLI / Antigravity (`mcpServers`)

```json
{
  "mcpServers": {
    "agent-cred": {
      "command": "node",
      "args": [
        "/home/fxckcode/agent-credential-broker/bin/agent-cred.js",
        "mcp",
        "--cwd",
        "/path/to/your/project"
      ]
    }
  }
}
```

### Exposed MCP Tools

| Tool Name | Purpose | Secret Exposure |
| :--- | :--- | :--- |
| `credential_list_profiles` | Lists configured profiles, allowed hosts/methods, and `secretPresent` boolean. | **Metadata only** |
| `credential_inspect_policy` | Inspects full non-secret policy rules for a named profile. | **Metadata only** |
| `credential_http_request` | Executes a policy-checked HTTP request (`profile`, `method`, `url`, optional `headers`, `body`). Denies non-HTTPS unless both policy and `allowHttpLocalhost` permit loopback testing. | **Redacted output + `<untrusted_api_data>` wrapper** |
| `credential_test_connection` | Runs the profile's `testRequest` health check and reports status/latency. | **Status metadata only** |

---

## Integration with `rsc-harness` & Software Factories

### 1. `rsc-harness` (`skills/agent-credentials/` & `01-TOOLS/`)
- Install or symlink [`skills/agent-credentials/SKILL.md`](./skills/agent-credentials/SKILL.md) into `.rsc/skills/agent-credentials/`.
- In `01-TOOLS/<TOOL>/test_connection`, call `agent-cred test --profile <profile>` instead of sourcing `.env` into an untrusted shell.

### 2. Autonomous Software Factories (`zellia-factory` / `factory.sh`)
- Keep `agent-cred` independent of the target repository.
- Never pass API tokens into `factory.conf`, `Bash($TEST_CMD)`, or agent environment variables.
- Grant planner/checker/reviewer agents access only to the `agent-cred` MCP server (`--mcp-config`) with read-only (`GET`) profiles scoped to the specific issue tracker or API host.

---

## Design Limits

1. **Same-UID Arbitrary Code Execution**: If an agent can run unrestricted Python/Node/Bash commands as the same OS user, it can bypass any user-space broker and talk to the OS keychain or filesystem directly. Combine `agent-cred` with tool gating (`--disallowedTools`) or OS/container user separation for untrusted code execution.
2. **Allowed-Host Abuse**: If a profile permits `POST` to an allowlisted host, a prompt-injected agent can send non-secret workspace data in the `POST` body to that allowlisted host. Use `GET`-only profiles whenever write access is unnecessary, and keep `maxRequestBytes` small.
3. **Transformative Server Echo**: `Redactor` strips literal, URL-encoded, and base64-encoded secrets plus configured regex patterns. It cannot detect a secret if a malicious remote endpoint encrypts or permutes the secret before returning it. Only allowlist trusted API hosts.

See [`SECURITY.md`](./SECURITY.md) and [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) for the complete threat model.

---

## Verification Checklist

- [x] `go test ./...` — Go unit and security-boundary tests
- [x] `go vet ./...` — Go static analysis
- [x] `go build ./cmd/agent-cred` — Native executable build
- [x] `GOOS=windows GOARCH=amd64 go build ./cmd/agent-cred` — Windows executable cross-build
- [x] `GOOS=darwin GOARCH=arm64 go build ./cmd/agent-cred` — macOS executable cross-build
- [x] Native MCP `initialize`, `tools/list`, and `tools/call` frames
- [x] Synthetic credential import and redaction checks
- [x] Node implementation retained as a differential behavior oracle

## License

[MIT](./LICENSE)
