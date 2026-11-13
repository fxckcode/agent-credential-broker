# `agent-cred` — Capability-Based Credential Broker & MCP Server for Coding Agents

[![CI](https://github.com/fxckcode/agent-credential-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/fxckcode/agent-credential-broker/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/fxckcode/agent-credential-broker?display_name=tag&sort=semver)](https://github.com/fxckcode/agent-credential-broker/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)

**Let agents use approved APIs without handing them your secrets.**

`agent-cred` is a local, capability-based credential broker with a CLI and MCP server for coding agents, software factories, and `rsc-harness`. It performs policy-approved HTTP requests while keeping raw credentials out of prompts, environment variables, process arguments, repository files, and returned output.

> [!IMPORTANT]
> **Security Truth (Same-UID Boundary)**
> No user-space software can prevent arbitrary code running with your OS user privileges (`UID`) from reading a secret if that secret is injected into its environment or `stdin`, or if the untrusted process can invoke the OS keychain directly.
> Therefore, `agent-cred` **does not provide a generic `exec` command that injects secrets**. Safe access is capability-based: the broker attaches the credential inside its own process, enforces strict host/method/path allowlists, and redacts secret material before returning the response.

---

## Quick Start

```bash
# 1. Install and run checks
npm install
npm test
npm run doctor

# 2. Initialize non-secret policy skeleton (.agent-cred/profiles.json, .env.example, .gitignore)
node bin/agent-cred.js init

# 3. Import a synthetic test credential (human runs this in their own terminal; never prints secret)
cp .env.example .env.local
node bin/agent-cred.js import \
  --profile example-github-readonly \
  --env-file .env.local \
  GITHUB_READONLY_TOKEN=github_pat_readonly
rm .env.local

# 4. Inspect profile policy metadata (no secrets returned)
node bin/agent-cred.js inspect --profile example-github-readonly

# 5. Execute a policy-checked HTTPS request
node bin/agent-cred.js request \
  --profile example-github-readonly \
  --method GET \
  --url https://api.github.com/rate_limit
```

Try the self-contained local demo using synthetic credentials against an ephemeral loopback server:

```bash
npm run demo
```

---

## Project status

`agent-cred` is an early open-source release (`0.1.0`) focused on safe local HTTP capabilities for coding agents. Read the [changelog](./CHANGELOG.md), [roadmap](./ROADMAP.md), and [security policy](./SECURITY.md) before adopting it for production credentials.

---

## Core Capabilities & Architecture

| Module | File | Responsibility |
| :--- | :--- | :--- |
| **`PolicyStore`** | [`src/policy-store.js`](./src/policy-store.js) | Validates and persists non-secret profile policies (`.agent-cred/profiles.json`, mode `0600`, atomic writes). Rejects unknown fields, wildcard hosts, and `query` auth schemes. |
| **`SecretStore`** | [`src/secret-store.js`](./src/secret-store.js) | Stores raw secrets in the OS keychain (`secret-tool` on Linux, `security` on macOS via `stdin`) or an explicit test-only `DevFileSecretStore` (`--store dev-file --allow-dev-store`). |
| **`Broker`** | [`src/broker.js`](./src/broker.js) | Enforces HTTPS-only default, exact host/method/path allowlists, request/response byte limits, sliding-window rate limits, and local redacted audit logging (`.agent-cred/audit.jsonl`). |
| **`HttpTransport`** | [`src/http-transport.js`](./src/http-transport.js) | Executes HTTP/HTTPS requests with pinned DNS socket lookup, private/metadata IP SSRF blocking (`169.254.169.254`, RFC1918, ULA), timeout enforcement, and no automatic redirect following. |
| **`Redactor`** | [`src/redactor.js`](./src/redactor.js) | Strips raw secrets, URL-encoded secrets, base64/base64url variants, Basic auth pairs, standard token shapes (`ghp_`, `github_pat_`, `sk-ant-`), sensitive headers, and profile regexes. |
| **`McpBrokerServer`** | [`src/mcp/server.js`](./src/mcp/server.js) | Exposes 4 stdio MCP tools (`credential_list_profiles`, `credential_inspect_policy`, `credential_http_request`, `credential_test_connection`) with `<untrusted_api_data>` framing. |

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
node bin/agent-cred.js import \
  --profile example-github-readonly \
  --env-file .env.test \
  GITHUB_TOKEN=github_pat_readonly

rm .env.test
```

### 3. Safe `curl` Compatibility Mode (`agent-cred curl`)

`agent-cred curl` parses a safe subset of `curl` flags (`--profile`, `-X`, `-H`, `-d`, `--json`, `-i`, `-s`, `-m`) without a shell and attaches credentials inside the broker:

```bash
node bin/agent-cred.js curl \
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

- [x] `npm test` — Runs unit, security-boundary, and end-to-end local HTTP server tests
- [x] `npm run lint` — Verifies syntax and checks that `shell: true` and `eval(` are absent
- [x] `npm run doctor` — Validates Node runtime (`>= 22`), OS keychain binary, and policy permissions
- [x] `npm run demo` — Runs a local-only synthetic credential demonstration

## License

[MIT](./LICENSE)
