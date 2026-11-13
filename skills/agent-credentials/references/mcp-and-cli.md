# `agent-cred` MCP & CLI Reference for Agents

## 1. MCP Tools (`agent-cred mcp`)

- `credential_list_profiles`: Lists profile names, allowed hosts/methods, and `secretPresent` boolean.
- `credential_inspect_policy`: Inspects `{ "profile": "<name>" }` policy limits and redaction rules.
- `credential_http_request`: Executes `{ "profile": "<name>", "method": "GET", "url": "https://..." }`.
- `credential_test_connection`: Runs the profile's read-only health check `{ "profile": "<name>" }`.

## 2. CLI Commands

```bash
# Initialize non-secret .agent-cred/ policy skeleton and .gitignore rules
agent-cred init

# Import secret from gitignored .env.local into OS keychain (human runs this)
agent-cred import --profile example-github-readonly --env-file .env.local GITHUB_READONLY_TOKEN=github_pat_readonly

# Inspect profile policy metadata
agent-cred inspect --profile example-github-readonly

# Perform a policy-checked HTTPS request
agent-cred request --profile example-github-readonly --method GET --url https://api.github.com/rate_limit

# Safe curl compatibility mode
agent-cred curl --profile example-github-readonly -X GET https://api.github.com/rate_limit
```

## 3. `rsc-harness` `01-TOOLS/<TOOL>/test_connection` Template

```bash
#!/usr/bin/env bash
set -euo pipefail
agent-cred test --profile example-github-readonly
```
