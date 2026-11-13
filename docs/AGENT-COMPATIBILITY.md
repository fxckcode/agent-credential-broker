# Cross-platform and local-agent verification

## Host limitation: Windows containers

This development host is Linux with a Linux Docker daemon. Docker cannot run Windows containers from this daemon; Windows containers require a Windows host/daemon or a Windows VM. The repository therefore verifies the same Node 22 contract in two ways:

- `Dockerfile.test` runs the full broker test/demo suite in a reproducible Linux container.
- `.github/workflows/windows.yml` runs `npm ci`, `npm test`, `npm run lint`, and `npm run doctor` on `windows-latest`.

A Windows container is not replaced by Wine. Wine is a different compatibility layer and is not an equivalent security or OS-keychain test.

## Local agent smoke tests

The local environment was checked without passing credentials to any agent. The smoke prompt was read-only and synthetic. Versions detected:

| Agent | Detected version | Headless status | Smoke result |
|---|---:|---|---|
| OpenCode | `2.2.5` | CLI available; provider/auth smoke depends on configured provider | **PASS** — synthetic read-only prompt returned exact marker |
| Cursor Agent | `2026.10.19-6bbf2c4` | CLI available | **NOT RUN** — authentication required; no credential was supplied |
| Pi | `1.3.0` | CLI available | **PASS** — synthetic read-only prompt returned marker (Pi redacted its own output metadata) |
| Agy | `1.5.6` | CLI available | **PASS** — Gemini 4 Argon Low synthetic read-only prompt returned marker |
| Claude Code | `2.1.240` | CLI available | **NOT RUN** — local OAuth session expired; no credential was supplied |
| Codex | `0.160.0` | CLI available | **PASS** — synthetic read-only prompt returned exact marker |
| Gemini CLI | `0.41.2` | CLI available | **NOT RUN** — no configured auth method; no credential was supplied |
| Cursor GUI command | unavailable in this headless shell | GUI process requires a display; use Cursor Agent for CI/smoke tests | **NOT RUN** — no X display in this shell |

The broker does not need an agent-specific credential injection path. Each agent should connect to the same stdio MCP command:

```json
{
  "mcpServers": {
    "agent-cred": {
      "command": "node",
      "args": ["/absolute/path/to/agent-credential-broker/bin/agent-cred.js", "mcp"]
    }
  }
}
```

The agent must only receive profile metadata and redacted broker responses. Do not add secrets to agent configuration, environment variables, or prompts.

## Commands

Linux container:

```bash
docker build -f Dockerfile.test -t agent-cred-test .
docker run --rm agent-cred-test
```

Host checks:

```bash
npm test
npm run lint
npm run doctor
npm run demo
```

## Evidence policy

A CLI version check proves installation, not provider authentication or MCP behavior. Provider calls may spend credits and can be unavailable without an account. Record those as `not_run` or `unavailable`, never as passing. The broker's own MCP lifecycle and security tests remain the authoritative local functional checks.
