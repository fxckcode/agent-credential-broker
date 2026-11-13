# Roadmap

## 0.1.x

- Improve cross-platform keychain adapters and diagnostics.
- Add profile export/import for non-secret policy only.
- Add a persistent local broker mode with shared rate-limit state.
- Add more protocol-specific adapters while preserving the capability boundary.

## 0.2.x

- Add optional OS/container isolation guidance for high-risk agents.
- Add signed, short-lived capability leases for multi-process factory runs.
- Add provider-specific setup recipes for Claude Code, Codex, Gemini CLI, Cursor, and OpenCode.
- Add richer redaction and response classification without claiming perfect secret detection.

## Non-goals

- Generic secret injection into arbitrary child processes.
- Returning raw credentials to an agent or MCP client.
- Remote telemetry or a hosted credential service in the core package.
