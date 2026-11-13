# Build Report: `agent-cred`

## 1. Summary of Delivered Artifacts

- **CLI Entry Point**: [`bin/agent-cred.js`](./bin/agent-cred.js) (`init`, `import`, `list`, `inspect`, `request`, `curl`, `test`, `mcp`, `doctor`; rejects `exec`/`run` by design).
- **Core Modules**:
  - [`src/policy-store.js`](./src/policy-store.js) — Strict fail-closed policy schema (`PolicyStore`, `validateProfile`, `initWorkspaceSkeleton`), atomic writes, and `0600` file permissions.
  - [`src/secret-store.js`](./src/secret-store.js) — `OsKeychainStore` (Linux `secret-tool` and macOS `security` via `stdin`), `DevFileSecretStore` (`--allow-dev-store` required), `MemorySecretStore`, and `.env` importer (`importFromEnvFile`).
  - [`src/broker.js`](./src/broker.js) — Capability-based HTTP broker enforcing HTTPS-only default, host/method/path allowlists, request/response size bounds, sliding-window rate limits, and local redacted audit logging.
  - [`src/http-transport.js`](./src/http-transport.js) — Native Node HTTP/HTTPS client with pinned DNS socket lookup, private/metadata IP SSRF blocking, timeout enforcement, and manual redirect handling.
  - [`src/redactor.js`](./src/redactor.js) — Strips literal, URL-encoded, base64/base64url, Basic auth, standard token prefixes (`ghp_`, `github_pat_`, `sk-ant-`), sensitive headers, and profile regexes.
  - [`src/curl-compat.js`](./src/curl-compat.js) — Safe `curl` parser rejecting dangerous flags (`-K`, `-d @file`, `-L`, `-u`, `-o`, `-F`, `-T`, `-k`, `-x`, `-v`, `--trace`).
  - [`src/mcp/server.js`](./src/mcp/server.js) — Stdio MCP server exposing `credential_list_profiles`, `credential_inspect_policy`, `credential_http_request`, and `credential_test_connection` with `<untrusted_api_data>` framing.
- **Harness Skill & Docs**:
  - [`skills/agent-credentials/SKILL.md`](./skills/agent-credentials/SKILL.md) and [`skills/agent-credentials/references/mcp-and-cli.md`](./skills/agent-credentials/references/mcp-and-cli.md)
  - [`README.md`](./README.md), [`SECURITY.md`](./SECURITY.md), [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md), [`CONTRIBUTING.md`](./CONTRIBUTING.md), [`LICENSE`](./LICENSE)
- **Test & Verification Suite**:
  - [`test/broker-core.test.js`](./test/broker-core.test.js)
  - [`test/e2e.test.js`](./test/e2e.test.js)
  - [`test/security-boundaries.test.js`](./test/security-boundaries.test.js)
  - [`scripts/lint.js`](./scripts/lint.js) and [`scripts/demo.js`](./scripts/demo.js)

---

## 2. Exact Commands Run & Observed Results

### Phase 1: RED Test Execution (Before Implementation)
Command:
```bash
npm test
```
Observed result:
- Exited with code `1` (`ERR_MODULE_NOT_FOUND` for `src/policy-store.js` across `test/broker-core.test.js` and `test/e2e.test.js`).

### Phase 2: GREEN Test Execution & Full Verification
Command:
```bash
npm install && npm test && npm run lint && npm run doctor && npm run demo && npm pack --dry-run
```
Observed results:
- `npm install`: `audited 1 package in 307ms, found 0 vulnerabilities` (generated `package-lock.json` with zero external runtime dependencies).
- `npm test`: `9 passed, 0 failed` (`test/broker-core.test.js`, `test/e2e.test.js`, `test/security-boundaries.test.js`).
- `npm run lint`: `Lint OK: checked 15 JS files (syntax + security invariants).`
- `npm run doctor`: `{"healthy": true, "nodeVersion": "22.22.3", "nodeSupported": true, "platform": "linux", "osKeychainBinary": "/usr/bin/secret-tool", "osKeychainAvailable": true, ...}`
- `npm run demo`: Initialized temporary workspace, imported synthetic token (`SYNTH_DEMO_CREDENTIAL_DO_NOT_USE_000111222`), executed policy-checked GET request and connection test against ephemeral `127.0.0.1` server, and verified `[REDACTED_SECRET]` replacement with zero secret leakage.
- `npm pack --dry-run`: Verified tarball (`18` files, `31.0 kB` packed, no secrets or test scratch files included).

---

## 3. Known Limitations

1. **Same-UID OS Privilege Boundary**: Any process running unrestricted under the same OS user account (`UID`) can invoke the OS keychain or read user-owned files directly. `agent-cred` protects secrets when agents are gated from arbitrary shell/keychain execution and interact with external APIs through the broker.
2. **Per-Process Rate-Limit Buckets**: Sliding-window rate limits (`rateLimit`) are held in memory per broker process. Prefer the long-lived `agent-cred mcp` server over repeated one-shot CLI invocations when enforcing session-wide rate limits.
3. **Transformative Server Echo**: `Redactor` strips literal, URL-encoded, and base64-encoded secrets plus configured regex patterns, but cannot detect a secret if a remote endpoint encrypts or hashes it before echoing it back.

---

## 4. Proposed Next Step

Wire `agent-cred mcp` into the local software-factory (`zellia-factory` / `factory.sh`) planner and checker agent configurations with a read-only GitHub profile (`allowedMethods: ["GET"]`, `allowedHosts: ["api.github.com"]`), replacing direct `gh` token inheritance in phase subshells.

## 5. Independent Verification After Agy

- `npm test`: 9 passed, 0 failed.
- `npm run lint`: passed; 15 JavaScript files checked.
- `npm run doctor`: healthy on Node 22.22.3; Linux OS keychain binary detected.
- `npm run demo`: passed with synthetic credentials and zero raw-secret leakage in output.
- `npm audit --omit=dev`: 0 vulnerabilities.
- `npm pack --dry-run`: passed; no test scratch files or credential stores included.
- Added CI workflow at `.github/workflows/ci.yml`.
- Hardened DNS validation to inspect all resolved addresses before connecting.
- Replaced absolute local `file://` links in public documentation with repository-relative links.
- Added public-facing project positioning: badges, release status, changelog, roadmap, and code of conduct.

## 6. Release 0.2.0 Verification Additions

- Added `.github/workflows/windows.yml` for Node 22 on `windows-latest`.
- Added `Dockerfile.test` and verified `docker build` + `docker run` locally on Linux.
- Added `docs/AGENT-COMPATIBILITY.md` with local CLI versions and honest smoke results.
- Smoke tests passed for OpenCode 2.2.5, Pi 1.3.0, Agy 1.5.6 using Gemini 4 Argon Low, and Codex 0.160.0.
- Cursor Agent, Claude Code, and Gemini CLI were detected but not authenticated; no credentials were supplied.
- Cursor GUI was not run because this shell has no X display.
- A Windows container was not started because the local Docker daemon is Linux; Windows containers require a Windows daemon or VM.
- Initial Windows CI exposed a POSIX mode-bit assertion (`438 !== 384`); release `v0.2.1` made that test platform-aware and Windows CI then passed.

## 7. Native Go Release 0.3.0

- Native CLI and MCP executable built from `cmd/agent-cred`.
- `go test ./...`: passed.
- `go vet ./...`: passed.
- Linux native build: passed.
- Windows amd64 cross-build: passed.
- macOS arm64 cross-build: passed.
- MCP initialize/tools/list/tools/call smoke: passed.
- Synthetic import/list/redaction smoke: passed with no secret output.
## 8. Native Windows Credential Manager Runtime Verification

- Windows Credential Manager round-trip test executed successfully in Windows CI using a synthetic credential.
- Node-vs-Go differential probes matched the required exit codes and exposed four MCP tools in both implementations.
- The Windows runner still emitted a non-blocking setup-go cache annotation; no product test failed.