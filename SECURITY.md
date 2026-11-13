# Security Policy & Threat Model (`agent-cred`)

## Fundamental Security Boundary (Same-UID Truth)

**No user-space credential broker can protect secrets from arbitrary code executing unrestricted with the same operating-system user privileges (`UID`).**

If an agent is granted unrestricted shell execution (`bash`, `python`, `node`, or `Bash($TEST_CMD)` in a software factory) running under the same OS user account that owns the OS keychain or secret store, malicious or prompt-injected code running in that user context can invoke the OS keychain or read user-accessible files directly.

Therefore:
1. **`agent-cred` deliberately refuses to implement a generic `agent-cred exec <cmd>` command** that injects secrets into child process environments or `stdin`.
2. **Safe agent access is capability-based**: the agent should be restricted from raw shell/keychain access (via `--disallowedTools`, sandbox profiles, or separate OS users/containers) and permitted to interact with external APIs **only** through `agent-cred` (MCP server or scoped CLI subcommands `request`, `curl`, `test`).
3. Inside `agent-cred`, secrets are attached only to policy-approved HTTP requests in memory and redacted from all responses, headers, errors, and audit logs.

---

## Threat Matrix & Mitigations

| Threat / Attack Vector | How `agent-cred` Mitigates It | Residual Limitation |
| :--- | :--- | :--- |
| **Prompt Injection via Tickets / API Responses** | All MCP tool descriptions and responses wrap external payloads in `<untrusted_api_data>` warnings. The broker enforces strict host, method, and path allowlists regardless of what the LLM requests. | If a profile allows `POST`/`DELETE` on a broad path prefix, a prompt-injected agent can still invoke allowed mutations within that profile's scope. Use read-only (`GET`) profiles by default. |
| **Exfiltration to Attacker Host (SSRF / Off-Host Leak)** | Every profile requires an explicit `allowedHosts` list (exact hostname match; wildcards like `*.example.com` are rejected). Automatic HTTP redirects (`301`/`302`/`307`/`308`) are never followed, preventing an allowlisted host from redirecting a credentialed request to an external server. | If an allowlisted host itself has an open user-content echo endpoint, data sent in the request body could be stored on that allowlisted host. Bound `maxRequestBytes` and `allowedPathPrefixes`. |
| **SSRF to Cloud Metadata or Internal Networks** | `src/http-transport.js` blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local / cloud metadata (`169.254.0.0/16`), CGNAT (`100.64/10`), and IPv6 ULA/link-local (`fc00::/7`, `fe80::/10`) by default. | Loopback HTTP is only permitted when **both** `profile.allowHttpLocalhost: true` and `--allow-http-localhost` are explicitly enabled for local test servers. |
| **DNS Rebinding** | `createPinnedLookup` in `src/http-transport.js` validates the DNS-resolved IP address inside the socket's custom `lookup` hook and passes that exact IP directly to `net.Socket`, eliminating the TOCTOU window between DNS check and TCP connect. | Custom DNS resolvers returning public IPs that route internally via NAT hairpinning require network-level egress rules. |
| **Response Echo / Output Secret Leakage** | `src/redactor.js` strips the raw secret, URL-encoded secret, base64 and base64url encodings, Basic-auth `:`-prefixed base64 encodings, standard token prefixes (`ghp_`, `github_pat_`, `sk-ant-`, `Bearer ...`), sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`), and profile `redactPatterns` from response bodies, headers, errors, and audit logs. | If a remote server encrypts, hashes, or splits a secret across non-contiguous characters before echoing it, string/regex redaction cannot detect the transformed value. |
| **Process Table (`ps` / `argv`) & Environment Leaks** | Secrets are never passed on `argv` or exported into child environments. `OsKeychainStore` writes secrets via `stdin` (`secret-tool store` / `security -i`) with `shell: false` and a stripped environment. `agent-cred curl` rejects `-u`, `--oauth2-bearer`, `-K`, and `-v`/`--trace`. | During `agent-cred import --env-file`, the source `.env` file exists on disk until deleted by the user. Store secrets in the OS keychain and delete temporary `.env` files immediately after import. |
- **File Permission & Partial-Write Leaks** | `.agent-cred/` is created with mode `0700` and policy/audit files are written atomically with `0600` on POSIX platforms (`fsync` + `rename`). On Windows, NTFS/ACL inheritance is the platform boundary and POSIX mode-bit assertions are skipped. | Non-POSIX filesystems (including FAT/exFAT) may ignore `chmod`; keep the profile directory user-private and run `agent-cred doctor`.
| **Keychain Unavailability / Headless CI Fallback** | `OsKeychainStore` is the default (`secret-tool` on Linux, `security` on macOS). `DevFileSecretStore` (`--store dev-file`) refuses to run unless `--allow-dev-store` is explicitly passed and stores secrets only in a gitignored `0700`/`0600` path. | `DevFileSecretStore` stores unencrypted JSON protected only by OS file permissions (`0600`). Never use `dev-file` for production credentials on shared machines. |
| **Replay & Runaway Agent Loops (Rate Limits)** | Each profile enforces a sliding-window rate limit (`rateLimit: { maxRequests, windowMs }`, default `30` requests / `60000` ms), `timeoutMs` (default `10000` ms), `maxRequestBytes`, and `maxResponseBytes`. | Rate limits are tracked per broker process; spawning many short-lived CLI processes resets in-memory buckets. Prefer running the persistent `agent-cred mcp` server for session-wide rate limiting. |
| **Credential Rotation** | Credentials are referenced by logical profile and credential name (`profile` + `credential.name`). Rotating a token requires only re-running `agent-cred import` with the new token and revoking the old token at the provider—no agent prompt or code changes needed. | Prefer short-lived, read-only tokens (1–24h expiry) and revoke immediately after an audit or factory run. |

---

## Reporting a Vulnerability

Do not open public GitHub issues for suspected security vulnerabilities. Report security findings privately to the repository maintainers with:
1. Affected version / commit SHA
2. Minimal reproduction using **synthetic test credentials only** (never include real tokens in reports)
3. Expected vs. observed security boundary behavior
