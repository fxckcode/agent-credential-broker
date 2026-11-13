# Contributing to `agent-cred`

Thank you for helping keep coding agents and developer credentials safe.

## Core Principles

1. **Capability-Based Security Only**: Never propose features that inject raw secrets into child-process environments, `argv`, or generic `exec` wrappers.
2. **Zero Live Secrets in Repository**: All tests, fixtures, demos, and documentation examples must use clearly marked synthetic strings (e.g., `SYNTH_TEST_ONLY_...`).
3. **Fail Closed**: Any ambiguity in profile policy, URL parsing, host/method matching, or option parsing must throw an error before retrieving a secret.
4. **No Shell Execution**: Never use `shell: true`, `exec()`, or `eval()` in runtime code.

## Development Workflow

```bash
# Run syntax and security-invariant linter
npm run lint

# Run unit, boundary, and end-to-end tests
npm test

# Run environment doctor
npm run doctor

# Run self-contained synthetic demo
npm run demo
```

## Pull Request Checklist

- [ ] Tests added/updated in `test/*.test.js` (RED then GREEN)
- [ ] `npm test` and `npm run lint` pass with zero warnings
- [ ] No live tokens, private URLs, or personal identifiers in code, tests, or docs
- [ ] Conventional commit messages without AI attribution trailers
