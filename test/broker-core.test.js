import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { PolicyStore } from '../src/policy-store.js';
import {
  MemorySecretStore,
  DevFileSecretStore,
  importFromEnvFile,
  validateSecretValue,
} from '../src/secret-store.js';
import { Redactor } from '../src/redactor.js';
import { parseCurlArgs } from '../src/curl-compat.js';
import { Broker } from '../src/broker.js';

function makeTempDir(prefix = 'agent-cred-core-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('PolicyStore enforces strict schema, atomic writes, and 0600 permissions', (t) => {
  const tmpDir = makeTempDir();
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const policyFile = path.join(tmpDir, '.agent-cred', 'profiles.json');
  const store = new PolicyStore(policyFile);

  const validProfile = {
    name: 'github-issues',
    description: 'Read-only GitHub issue access',
    credential: {
      name: 'gh_token',
      scheme: 'bearer',
      headerName: 'Authorization',
    },
    allowedHosts: ['api.github.com'],
    allowedMethods: ['GET'],
    allowedPathPrefixes: ['/repos/'],
    allowHttpLocalhost: false,
    timeoutMs: 5000,
    maxRequestBytes: 4096,
    maxResponseBytes: 65536,
    rateLimit: { maxRequests: 10, windowMs: 60000 },
    redactPatterns: ['INTERNAL_REF_[0-9]+'],
    redactHeaders: ['x-custom-secret'],
  };

  store.saveProfile(validProfile);
  const loaded = store.getProfile('github-issues');
  assert.equal(loaded.name, 'github-issues');
  assert.deepEqual(loaded.allowedHosts, ['api.github.com']);

  const stat = fs.statSync(policyFile);
  assert.equal(stat.mode & 0o777, 0o600, 'policy file must be 0600');

  // Fail closed on wildcard host
  assert.throws(
    () =>
      store.saveProfile({
        ...validProfile,
        name: 'bad-wildcard',
        allowedHosts: ['*.github.com'],
      }),
    /wildcard|invalid host/i
  );

  // Fail closed on unknown property
  assert.throws(
    () =>
      store.saveProfile({
        ...validProfile,
        name: 'bad-unknown',
        unexpectedField: true,
      }),
    /unknown|unexpected/i
  );

  // Fail closed on query auth scheme
  assert.throws(
    () =>
      store.saveProfile({
        ...validProfile,
        name: 'bad-query',
        credential: { name: 'tok', scheme: 'query', headerName: 'api_key' },
      }),
    /scheme/i
  );

  // Fail closed on malformed JSON on disk
  fs.writeFileSync(policyFile, '{malformed json', { mode: 0o600 });
  assert.throws(() => store.loadProfiles(), /malformed|invalid json/i);
});

test('SecretStore validates secret shapes, requires explicit dev-file opt-in, and imports .env without leaking', (t) => {
  const tmpDir = makeTempDir();
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  // Reject secrets with control characters / header injection
  assert.throws(
    () => validateSecretValue('synth_secret_with\r\nX-Injected: true'),
    /control character|newline|invalid/i
  );

  // DevFileSecretStore requires allowDevStore: true
  const secretsDir = path.join(tmpDir, 'dev-secrets');
  assert.throws(() => new DevFileSecretStore({ dir: secretsDir }), /allowDevStore|development/i);

  const devStore = new DevFileSecretStore({ dir: secretsDir, allowDevStore: true });
  const envFile = path.join(tmpDir, '.env.test');
  const syntheticSecret = 'SYNTH_TEST_ONLY_TOKEN_998877665544332211';
  fs.writeFileSync(
    envFile,
    `# Comment line\nexport GITHUB_TOKEN="${syntheticSecret}"\nOTHER_VAR=ignored\n`,
    { mode: 0o600 }
  );

  const result = importFromEnvFile({
    envFilePath: envFile,
    profile: 'github-issues',
    mappings: ['GITHUB_TOKEN=gh_token'],
    secretStore: devStore,
  });

  assert.equal(result.imported.length, 1);
  assert.equal(result.imported[0].envKey, 'GITHUB_TOKEN');
  assert.equal(result.imported[0].credentialName, 'gh_token');
  assert.equal(JSON.stringify(result).includes(syntheticSecret), false, 'import summary must never contain secret');
  assert.equal(devStore.hasSecret('github-issues', 'gh_token'), true);
  assert.equal(devStore.getSecret('github-issues', 'gh_token'), syntheticSecret);
});

test('Redactor strips raw, URL-encoded, base64-encoded secrets and custom patterns', () => {
  const rawSecret = 'SYNTH_SECRET_VALUE_ABCDEF1234567890';
  const redactor = new Redactor({
    secrets: [rawSecret],
    customPatterns: ['TICKET_INTERNAL_[0-9]{4}'],
    redactHeaders: ['authorization', 'x-api-key'],
  });

  const b64 = Buffer.from(rawSecret, 'utf8').toString('base64');
  const urlEnc = encodeURIComponent(rawSecret);

  const sample = `Header leak: ${rawSecret}, b64=${b64}, url=${urlEnc}, ref=TICKET_INTERNAL_4242, ghp_1234567890abcdef1234567890abcdef123456`;
  const redacted = redactor.redactText(sample);

  assert.equal(redacted.includes(rawSecret), false);
  assert.equal(redacted.includes(b64), false);
  assert.equal(redacted.includes('TICKET_INTERNAL_4242'), false);
  assert.equal(redacted.includes('ghp_1234567890'), false);
  assert.match(redacted, /\[REDACTED/);

  const redactedHeaders = redactor.redactHeaders({
    Authorization: `Bearer ${rawSecret}`,
    'Content-Type': 'application/json',
  });
  assert.equal(redactedHeaders.authorization.includes(rawSecret), false);
  assert.equal(redactedHeaders['content-type'], 'application/json');
});

test('parseCurlArgs supports safe subset and rejects dangerous curl flags', () => {
  const parsed = parseCurlArgs([
    '--profile',
    'api-prof',
    '-X',
    'POST',
    '-H',
    'Accept: application/json',
    '-d',
    '{"hello":"world"}',
    'https://api.example.com/v1/items',
  ]);
  assert.equal(parsed.profile, 'api-prof');
  assert.equal(parsed.method, 'POST');
  assert.equal(parsed.url, 'https://api.example.com/v1/items');
  assert.equal(parsed.body, '{"hello":"world"}');

  // Reject -K / --config
  assert.throws(
    () => parseCurlArgs(['--profile', 'api-prof', '-K', '/etc/passwd', 'https://api.example.com']),
    /unsupported|disallowed/i
  );

  // Reject @file data syntax
  assert.throws(
    () => parseCurlArgs(['--profile', 'api-prof', '-d', '@/etc/hostname', 'https://api.example.com']),
    /@file|unsupported|file/i
  );

  // Reject -L / --location (credential redirect leak risk)
  assert.throws(
    () => parseCurlArgs(['--profile', 'api-prof', '-L', 'https://api.example.com']),
    /redirect|unsupported/i
  );
});

test('Broker enforces rate limits and fails closed on missing profile or secret', async (t) => {
  const tmpDir = makeTempDir();
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const policyStore = new PolicyStore(path.join(tmpDir, '.agent-cred', 'profiles.json'));
  const secretStore = new MemorySecretStore();

  policyStore.saveProfile({
    name: 'strict-prof',
    credential: { name: 'api_key', scheme: 'bearer', headerName: 'Authorization' },
    allowedHosts: ['api.example.com'],
    allowedMethods: ['GET'],
    rateLimit: { maxRequests: 1, windowMs: 60000 },
  });

  const broker = new Broker({
    policyStore,
    secretStore,
    auditLogPath: path.join(tmpDir, '.agent-cred', 'audit.jsonl'),
    transport: async () => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
    }),
  });

  // Missing secret fails closed
  await assert.rejects(
    () => broker.executeRequest({ profile: 'strict-prof', method: 'GET', url: 'https://api.example.com/v1' }),
    /secret.*not found|missing credential/i
  );

  secretStore.setSecret('strict-prof', 'api_key', 'SYNTH_RATE_LIMIT_KEY_1234567890');

  // First call passes
  const res1 = await broker.executeRequest({
    profile: 'strict-prof',
    method: 'GET',
    url: 'https://api.example.com/v1',
  });
  assert.equal(res1.status, 200);

  // Second call within window exceeds rate limit
  await assert.rejects(
    () => broker.executeRequest({ profile: 'strict-prof', method: 'GET', url: 'https://api.example.com/v1' }),
    /rate limit/i
  );
});
