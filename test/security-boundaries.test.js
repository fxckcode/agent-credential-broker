import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';

import {
  PolicyStore,
  MemorySecretStore,
  Broker,
  isPrivateOrReservedIp,
  isLoopbackAddress,
  startStdioMcpServer,
} from '../src/index.js';

const CLI_PATH = path.resolve(import.meta.dirname, '../bin/agent-cred.js');

function makeTempDir(prefix = 'agent-cred-sec-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('SSRF IP classification blocks private, link-local, metadata, and reserved ranges', () => {
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('8.8.8.8'), false);

  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true, 'cloud metadata IP must be blocked');
  assert.equal(isPrivateOrReservedIp('10.1.2.3'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.31.255.255'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true);
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);
  assert.equal(isPrivateOrReservedIp('fc00::1'), true);
  assert.equal(isPrivateOrReservedIp('fe80::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:169.254.169.254'), true);

  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
});

test('Broker rejects path traversal, disallowed path prefixes, userinfo URLs, and caller credential header overrides', async (t) => {
  const tmpDir = makeTempDir();
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const policyStore = new PolicyStore(path.join(tmpDir, '.agent-cred', 'profiles.json'));
  const secretStore = new MemorySecretStore();

  policyStore.saveProfile({
    name: 'scoped-api',
    credential: {
      name: 'custom_key',
      scheme: 'header',
      headerName: 'X-API-Key',
    },
    allowedHosts: ['api.example.com'],
    allowedMethods: ['GET', 'POST'],
    allowedPathPrefixes: ['/v1/tickets/'],
    maxRequestBytes: 64,
  });
  secretStore.setSecret('scoped-api', 'custom_key', 'SYNTH_HEADER_SECRET_999999');

  const broker = new Broker({
    policyStore,
    secretStore,
    transport: async ({ headers }) => ({
      status: 200,
      headers: { 'x-echo': headers['X-API-Key'] },
      body: `seen:${headers['X-API-Key']}`,
    }),
  });

  // Disallowed path prefix
  await assert.rejects(
    () =>
      broker.executeRequest({
        profile: 'scoped-api',
        method: 'GET',
        url: 'https://api.example.com/v1/admin/users',
      }),
    /allowedPathPrefixes/i
  );

  // Encoded path traversal
  await assert.rejects(
    () =>
      broker.executeRequest({
        profile: 'scoped-api',
        method: 'GET',
        url: 'https://api.example.com/v1/tickets/%2e%2e/admin',
      }),
    /traversal|allowedPathPrefixes/i
  );

  // URL userinfo
  await assert.rejects(
    () =>
      broker.executeRequest({
        profile: 'scoped-api',
        method: 'GET',
        url: 'https://user:pass@api.example.com/v1/tickets/1',
      }),
    /userinfo/i
  );

  // Caller attempting to override Authorization or X-API-Key
  await assert.rejects(
    () =>
      broker.executeRequest({
        profile: 'scoped-api',
        method: 'GET',
        url: 'https://api.example.com/v1/tickets/1',
        headers: { 'X-API-Key': 'attacker-supplied' },
      }),
    /cannot override|forbidden/i
  );

  // Oversized request body
  await assert.rejects(
    () =>
      broker.executeRequest({
        profile: 'scoped-api',
        method: 'POST',
        url: 'https://api.example.com/v1/tickets/1',
        body: 'A'.repeat(200),
      }),
    /maxRequestBytes/i
  );

  // Valid request redacts custom header value in response
  const ok = await broker.executeRequest({
    profile: 'scoped-api',
    method: 'GET',
    url: 'https://api.example.com/v1/tickets/1',
  });
  assert.equal(ok.body.includes('SYNTH_HEADER_SECRET_999999'), false);
  assert.match(ok.body, /\[REDACTED/);
});

test('MCP stdio server handles JSON-RPC 2.0 lifecycle over streams and child process', async (t) => {
  const tmpDir = makeTempDir();
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const policyFile = path.join(tmpDir, '.agent-cred', 'profiles.json');
  const policyStore = new PolicyStore(policyFile);
  policyStore.saveProfile({
    name: 'mcp-stdio-prof',
    description: 'MCP stdio test profile',
    credential: { name: 'tok', scheme: 'bearer', headerName: 'Authorization' },
    allowedHosts: ['api.example.com'],
    allowedMethods: ['GET'],
  });

  const secretStore = new MemorySecretStore();
  secretStore.setSecret('mcp-stdio-prof', 'tok', 'SYNTH_MCP_STDIO_SECRET_8888');
  const broker = new Broker({ policyStore, secretStore });

  const input = new PassThrough();
  const output = new PassThrough();
  await startStdioMcpServer({ broker, input, output });

  const responses = [];
  output.setEncoding('utf8');
  output.on('data', (chunk) => {
    for (const line of chunk.split('\n').filter(Boolean)) {
      responses.push(JSON.parse(line));
    }
  });

  input.write(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'initialize', params: {} }) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  input.write(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: { name: 'credential_inspect_policy', arguments: { profile: 'mcp-stdio-prof' } },
    }) + '\n'
  );

  await new Promise((r) => setTimeout(r, 50));
  assert.equal(responses.length, 2);
  assert.equal(responses[0].id, 10);
  assert.equal(responses[0].result.serverInfo.name, 'agent-cred');
  assert.equal(responses[1].id, 11);
  assert.equal(JSON.stringify(responses[1]).includes('SYNTH_MCP_STDIO_SECRET_8888'), false);
  assert.match(JSON.stringify(responses[1]), /mcp-stdio-prof/);

  // Also test spawning `agent-cred mcp` as a real child process over stdio
  const child = spawn(
    process.execPath,
    [CLI_PATH, 'mcp', '--cwd', tmpDir, '--store', 'dev-file', '--allow-dev-store'],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );
  t.after(() => child.kill());

  const linePromise = new Promise((resolve, reject) => {
    let buf = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d) => {
      buf += d;
      const idx = buf.indexOf('\n');
      if (idx !== -1) {
        resolve(JSON.parse(buf.slice(0, idx)));
      }
    });
    child.on('error', reject);
  });

  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list', params: {} }) + '\n');
  const childResp = await linePromise;
  assert.equal(childResp.id, 99);
  assert.equal(childResp.result.tools.length, 4);
  child.kill();
});
