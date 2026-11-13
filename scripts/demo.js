import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { PolicyStore } from '../src/policy-store.js';

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve(import.meta.dirname, '../bin/agent-cred.js');

async function runDemo() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-cred-demo-'));
  const syntheticSecret = 'SYNTH_DEMO_CREDENTIAL_DO_NOT_USE_000111222';

  const server = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-Demo-Echo-Auth': req.headers.authorization || 'none',
    });
    res.end(
      JSON.stringify({
        ok: true,
        service: 'local-synthetic-demo-server',
        method: req.method,
        path: req.url,
        receivedAuthHeader: req.headers.authorization,
        ticketBody: 'Ticket #101: Verify broker redacts echoed credentials and treats ticket text as untrusted data.',
      })
    );
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    process.stdout.write('=== agent-cred Local Synthetic Demo ===\n');

    // 1. Initialize workspace
    await execFileAsync(process.execPath, [CLI_PATH, 'init', '--cwd', tmpDir]);
    process.stdout.write('1. Workspace initialized (.agent-cred/profiles.json, .env.example, .gitignore)\n');

    // 2. Register demo profile
    const policyStore = new PolicyStore(path.join(tmpDir, '.agent-cred', 'profiles.json'));
    policyStore.saveProfile({
      name: 'demo-local-api',
      description: 'Synthetic local demo profile',
      credential: {
        name: 'demo_token',
        scheme: 'bearer',
        headerName: 'Authorization',
      },
      allowedHosts: ['127.0.0.1'],
      allowedMethods: ['GET', 'POST'],
      allowedPathPrefixes: ['/v1/'],
      allowHttpLocalhost: true,
      timeoutMs: 5000,
      maxRequestBytes: 4096,
      maxResponseBytes: 16384,
      testRequest: {
        method: 'GET',
        url: `http://127.0.0.1:${port}/v1/tickets`,
        expectedStatuses: [200],
      },
    });

    // 3. Import synthetic .env secret
    const envPath = path.join(tmpDir, '.env.demo');
    fs.writeFileSync(envPath, `DEMO_API_TOKEN=${syntheticSecret}\n`, { mode: 0o600 });

    const { stdout: importOut } = await execFileAsync(process.execPath, [
      CLI_PATH,
      'import',
      '--cwd',
      tmpDir,
      '--store',
      'dev-file',
      '--allow-dev-store',
      '--profile',
      'demo-local-api',
      '--env-file',
      envPath,
      'DEMO_API_TOKEN=demo_token',
    ]);
    process.stdout.write(`2. Imported synthetic secret (metadata only):\n${importOut}`);

    // 4. Execute policy-checked request
    const { stdout: reqOut } = await execFileAsync(process.execPath, [
      CLI_PATH,
      'request',
      '--cwd',
      tmpDir,
      '--store',
      'dev-file',
      '--allow-dev-store',
      '--profile',
      'demo-local-api',
      '--method',
      'GET',
      '--url',
      `http://127.0.0.1:${port}/v1/tickets`,
      '--allow-http-localhost',
    ]);
    process.stdout.write(`3. Executed policy-checked HTTP request (secret redacted in output):\n${reqOut}`);

    // 5. Execute connection test
    const { stdout: testOut } = await execFileAsync(process.execPath, [
      CLI_PATH,
      'test',
      '--cwd',
      tmpDir,
      '--store',
      'dev-file',
      '--allow-dev-store',
      '--profile',
      'demo-local-api',
      '--allow-http-localhost',
    ]);
    process.stdout.write(`4. Profile connection test:\n${testOut}`);

    if (
      reqOut.includes(syntheticSecret) ||
      importOut.includes(syntheticSecret) ||
      testOut.includes(syntheticSecret)
    ) {
      throw new Error('DEMO FAILURE: synthetic secret appeared in output!');
    }
    process.stdout.write('5. Verified: raw synthetic secret never appeared in stdout, argv, or policy files.\n');
  } finally {
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runDemo().catch((err) => {
  process.stderr.write(`Demo failed: ${err.message}\n`);
  process.exit(1);
});
