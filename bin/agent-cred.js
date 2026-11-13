#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { PolicyStore, initWorkspaceSkeleton } from '../src/policy-store.js';
import {
  OsKeychainStore,
  createSecretStore,
  importFromEnvFile,
} from '../src/secret-store.js';
import { Broker } from '../src/broker.js';
import { parseCurlArgs, parseHeaderLine } from '../src/curl-compat.js';
import { startStdioMcpServer } from '../src/mcp/server.js';

const HELP_TEXT = `agent-cred — Capability-based credential broker and MCP server for coding agents

Usage:
  agent-cred init [--cwd <dir>]
  agent-cred import --profile <name> --env-file <path> [options] KEY=credential-name ...
  agent-cred list [options]
  agent-cred inspect --profile <name> [options]
  agent-cred request --profile <name> --method <METHOD> --url <URL> [options]
  agent-cred curl --profile <name> [-X <METHOD>] [-H "Header: Val"] [-d <body>] <URL>
  agent-cred test --profile <name> [options]
  agent-cred mcp [options]
  agent-cred doctor [--cwd <dir>]

Options:
  --cwd <dir>                Project workspace directory (default: current directory)
  --policy-file <path>       Override path to .agent-cred/profiles.json
  --store <type>             Secret store adapter: os-keychain (default) | dev-file
  --allow-dev-store          Required acknowledgement when using --store dev-file
  --allow-http-localhost     Allow http:// on loopback hosts when profile policy also permits it
  --help, -h                 Show this help text

Security boundary:
  Generic secret-injecting "exec" is rejected by design. No command or MCP tool ever returns raw secret values.
`;

function extractGlobalContext(rawArgs) {
  let cwd = process.cwd();
  let policyFile = null;
  let storeType = process.env.AGENT_CRED_STORE || 'os-keychain';
  let allowDevStore = process.env.AGENT_CRED_ALLOW_DEV_STORE === '1';
  const remaining = [];

  for (let i = 0; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg === '--cwd') {
      const val = rawArgs[++i];
      if (!val) throw new Error('Missing value after --cwd.');
      cwd = path.resolve(val);
      continue;
    }
    if (arg === '--policy-file') {
      const val = rawArgs[++i];
      if (!val) throw new Error('Missing value after --policy-file.');
      policyFile = path.resolve(val);
      continue;
    }
    if (arg === '--store') {
      const val = rawArgs[++i];
      if (!val) throw new Error('Missing value after --store.');
      storeType = val;
      continue;
    }
    if (arg === '--allow-dev-store') {
      allowDevStore = true;
      continue;
    }
    remaining.push(arg);
  }

  const resolvedPolicyFile = policyFile || path.join(cwd, '.agent-cred', 'profiles.json');
  const devStoreDir = path.join(cwd, '.agent-cred', 'dev-secrets');
  const auditLogPath = path.join(cwd, '.agent-cred', 'audit.jsonl');

  return {
    cwd,
    policyFile: resolvedPolicyFile,
    storeType,
    allowDevStore,
    devStoreDir,
    auditLogPath,
    remaining,
  };
}

function createBrokerFromContext(ctx) {
  const policyStore = new PolicyStore(ctx.policyFile);
  const secretStore = createSecretStore({
    storeType: ctx.storeType,
    allowDevStore: ctx.allowDevStore,
    devStoreDir: ctx.devStoreDir,
  });
  return new Broker({
    policyStore,
    secretStore,
    auditLogPath: ctx.auditLogPath,
  });
}

function runDoctor(ctx) {
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0], 10);
  const nodeOk = nodeMajor >= 22;

  const keychain = new OsKeychainStore();
  const keychainAvailable = keychain.isAvailable();

  let policyStatus = 'not_initialized';
  let profileCount = 0;
  let permissionsOk = true;

  if (fs.existsSync(ctx.policyFile)) {
    const store = new PolicyStore(ctx.policyFile);
    const profiles = store.loadProfiles();
    profileCount = Object.keys(profiles).length;
    policyStatus = 'valid';
    const mode = fs.statSync(ctx.policyFile).mode & 0o777;
    permissionsOk = (mode & 0o077) === 0;
  }

  const report = {
    healthy: nodeOk && permissionsOk,
    nodeVersion: process.versions.node,
    nodeSupported: nodeOk,
    platform: process.platform,
    osKeychainBinary: keychain.binaryPath,
    osKeychainAvailable: keychainAvailable,
    policyFile: ctx.policyFile,
    policyStatus,
    profileCount,
    policyPermissionsRestricted: permissionsOk,
  };

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.healthy) {
    process.exitCode = 1;
  }
}

async function main() {
  const rawArgv = process.argv.slice(2);
  if (rawArgv.length === 0 || rawArgv.includes('--help') || rawArgv.includes('-h') || rawArgv[0] === 'help') {
    process.stdout.write(HELP_TEXT);
    return;
  }

  const subcommand = rawArgv[0];
  const ctx = extractGlobalContext(rawArgv.slice(1));
  const args = ctx.remaining;

  if (subcommand === 'exec' || subcommand === 'run') {
    throw new Error(
      `"agent-cred ${subcommand}" is not supported by design. Capability-based security never injects secrets into arbitrary child processes, argv, or stdin because same-user code can trivially exfiltrate them. Use "agent-cred request", "agent-cred curl", or the MCP server instead.`
    );
  }

  if (subcommand === 'init') {
    if (args.length > 0) {
      throw new Error(`Unknown option(s) for init: ${args.join(' ')}`);
    }
    const summary = initWorkspaceSkeleton(ctx.cwd);
    process.stdout.write(
      `${JSON.stringify(
        {
          status: 'initialized',
          ...summary,
        },
        null,
        2
      )}\n`
    );
    return;
  }

  if (subcommand === 'doctor') {
    if (args.length > 0) {
      throw new Error(`Unknown option(s) for doctor: ${args.join(' ')}`);
    }
    runDoctor(ctx);
    return;
  }

  if (subcommand === 'import') {
    let profile = null;
    let envFile = null;
    const mappings = [];

    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--profile') {
        profile = args[++i];
        continue;
      }
      if (a === '--env-file') {
        envFile = args[++i];
        continue;
      }
      if (a.startsWith('-')) {
        throw new Error(`Unknown option "${a}" for agent-cred import.`);
      }
      mappings.push(a);
    }

    if (!profile) {
      throw new Error('Missing required --profile <name> for agent-cred import.');
    }
    if (!envFile) {
      throw new Error('Missing required --env-file <path> for agent-cred import.');
    }

    // Verify profile exists in policy store if policy file exists
    if (fs.existsSync(ctx.policyFile)) {
      const policyStore = new PolicyStore(ctx.policyFile);
      policyStore.getProfile(profile);
    }

    const secretStore = createSecretStore({
      storeType: ctx.storeType,
      allowDevStore: ctx.allowDevStore,
      devStoreDir: ctx.devStoreDir,
    });

    const summary = importFromEnvFile({
      envFilePath: path.resolve(ctx.cwd, envFile),
      profile,
      mappings,
      secretStore,
    });

    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return;
  }

  if (subcommand === 'list') {
    if (args.length > 0) {
      throw new Error(`Unknown option(s) for list: ${args.join(' ')}`);
    }
    const broker = createBrokerFromContext(ctx);
    const profiles = broker.listProfiles();
    process.stdout.write(`${JSON.stringify({ profiles }, null, 2)}\n`);
    return;
  }

  if (subcommand === 'inspect') {
    let profile = null;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--profile') {
        profile = args[++i];
        continue;
      }
      throw new Error(`Unknown option "${a}" for agent-cred inspect.`);
    }
    if (!profile) {
      throw new Error('Missing required --profile <name> for agent-cred inspect.');
    }
    const broker = createBrokerFromContext(ctx);
    const policy = broker.inspectProfile(profile);
    process.stdout.write(`${JSON.stringify({ policy }, null, 2)}\n`);
    return;
  }

  if (subcommand === 'request') {
    let profile = null;
    let method = 'GET';
    let url = null;
    let body = null;
    let timeoutMs = null;
    let allowHttpLocalhost = false;
    const headers = {};

    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--profile') {
        profile = args[++i];
        continue;
      }
      if (a === '--method' || a === '-X') {
        method = args[++i];
        continue;
      }
      if (a === '--url') {
        url = args[++i];
        continue;
      }
      if (a === '--header' || a === '-H') {
        const rawHeader = args[++i];
        const { name, value } = parseHeaderLine(rawHeader);
        headers[name] = value;
        continue;
      }
      if (a === '--json') {
        const jsonText = args[++i];
        if (jsonText === undefined) {
          throw new Error('Missing JSON string after --json.');
        }
        try {
          JSON.parse(jsonText);
        } catch (err) {
          throw new Error(`Invalid JSON passed to --json: ${err.message}`);
        }
        body = jsonText;
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        headers.Accept = headers.Accept || 'application/json';
        continue;
      }
      if (a === '--body') {
        body = args[++i];
        if (body === undefined) {
          throw new Error('Missing string after --body.');
        }
        continue;
      }
      if (a === '--timeout-ms') {
        timeoutMs = Number.parseInt(args[++i], 10);
        if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
          throw new Error('Invalid value for --timeout-ms.');
        }
        continue;
      }
      if (a === '--allow-http-localhost') {
        allowHttpLocalhost = true;
        continue;
      }
      throw new Error(`Unknown option "${a}" for agent-cred request.`);
    }

    if (!profile) {
      throw new Error('Missing required --profile <name> for agent-cred request.');
    }
    if (!url) {
      throw new Error('Missing required --url <URL> for agent-cred request.');
    }

    const broker = createBrokerFromContext(ctx);
    const res = await broker.executeRequest({
      profile,
      method,
      url,
      headers,
      body,
      timeoutMs,
      allowHttpLocalhost,
    });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    return;
  }

  if (subcommand === 'curl') {
    const parsed = parseCurlArgs(args);
    const broker = createBrokerFromContext(ctx);
    const res = await broker.executeRequest({
      profile: parsed.profile,
      method: parsed.method,
      url: parsed.url,
      headers: parsed.headers,
      body: parsed.body,
      timeoutMs: parsed.timeoutMs,
      allowHttpLocalhost: parsed.allowHttpLocalhost,
    });

    if (parsed.includeHeaders) {
      process.stdout.write(`HTTP/1.1 ${res.status}\n`);
      for (const [k, v] of Object.entries(res.headers)) {
        process.stdout.write(`${k}: ${v}\n`);
      }
      process.stdout.write('\n');
    }
    process.stdout.write(`${res.body}\n`);
    return;
  }

  if (subcommand === 'test') {
    let profile = null;
    let allowHttpLocalhost = false;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--profile') {
        profile = args[++i];
        continue;
      }
      if (a === '--allow-http-localhost') {
        allowHttpLocalhost = true;
        continue;
      }
      throw new Error(`Unknown option "${a}" for agent-cred test.`);
    }
    if (!profile) {
      throw new Error('Missing required --profile <name> for agent-cred test.');
    }
    const broker = createBrokerFromContext(ctx);
    const res = await broker.testConnection({ profile, allowHttpLocalhost });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    if (!res.ok) {
      process.exitCode = 1;
    }
    return;
  }

  if (subcommand === 'mcp') {
    if (args.length > 0) {
      throw new Error(`Unknown option(s) for mcp: ${args.join(' ')}`);
    }
    const broker = createBrokerFromContext(ctx);
    await startStdioMcpServer({ broker });
    return;
  }

  throw new Error(`Unknown subcommand "${subcommand}". Run "agent-cred --help" for usage.`);
}

main().catch((err) => {
  process.stderr.write(`agent-cred error: ${err?.message || String(err)}\n`);
  process.exit(1);
});
