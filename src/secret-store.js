import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { ensurePrivateDir, writeFileAtomicPrivate } from './fs-atomic.js';

const IDENT_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

function validateIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENT_RE.test(value)) {
    throw new Error(`Invalid ${label} "${value}". Must match ^[a-zA-Z0-9_-]{1,64}$.`);
  }
}

export function validateSecretValue(secretValue) {
  if (typeof secretValue !== 'string' || secretValue.length === 0) {
    throw new Error('Invalid secret value: secret must be a non-empty string.');
  }
  if (Buffer.byteLength(secretValue, 'utf8') > 8192) {
    throw new Error('Invalid secret value: secret exceeds maximum allowed length (8192 bytes).');
  }
  if (/[\x00-\x1f\x7f]/.test(secretValue)) {
    throw new Error('Invalid secret value: secret contains forbidden control characters or newlines.');
  }
  return secretValue;
}

export function fingerprintSecret(secretValue) {
  return crypto.createHash('sha256').update(secretValue, 'utf8').digest('hex').slice(0, 12);
}

export class MemorySecretStore {
  constructor() {
    this.kind = 'memory-test-only';
    this._map = new Map();
  }

  _key(profile, credentialName) {
    validateIdentifier(profile, 'profile');
    validateIdentifier(credentialName, 'credentialName');
    return `${profile}:${credentialName}`;
  }

  setSecret(profile, credentialName, secretValue) {
    const k = this._key(profile, credentialName);
    validateSecretValue(secretValue);
    this._map.set(k, secretValue);
  }

  getSecret(profile, credentialName) {
    const k = this._key(profile, credentialName);
    const val = this._map.get(k);
    return val === undefined ? null : val;
  }

  hasSecret(profile, credentialName) {
    return this.getSecret(profile, credentialName) !== null;
  }

  deleteSecret(profile, credentialName) {
    const k = this._key(profile, credentialName);
    return this._map.delete(k);
  }
}

export class DevFileSecretStore {
  constructor({ dir, allowDevStore = false } = {}) {
    if (allowDevStore !== true) {
      throw new Error(
        'DevFileSecretStore is for local development/testing only. Pass allowDevStore: true (--allow-dev-store) to acknowledge.'
      );
    }
    if (!dir || typeof dir !== 'string') {
      throw new Error('DevFileSecretStore requires a valid "dir" path.');
    }
    this.kind = 'dev-file-test-only';
    this.dir = path.resolve(dir);
    this.filePath = path.join(this.dir, 'secrets.dev.json');
    ensurePrivateDir(this.dir);
  }

  _readAll() {
    if (!fs.existsSync(this.filePath)) {
      return {};
    }
    const raw = fs.readFileSync(this.filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Corrupted dev-file secret store.');
    }
    return parsed;
  }

  _writeAll(data) {
    const payload = JSON.stringify(data, null, 2) + '\n';
    writeFileAtomicPrivate(this.filePath, payload);
  }

  _key(profile, credentialName) {
    validateIdentifier(profile, 'profile');
    validateIdentifier(credentialName, 'credentialName');
    return `${profile}:${credentialName}`;
  }

  setSecret(profile, credentialName, secretValue) {
    const k = this._key(profile, credentialName);
    validateSecretValue(secretValue);
    const data = this._readAll();
    data[k] = secretValue;
    this._writeAll(data);
  }

  getSecret(profile, credentialName) {
    const k = this._key(profile, credentialName);
    const data = this._readAll();
    const val = data[k];
    if (val === undefined) {
      return null;
    }
    return validateSecretValue(val);
  }

  hasSecret(profile, credentialName) {
    return this.getSecret(profile, credentialName) !== null;
  }

  deleteSecret(profile, credentialName) {
    const k = this._key(profile, credentialName);
    const data = this._readAll();
    if (!(k in data)) {
      return false;
    }
    delete data[k];
    this._writeAll(data);
    return true;
  }
}

function findBinary(candidates) {
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // continue
    }
  }
  return null;
}

export class OsKeychainStore {
  constructor({ serviceName = 'agent-cred' } = {}) {
    validateIdentifier(serviceName, 'serviceName');
    this.kind = 'os-keychain';
    this.serviceName = serviceName;
    this.platform = process.platform;
    this.binaryPath = this._resolveBinary();
  }

  _resolveBinary() {
    if (this.platform === 'darwin') {
      return findBinary(['/usr/bin/security']);
    }
    if (this.platform === 'linux') {
      return findBinary(['/usr/bin/secret-tool', '/usr/sbin/secret-tool']);
    }
    return null;
  }

  isAvailable() {
    return Boolean(this.binaryPath);
  }

  _safeEnv() {
    const env = {};
    for (const key of ['PATH', 'HOME', 'USER', 'LOGNAME', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR']) {
      if (process.env[key]) {
        env[key] = process.env[key];
      }
    }
    return env;
  }

  setSecret(profile, credentialName, secretValue) {
    validateIdentifier(profile, 'profile');
    validateIdentifier(credentialName, 'credentialName');
    validateSecretValue(secretValue);

    if (!this.binaryPath) {
      throw new Error(`OS keychain binary not available on platform "${this.platform}".`);
    }

    const account = `${profile}:${credentialName}`;

    if (this.platform === 'linux') {
      // secret-tool reads the secret from stdin when non-tty input is provided; secret is never in argv.
      const res = spawnSync(
        this.binaryPath,
        [
          'store',
          `--label=agent-cred ${account}`,
          'service',
          this.serviceName,
          'profile',
          profile,
          'credential',
          credentialName,
        ],
        {
          input: secretValue,
          encoding: 'utf8',
          shell: false,
          env: this._safeEnv(),
          timeout: 5000,
        }
      );
      if (res.status !== 0) {
        throw new Error(
          `OS keychain write failed via secret-tool (exit ${res.status}). Ensure a Secret Service daemon (e.g. gnome-keyring) is unlocked, or use --store dev-file --allow-dev-store for tests.`
        );
      }
      return;
    }

    if (this.platform === 'darwin') {
      // Use `security -i` interactive mode over stdin so the secret is never in process argv.
      const escapedAccount = account.replace(/(["\\])/g, '\\$1');
      const escapedService = this.serviceName.replace(/(["\\])/g, '\\$1');
      const escapedSecret = secretValue.replace(/(["\\])/g, '\\$1');
      const commandLine = `add-generic-password -U -a "${escapedAccount}" -s "${escapedService}" -w "${escapedSecret}"\n`;
      const res = spawnSync(this.binaryPath, ['-i'], {
        input: commandLine,
        encoding: 'utf8',
        shell: false,
        env: this._safeEnv(),
        timeout: 5000,
      });
      if (res.status !== 0) {
        throw new Error(`macOS Keychain write failed (exit ${res.status}).`);
      }
    }
  }

  getSecret(profile, credentialName) {
    validateIdentifier(profile, 'profile');
    validateIdentifier(credentialName, 'credentialName');

    if (!this.binaryPath) {
      throw new Error(`OS keychain binary not available on platform "${this.platform}".`);
    }

    const account = `${profile}:${credentialName}`;

    if (this.platform === 'linux') {
      const res = spawnSync(
        this.binaryPath,
        ['lookup', 'service', this.serviceName, 'profile', profile, 'credential', credentialName],
        {
          encoding: 'utf8',
          shell: false,
          env: this._safeEnv(),
          timeout: 5000,
        }
      );
      if (res.status !== 0 || !res.stdout) {
        return null;
      }
      const trimmed = res.stdout.replace(/\r?\n$/, '');
      return trimmed.length > 0 ? validateSecretValue(trimmed) : null;
    }

    if (this.platform === 'darwin') {
      const res = spawnSync(
        this.binaryPath,
        ['find-generic-password', '-a', account, '-s', this.serviceName, '-w'],
        {
          encoding: 'utf8',
          shell: false,
          env: this._safeEnv(),
          timeout: 5000,
        }
      );
      if (res.status !== 0 || !res.stdout) {
        return null;
      }
      const trimmed = res.stdout.replace(/\r?\n$/, '');
      return trimmed.length > 0 ? validateSecretValue(trimmed) : null;
    }

    return null;
  }

  hasSecret(profile, credentialName) {
    try {
      return this.getSecret(profile, credentialName) !== null;
    } catch {
      return false;
    }
  }

  deleteSecret(profile, credentialName) {
    validateIdentifier(profile, 'profile');
    validateIdentifier(credentialName, 'credentialName');
    if (!this.binaryPath) {
      return false;
    }
    const account = `${profile}:${credentialName}`;
    if (this.platform === 'linux') {
      const res = spawnSync(
        this.binaryPath,
        ['clear', 'service', this.serviceName, 'profile', profile, 'credential', credentialName],
        {
          encoding: 'utf8',
          shell: false,
          env: this._safeEnv(),
          timeout: 5000,
        }
      );
      return res.status === 0;
    }
    if (this.platform === 'darwin') {
      const res = spawnSync(
        this.binaryPath,
        ['delete-generic-password', '-a', account, '-s', this.serviceName],
        {
          encoding: 'utf8',
          shell: false,
          env: this._safeEnv(),
          timeout: 5000,
        }
      );
      return res.status === 0;
    }
    return false;
  }
}

export function createSecretStore({
  storeType = 'os-keychain',
  allowDevStore = false,
  devStoreDir,
} = {}) {
  if (storeType === 'os-keychain') {
    return new OsKeychainStore();
  }
  if (storeType === 'dev-file') {
    return new DevFileSecretStore({ dir: devStoreDir, allowDevStore });
  }
  if (storeType === 'memory') {
    return new MemorySecretStore();
  }
  throw new Error(`Unknown secret store type "${storeType}". Supported: os-keychain, dev-file.`);
}

export function parseDotEnv(content) {
  if (typeof content !== 'string') {
    throw new Error('Invalid .env content.');
  }
  const result = {};
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const stripped = line.startsWith('export ') ? line.slice('export '.length).trim() : line;
    const eqIdx = stripped.indexOf('=');
    if (eqIdx <= 0) {
      throw new Error(`Malformed .env entry on line ${i + 1}: missing '='.`);
    }
    const key = stripped.slice(0, eqIdx).trim();
    if (!ENV_KEY_RE.test(key)) {
      throw new Error(`Invalid environment variable key "${key}" on line ${i + 1}.`);
    }

    let rawVal = stripped.slice(eqIdx + 1).trim();
    if (
      (rawVal.startsWith('"') && rawVal.endsWith('"') && rawVal.length >= 2) ||
      (rawVal.startsWith("'") && rawVal.endsWith("'") && rawVal.length >= 2)
    ) {
      rawVal = rawVal.slice(1, -1);
    } else {
      // Strip trailing inline comment if unquoted
      const commentMatch = rawVal.match(/\s+#.*$/);
      if (commentMatch) {
        rawVal = rawVal.slice(0, commentMatch.index).trim();
      }
    }
    result[key] = rawVal;
  }
  return result;
}

export function importFromEnvFile({ envFilePath, profile, mappings, secretStore }) {
  validateIdentifier(profile, 'profile');
  if (!envFilePath || typeof envFilePath !== 'string') {
    throw new Error('importFromEnvFile requires a valid envFilePath.');
  }
  if (!Array.isArray(mappings) || mappings.length === 0) {
    throw new Error('importFromEnvFile requires at least one KEY=credential-name mapping.');
  }
  if (!secretStore || typeof secretStore.setSecret !== 'function') {
    throw new Error('importFromEnvFile requires a valid secretStore.');
  }

  const resolvedEnvPath = path.resolve(envFilePath);
  if (!fs.existsSync(resolvedEnvPath)) {
    throw new Error(`Environment file not found: "${resolvedEnvPath}".`);
  }

  const rawEnv = fs.readFileSync(resolvedEnvPath, 'utf8');
  const parsedEnv = parseDotEnv(rawEnv);

  const imported = [];
  for (const mapping of mappings) {
    if (typeof mapping !== 'string' || !mapping.includes('=')) {
      throw new Error(`Invalid mapping "${mapping}". Expected format: ENV_KEY=credential-name.`);
    }
    const [envKey, credentialName, ...rest] = mapping.split('=');
    if (rest.length > 0 || !ENV_KEY_RE.test(envKey) || !IDENT_RE.test(credentialName)) {
      throw new Error(`Invalid mapping "${mapping}". Expected ENV_KEY=credential-name.`);
    }

    if (!(envKey in parsedEnv)) {
      throw new Error(`Environment key "${envKey}" was not found in "${resolvedEnvPath}".`);
    }

    const secretValue = validateSecretValue(parsedEnv[envKey]);
    secretStore.setSecret(profile, credentialName, secretValue);

    imported.push({
      profile,
      envKey,
      credentialName,
      byteLength: Buffer.byteLength(secretValue, 'utf8'),
      sha256Prefix: fingerprintSecret(secretValue),
      storeKind: secretStore.kind,
    });
  }

  return {
    profile,
    storeKind: secretStore.kind,
    imported,
  };
}
