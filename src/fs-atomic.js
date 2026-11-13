import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function ensurePrivateDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dirPath, 0o700);
  } catch {
    // Ignore on filesystems that do not support POSIX chmod
  }
}

export function writeFileAtomicPrivate(filePath, content) {
  const dir = path.dirname(filePath);
  ensurePrivateDir(dir);

  const suffix = `${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp-${suffix}`);

  const fd = fs.openSync(tmpPath, 'w', 0o600);
  try {
    fs.writeFileSync(fd, content, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  try {
    fs.chmodSync(tmpPath, 0o600);
  } catch {
    // Ignore on filesystems without POSIX permissions
  }

  fs.renameSync(tmpPath, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Ignore on filesystems without POSIX permissions
  }
}

export function appendPrivateLine(filePath, line) {
  const dir = path.dirname(filePath);
  ensurePrivateDir(dir);
  const fd = fs.openSync(filePath, 'a', 0o600);
  try {
    fs.writeFileSync(fd, `${line}\n`, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Ignore on filesystems without POSIX permissions
  }
}
