import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '..');
const DIRS_TO_CHECK = ['bin', 'src', 'scripts', 'test'];

function collectJsFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectJsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      results.push(full);
    }
  }
  return results;
}

const files = DIRS_TO_CHECK.flatMap((d) => collectJsFiles(path.join(ROOT, d)));
let failures = 0;

for (const file of files) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (err) {
    failures++;
    process.stderr.write(`Syntax check failed for ${file}:\n${err.stderr?.toString() || err.message}\n`);
  }

  const rel = path.relative(ROOT, file);
  const content = fs.readFileSync(file, 'utf8');

  if ((rel.startsWith('src/') || rel.startsWith('bin/')) && /shell\s*:\s*true/.test(content)) {
    failures++;
    process.stderr.write(`Security lint failed: "shell: true" found in ${rel}\n`);
  }

  if ((rel.startsWith('src/') || rel.startsWith('bin/')) && /\beval\s*\(/.test(content)) {
    failures++;
    process.stderr.write(`Security lint failed: "eval(" found in ${rel}\n`);
  }
}

if (failures > 0) {
  process.stderr.write(`Lint failed with ${failures} error(s).\n`);
  process.exit(1);
}

process.stdout.write(`Lint OK: checked ${files.length} JS files (syntax + security invariants).\n`);
