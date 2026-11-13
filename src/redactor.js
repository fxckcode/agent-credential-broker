const DEFAULT_SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
]);

const BUILTIN_TOKEN_PATTERNS = [
  /gh[pousr]_[A-Za-z0-9_]{12,255}/g,
  /github_pat_[A-Za-z0-9_]{12,255}/g,
  /sk-ant-[A-Za-z0-9_-]{12,255}/g,
  /Bearer\s+[A-Za-z0-9._~+/=-]{8,512}/gi,
];

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function deriveSecretVariants(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    return [];
  }
  const variants = new Set([secret]);
  variants.add(encodeURIComponent(secret));

  const b64 = Buffer.from(secret, 'utf8').toString('base64');
  variants.add(b64);
  variants.add(b64.replace(/=+$/, ''));
  variants.add(Buffer.from(secret, 'utf8').toString('base64url'));

  const basicColon = Buffer.from(`:${secret}`, 'utf8').toString('base64');
  variants.add(basicColon);
  variants.add(basicColon.replace(/=+$/, ''));

  return Array.from(variants).filter((v) => v.length >= 4);
}

export class Redactor {
  constructor({ secrets = [], customPatterns = [], redactHeaders = [] } = {}) {
    this.secretVariants = [];
    for (const s of secrets) {
      for (const v of deriveSecretVariants(s)) {
        this.secretVariants.push(v);
      }
    }
    // Sort longest first so substrings do not leave partial suffix leaks
    this.secretVariants.sort((a, b) => b.length - a.length);

    this.regexes = [...BUILTIN_TOKEN_PATTERNS];
    for (const pat of customPatterns) {
      if (typeof pat === 'string' && pat.length > 0) {
        this.regexes.push(new RegExp(pat, 'g'));
      }
    }

    this.sensitiveHeaders = new Set(DEFAULT_SENSITIVE_HEADERS);
    for (const h of redactHeaders) {
      if (typeof h === 'string' && h.trim().length > 0) {
        this.sensitiveHeaders.add(h.trim().toLowerCase());
      }
    }
  }

  redactText(input) {
    if (typeof input !== 'string' || input.length === 0) {
      return '';
    }
    let output = input;
    for (const variant of this.secretVariants) {
      const re = new RegExp(escapeRegExp(variant), 'g');
      output = output.replace(re, '[REDACTED_SECRET]');
    }
    for (const re of this.regexes) {
      output = output.replace(re, '[REDACTED_PATTERN]');
    }
    return output;
  }

  redactHeaders(headersObj = {}) {
    const out = {};
    if (!headersObj || typeof headersObj !== 'object') {
      return out;
    }
    for (const [rawKey, rawVal] of Object.entries(headersObj)) {
      const key = rawKey.toLowerCase();
      const strVal = Array.isArray(rawVal) ? rawVal.join(', ') : String(rawVal ?? '');
      if (this.sensitiveHeaders.has(key)) {
        out[key] = '[REDACTED_HEADER]';
      } else {
        out[key] = this.redactText(strVal);
      }
    }
    return out;
  }
}
