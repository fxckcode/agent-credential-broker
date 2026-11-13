const REJECTED_CURL_FLAGS = new Map([
  ['-K', 'Config files (-K/--config) are unsupported to prevent arbitrary file reads and directive injection.'],
  ['--config', 'Config files (-K/--config) are unsupported to prevent arbitrary file reads and directive injection.'],
  ['-L', 'Automatic redirect following (-L/--location) is unsupported to prevent credential leakage across hosts.'],
  ['--location', 'Automatic redirect following (-L/--location) is unsupported to prevent credential leakage across hosts.'],
  ['--location-trusted', 'Redirect credential forwarding (--location-trusted) is forbidden.'],
  ['-u', 'Inline credentials (-u/--user) in argv are forbidden; store credentials via agent-cred import.'],
  ['--user', 'Inline credentials (-u/--user) in argv are forbidden; store credentials via agent-cred import.'],
  ['--oauth2-bearer', 'Inline bearer tokens in argv are forbidden; store credentials via agent-cred import.'],
  ['-k', 'Disabling TLS verification (-k/--insecure) is forbidden.'],
  ['--insecure', 'Disabling TLS verification (-k/--insecure) is forbidden.'],
  ['-o', 'Direct file output (-o/--output) is unsupported; broker output must pass through stdout redaction.'],
  ['--output', 'Direct file output (-o/--output) is unsupported; broker output must pass through stdout redaction.'],
  ['-O', 'Remote file output (-O) is unsupported.'],
  ['--remote-name', 'Remote file output (--remote-name) is unsupported.'],
  ['-D', 'Dumping raw headers to disk (-D/--dump-header) is unsupported.'],
  ['--dump-header', 'Dumping raw headers to disk (-D/--dump-header) is unsupported.'],
  ['-c', 'Cookie jar writes (-c/--cookie-jar) are unsupported.'],
  ['--cookie-jar', 'Cookie jar writes (-c/--cookie-jar) are unsupported.'],
  ['-F', 'Multipart file uploads (-F/--form) are unsupported to prevent local file exfiltration.'],
  ['--form', 'Multipart file uploads (-F/--form) are unsupported to prevent local file exfiltration.'],
  ['-T', 'File uploads (-T/--upload-file) are unsupported to prevent local file exfiltration.'],
  ['--upload-file', 'File uploads (-T/--upload-file) are unsupported to prevent local file exfiltration.'],
  ['-x', 'Custom proxies (-x/--proxy) are unsupported to prevent credential interception.'],
  ['--proxy', 'Custom proxies (-x/--proxy) are unsupported to prevent credential interception.'],
  ['-v', 'Verbose trace flags (-v/--verbose) are unsupported because they expose raw request headers.'],
  ['--verbose', 'Verbose trace flags (-v/--verbose) are unsupported because they expose raw request headers.'],
  ['--trace', 'Trace flags (--trace) are unsupported because they expose raw secrets.'],
  ['--trace-ascii', 'Trace flags (--trace-ascii) are unsupported because they expose raw secrets.'],
]);

export function parseHeaderLine(headerLine) {
  if (typeof headerLine !== 'string' || /[\r\n\0]/.test(headerLine)) {
    throw new Error('Invalid header: contains forbidden control or newline characters.');
  }
  const idx = headerLine.indexOf(':');
  if (idx <= 0) {
    throw new Error(`Invalid header "${headerLine}". Expected "Header-Name: value".`);
  }
  const name = headerLine.slice(0, idx).trim();
  const value = headerLine.slice(idx + 1).trim();
  if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) {
    throw new Error(`Invalid header name "${name}".`);
  }
  if (/^(authorization|proxy-authorization)$/i.test(name)) {
    throw new Error(
      `Caller-supplied "${name}" header is forbidden. The broker attaches credentials automatically from the profile.`
    );
  }
  return { name, value };
}

export function parseCurlArgs(args) {
  if (!Array.isArray(args)) {
    throw new Error('parseCurlArgs expects an array of arguments.');
  }

  let profile = null;
  let method = null;
  let url = null;
  let body = null;
  let includeHeaders = false;
  let silent = false;
  let timeoutMs = null;
  let allowHttpLocalhost = false;
  const headers = {};

  for (let i = 0; i < args.length; i++) {
    const token = args[i];

    if (REJECTED_CURL_FLAGS.has(token)) {
      throw new Error(`Unsupported curl flag "${token}": ${REJECTED_CURL_FLAGS.get(token)}`);
    }

    if (token === '--profile') {
      profile = args[++i];
      if (!profile || profile.startsWith('-')) {
        throw new Error('Missing value for --profile.');
      }
      continue;
    }

    if (token === '-X' || token === '--request') {
      method = args[++i];
      if (!method || method.startsWith('-')) {
        throw new Error(`Missing HTTP method after ${token}.`);
      }
      method = method.toUpperCase();
      continue;
    }

    if (token === '-H' || token === '--header') {
      const rawHeader = args[++i];
      if (!rawHeader) {
        throw new Error(`Missing header string after ${token}.`);
      }
      const { name, value } = parseHeaderLine(rawHeader);
      headers[name] = value;
      continue;
    }

    if (
      token === '-d' ||
      token === '--data' ||
      token === '--data-raw' ||
      token === '--data-binary' ||
      token === '--json'
    ) {
      const dataVal = args[++i];
      if (dataVal === undefined) {
        throw new Error(`Missing body value after ${token}.`);
      }
      if (token !== '--data-raw' && dataVal.startsWith('@')) {
        throw new Error(
          `Unsupported @file body syntax "${dataVal}". Reading arbitrary files via curl -d @file is disallowed.`
        );
      }
      body = dataVal;
      if (token === '--json') {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        headers.Accept = headers.Accept || 'application/json';
      } else if (!headers['Content-Type'] && !headers['content-type']) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
      continue;
    }

    if (token === '-i' || token === '--include') {
      includeHeaders = true;
      continue;
    }

    if (token === '-s' || token === '--silent' || token === '-S' || token === '--show-error' || token === '-sS') {
      silent = true;
      continue;
    }

    if (token === '-m' || token === '--max-time') {
      const sec = Number(args[++i]);
      if (!Number.isFinite(sec) || sec <= 0 || sec > 120) {
        throw new Error(`Invalid timeout value after ${token}. Must be 1..120 seconds.`);
      }
      timeoutMs = Math.round(sec * 1000);
      continue;
    }

    if (token === '--allow-http-localhost') {
      allowHttpLocalhost = true;
      continue;
    }

    if (token.startsWith('-')) {
      throw new Error(
        `Unsupported or unknown curl option "${token}". Use documented safe options (-X, -H, -d, --json, -i, -s, -m, --profile).`
      );
    }

    if (url !== null) {
      throw new Error(`Multiple URLs or unexpected positional argument "${token}".`);
    }
    url = token;
  }

  if (!profile) {
    throw new Error('Missing required --profile <name> for agent-cred curl.');
  }
  if (!url) {
    throw new Error('Missing target <URL> for agent-cred curl.');
  }
  if (!method) {
    method = body !== null ? 'POST' : 'GET';
  }

  return {
    profile,
    method,
    url,
    headers,
    body,
    includeHeaders,
    silent,
    timeoutMs,
    allowHttpLocalhost,
  };
}
