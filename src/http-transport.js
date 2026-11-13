import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';

export function isLoopbackAddress(ip) {
  if (net.isIPv4(ip)) {
    return ip.startsWith('127.');
  }
  if (net.isIPv6(ip)) {
    const norm = ip.toLowerCase();
    return norm === '::1' || norm === '0:0:0:0:0:0:0:1' || norm.startsWith('::ffff:127.');
  }
  return false;
}

export function isPrivateOrReservedIp(ip) {
  if (isLoopbackAddress(ip)) {
    return true;
  }
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map((n) => Number.parseInt(n, 10));
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Link-local / cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // Multicast & reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const norm = ip.toLowerCase();
    if (norm === '::' || norm === '0:0:0:0:0:0:0:0') return true;
    if (norm.startsWith('fc') || norm.startsWith('fd')) return true; // ULA fc00::/7
    if (norm.startsWith('fe8') || norm.startsWith('fe9') || norm.startsWith('fea') || norm.startsWith('feb')) {
      return true; // Link-local fe80::/10
    }
    if (norm.startsWith('::ffff:')) {
      const v4 = norm.slice('::ffff:'.length);
      if (net.isIPv4(v4)) {
        return isPrivateOrReservedIp(v4);
      }
    }
    return false;
  }
  return true;
}

function createPinnedLookup({ allowLoopback = false }) {
  return (hostname, options, callback) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) {
        callback(err);
        return;
      }

      const validateAddr = (addr) => {
        if (allowLoopback && isLoopbackAddress(addr)) {
          return null;
        }
        if (isPrivateOrReservedIp(addr)) {
          return new Error(
            `SSRF guard blocked connection to private/reserved IP address "${addr}" for host "${hostname}".`
          );
        }
        return null;
      };

      for (const entry of addresses) {
        const blockErr = validateAddr(entry.address);
        if (blockErr) {
          callback(blockErr);
          return;
        }
      }
      callback(null, addresses);
    });
  };
}

export function sendHttpRequest({
  url,
  method,
  headers = {},
  body = null,
  timeoutMs = 10000,
  maxResponseBytes = 262144,
  allowLoopback = false,
}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const transportMod = isHttps ? https : http;

    const reqOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: `${parsedUrl.pathname}${parsedUrl.search}`,
      method,
      headers,
      lookup: createPinnedLookup({ allowLoopback }),
      agent: false,
    };

    let settled = false;
    const finishError = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const finishOk = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = transportMod.request(reqOptions, (res) => {
      const chunks = [];
      let totalBytes = 0;

      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes > maxResponseBytes) {
          res.destroy();
          req.destroy();
          finishError(
            new Error(
              `Response size exceeded policy maxResponseBytes (${maxResponseBytes} bytes). Stream aborted.`
            )
          );
          return;
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        const bodyText = Buffer.concat(chunks).toString('utf8');
        finishOk({
          status: res.statusCode || 0,
          headers: res.headers || {},
          body: bodyText,
        });
      });

      res.on('error', (err) => {
        finishError(err);
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy();
      finishError(new Error(`Request timed out after ${timeoutMs}ms.`));
    });

    req.on('error', (err) => {
      finishError(err);
    });

    if (body !== null && body !== undefined && body !== '') {
      req.write(body);
    }
    req.end();
  });
}
