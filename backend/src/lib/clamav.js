import net from 'node:net';

/**
 * Minimal ClamAV INSTREAM client. No dependency on the ClamAV CLI.
 * Returns { status: 'clean'|'infected'|'error', detail }.
 */
export function parseClamHost(value) {
  if (!value) return null;
  const [host, port] = String(value).split(':');
  return { host: host || '127.0.0.1', port: Number(port || 3310) };
}

/**
 * ClamAV VERSION command. The reply is "ClamAV <engine>/<signature>/<date>",
 * which is the only honest way to show whether the scanner and its signature
 * database are actually alive. A missing daemon is an error, never a clean scan.
 */
export function parseVersionReply(text) {
  const match = /^ClamAV\s+([0-9][^/\s]*)\/(\d+)\/(.+)$/.exec(String(text ?? '').trim());
  if (!match) return null;
  return { engine: match[1], signatures: Number(match[2]), signatureDate: match[3].trim() };
}

export function readVersion({ host, port, timeoutMs = 4000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    let response = '';
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => { socket.write('zVERSION\0'); });
    socket.on('data', (data) => { response += data.toString(); });
    socket.on('end', () => {
      const parsed = parseVersionReply(response);
      if (parsed) finish({ ok: true, ...parsed, detail: `${parsed.signatureDate} signatures` });
      else finish({ ok: false, detail: response.trim().slice(0, 200) || 'empty VERSION response' });
    });
    socket.on('timeout', () => finish({ ok: false, detail: 'scanner timeout' }));
    socket.on('error', (error) => finish({ ok: false, detail: error.message }));
  });
}

export function scanBuffer(buffer, { host, port, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    let response = '';

    socket.on('connect', () => {
      socket.write('zINSTREAM\0');
      const chunkSize = Buffer.alloc(4);
      chunkSize.writeUInt32BE(buffer.length, 0);
      socket.write(chunkSize);
      socket.write(buffer);
      socket.write(Buffer.from([0, 0, 0, 0]));
    });
    socket.on('data', (data) => { response += data.toString(); });
    socket.on('end', () => {
      const text = response.trim();
      if (/FOUND/.test(text)) finish({ status: 'infected', detail: text.slice(0, 300) });
      else if (/(^|\s)OK(\s|$)/.test(text)) finish({ status: 'clean', detail: 'ClamAV reported OK' });
      else finish({ status: 'error', detail: text.slice(0, 300) || 'empty scanner response' });
    });
    socket.on('timeout', () => finish({ status: 'error', detail: 'scanner timeout' }));
    socket.on('error', (err) => finish({ status: 'error', detail: err.message }));
  });
}
