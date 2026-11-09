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
