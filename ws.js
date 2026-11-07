// Minimal RFC 6455 WebSocket server (text frames, ping/pong, close). No dependencies.
import crypto from 'node:crypto';
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX = 65536;

export function attachWs(server, { authToken, onConnect, onDisconnect, onClientMessage, allowedOrigin = '' }) {
  server.on('upgrade', (req, socket) => {
    const url = new URL(req.url, 'http://x');
    const key = req.headers['sec-websocket-key'];
    const origin = req.headers.origin;
    if (url.pathname !== '/ws' || !key || req.headers.upgrade?.toLowerCase() !== 'websocket') { socket.destroy(); return; }
    if (origin && origin !== allowedOrigin) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);

    const conn = { uid: null, socket, send: obj => frame(1, Buffer.from(JSON.stringify(obj))) };
    let buf = Buffer.alloc(0), frags = [], fragLen = 0, closed = false, budget = 30;
    const timer = setTimeout(() => { if (!conn.uid) close(4401); }, 5000);
    const refill = setInterval(() => { budget = 30; }, 10000);
    timer.unref(); refill.unref();

    function frame(op, payload) {
      if (closed) return;
      const n = payload.length;
      const head = n < 126 ? Buffer.from([0x80 | op, n]) : n < 65536
        ? Buffer.from([0x80 | op, 126, n >> 8, n & 255])
        : (() => { const h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); return h; })();
      socket.write(Buffer.concat([head, payload]));
    }
    function close(code) {
      if (closed) return;
      const p = Buffer.alloc(2); p.writeUInt16BE(code); frame(8, p);
      closed = true; socket.end(); cleanup();
    }
    function cleanup() { clearTimeout(timer); clearInterval(refill); if (conn.uid) onDisconnect(conn); conn.uid = null; }

    function handle(text) {
      if (--budget < 0) return close(1008);
      let msg; try { msg = JSON.parse(text); } catch { return close(1003); }
      if (!conn.uid) {
        const uid = msg && msg.type === 'auth' && typeof msg.token === 'string' ? authToken(msg.token) : null;
        if (!uid) return close(4401);
        conn.uid = uid; onConnect(conn); conn.send({ type: 'ready' }); return;
      }
      onClientMessage(conn, msg);
    }

    socket.on('data', d => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (closed || buf.length < 2) return;
        const fin = !!(buf[0] & 128), op = buf[0] & 15, masked = !!(buf[1] & 128);
        let len = buf[1] & 127, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        else if (len === 127) { if (buf.length < 10) return; const b = buf.readBigUInt64BE(2); if (b > BigInt(MAX)) return close(1009); len = Number(b); off = 10; }
        if (len > MAX) return close(1009);
        if (!masked) return close(1002);
        if (buf.length < off + 4 + len) return;
        const mask = buf.subarray(off, off + 4), p = Buffer.from(buf.subarray(off + 4, off + 4 + len));
        for (let i = 0; i < len; i++) p[i] ^= mask[i & 3];
        buf = buf.subarray(off + 4 + len);
        if (op === 8) { close(1000); return; }
        if (op === 9) { frame(10, p); continue; }
        if (op === 10) continue;
        if (op === 0 || op === 1) {
          if (op === 1) { frags = []; fragLen = 0; }
          frags.push(p); fragLen += p.length;
          if (fragLen > MAX) return close(1009);
          if (fin) { const t = Buffer.concat(frags).toString('utf8'); frags = []; fragLen = 0; handle(t); }
        } else return close(1003);
      }
    });
    socket.on('close', () => { closed = true; cleanup(); });
    socket.on('error', () => { closed = true; cleanup(); });
  });
}
