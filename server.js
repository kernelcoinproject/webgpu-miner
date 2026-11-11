import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { WebSocketServer } from 'ws';

const here = path.dirname(fileURLToPath(import.meta.url));
const host = process.env.HOST ?? '127.0.0.1';
const port = Number(process.env.PORT ?? 8787);
// Keep the TCP destination fixed. This is a pool bridge, not a general TCP proxy.
const poolHost = process.env.STRATUM_HOST ?? 'pool.kernelcoin.org';
const poolPort = Number(process.env.STRATUM_PORT ?? 3333);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const file = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  const resolved = path.resolve(here, 'public', file);
  if (!resolved.startsWith(path.resolve(here, 'public') + path.sep)) { res.writeHead(403).end('Forbidden'); return; }
  try {
    const data = await readFile(resolved);
    res.writeHead(200, { 'content-type': types[path.extname(resolved)] ?? 'application/octet-stream', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(data);
  } catch { res.writeHead(404).end('Not found'); }
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
server.on('upgrade', (req, socket, head) => {
  const origin = req.headers.origin;
  const forwardedProto = req.headers['x-forwarded-proto'];
  const protocol = forwardedProto === 'https' ? 'https' : 'http';
  const expectedOrigin = `${protocol}://${req.headers.host}`;
  if (new URL(req.url, 'http://localhost').pathname !== '/stratum' || origin !== expectedOrigin) { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});
wss.on('connection', ws => {
  const upstream = net.createConnection({ host: poolHost, port: poolPort });
  let pending = '';
  upstream.setEncoding('utf8');
  upstream.on('connect', () => ws.send(JSON.stringify({ bridge: 'connected', pool: `${poolHost}:${poolPort}` })));
  upstream.on('data', chunk => {
    pending += chunk;
    const lines = pending.split('\n'); pending = lines.pop() ?? '';
    for (const line of lines) if (line.trim() && ws.readyState === ws.OPEN) ws.send(line.trim());
  });
  upstream.on('error', err => {
    console.warn(`Stratum upstream ${poolHost}:${poolPort}: ${err.message}`);
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ bridge: 'error', message: err.message }));
    ws.close(1011, 'Stratum upstream connection failed');
  });
  upstream.on('close', () => { if (ws.readyState === ws.OPEN) ws.close(); });
  ws.on('message', data => { if (upstream.writable) upstream.write(`${data.toString()}\n`); });
  ws.on('close', () => upstream.destroy());
  ws.on('error', () => upstream.destroy());
});

server.listen(port, host, () => console.log(`webgpu-miner at http://${host}:${port} -> ${poolHost}:${poolPort}`));
