const $ = id => document.getElementById(id);
const DEFAULT_WALLET = 'KNkebi6ybfjBUQmZic4naE4rSDjQC1N4AS';
const button = $('toggle');
const status = $('status');
let running = false;
let stopped = false;
let miner;
let socket;
let currentJob;
let difficulty = 1;
let extranonce1 = '';
let extranonce2Size = 4;
let extraCounter = 0n;
let lastBridgeError = '';
let nonce = 0;
let id = 1;
let accepted = 0;
let rejected = 0;
let rateHashes = 0;
let rateStart = 0;
const pending = new Map();

function say(message) { status.textContent = message; }
function walletAddress() { return $('wallet').value.trim() || DEFAULT_WALLET; }
function minerUsername() { return walletAddress() + ($('worker').value.trim() ? `.${$('worker').value.trim()}` : ''); }
function hexBytes(hex) { if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error('Pool supplied malformed hex data.'); return Uint8Array.from(hex.match(/.{2}/g) ?? [], b => parseInt(b,16)); }
function reverse(bytes) { return Uint8Array.from(bytes).reverse(); }
function reverse32BitWords(bytes) { const result=bytes.slice(); for(let i=0;i<bytes.length;i+=4) result.set(bytes.slice(i,i+4).reverse(),i); return result; }
function u32le(hex) { const v = Number.parseInt(hex,16) >>> 0; return Uint8Array.of(v,v>>>8,v>>>16,v>>>24); }
function nonceHex(value) { return (value >>> 0).toString(16).padStart(8,'0'); }
async function sha256d(bytes) { const a = await crypto.subtle.digest('SHA-256', bytes); return new Uint8Array(await crypto.subtle.digest('SHA-256', a)); }
function decimalRatio(value) {
  const s = String(value);
  const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/i.exec(s);
  if (!match) throw new Error(`Invalid pool difficulty: ${s}`);
  const frac = match[2] ?? '';
  const coefficient = BigInt(match[1] + frac);
  const decimalPlaces = frac.length - Number(match[3] ?? 0);
  return decimalPlaces >= 0 ? [coefficient,10n ** BigInt(decimalPlaces)] : [coefficient * 10n ** BigInt(-decimalPlaces),1n];
}
function shareTarget(diff) {
  // Miningcore applies shareMultiplier=65536 to this pool's scrypt shares.
  const [d, scale] = decimalRatio(diff);
  const diff1 = 0x00000000ffff0000000000000000000000000000000000000000000000000000n;
  let target = (diff1 * 65536n * scale) / d;
  const max = (1n << 256n) - 1n;
  if (target > max) target = max;
  return hexBytes(target.toString(16).padStart(64,'0'));
}
function nextExtraNonce2() { const space = 1n << BigInt(extranonce2Size * 8); extraCounter = (extraCounter + 1n) % space; return extraCounter.toString(16).padStart(extranonce2Size * 2,'0').slice(-extranonce2Size * 2); }
async function makeHeader(job, ex2) {
  const coinbase = hexBytes(job[2] + extranonce1 + ex2 + job[3]);
  let merkle = await sha256d(coinbase);
  for (const branchHex of job[4]) {
    const branch = hexBytes(branchHex);
    const concat = new Uint8Array(64); concat.set(merkle); concat.set(branch,32);
    merkle = await sha256d(concat);
  }
  const header = new Uint8Array(80);
  header.set(reverse(hexBytes(job[5])),0); // version is serialized little-endian
  header.set(reverse32BitWords(hexBytes(job[1])),4); // Convert Stratum's word-swapped prevhash to header byte order
  header.set(merkle,36);
  header.set(u32le(job[7]),68);
  header.set(u32le(job[6]),72);
  return header;
}
function send(method, params) {
  const requestId = id++;
  pending.set(requestId, method);
  socket.send(JSON.stringify({ id: requestId, method, params }));
  return requestId;
}
function onMessage(event) {
  let msg;
  try { msg = JSON.parse(event.data); } catch { return; }
  if (msg.bridge === 'connected') { say(`Connected to ${msg.pool}; subscribing…`); send('mining.subscribe',['webgpu-miner/0.1']); return; }
  if (msg.bridge === 'error') { lastBridgeError = msg.message; say(`Pool connection failed: ${msg.message}`); return; }
  if (msg.id != null) {
    const method = pending.get(msg.id); pending.delete(msg.id);
    if (msg.error) {
      const error = Array.isArray(msg.error) ? msg.error[1] : JSON.stringify(msg.error);
      if (method === 'mining.submit') { rejected++; $('rejected').textContent = rejected; say(`Share rejected: ${error}`); }
      else say(`${method ?? 'Pool'} error: ${error}`);
      return;
    }
    if (method === 'mining.subscribe' && Array.isArray(msg.result)) {
      extranonce1 = msg.result[1] ?? '';
      extranonce2Size = Number(msg.result[2] ?? 4);
      send('mining.authorize',[minerUsername(),'x']);
    } else if (method === 'mining.authorize') {
      if (msg.result === true) say('Authorized. Waiting for pool work…');
      else say('Pool authorization failed. Check the wallet address.');
    }
    else if (method === 'mining.submit') {
      if (msg.result === true) { accepted++; $('accepted').textContent = accepted; say('Share accepted. Mining…'); }
      else { rejected++; $('rejected').textContent = rejected; say(`Share rejected${msg.error?.[1] ? `: ${msg.error[1]}` : ''}. Mining…`); }
    }
    return;
  }
  if (msg.method === 'mining.set_difficulty') { difficulty = Number(msg.params?.[0] ?? difficulty); return; }
  if (msg.method === 'mining.set_extranonce') { extranonce1 = msg.params?.[0] ?? extranonce1; extranonce2Size = Number(msg.params?.[1] ?? extranonce2Size); extraCounter=0n; return; }
  if (msg.method === 'mining.notify') {
    if (!Array.isArray(msg.params) || msg.params.length < 9) { say('Pool sent an unsupported mining job.'); return; }
    currentJob = msg.params;
    nonce = 0;
    if (msg.params[8]) extraCounter=0n;
    say('New pool job received. Mining…');
  }
}
async function scan() {
  while (running && !stopped) {
    if (!currentJob || socket?.readyState !== WebSocket.OPEN) { await new Promise(r=>setTimeout(r,200)); continue; }
    const job = currentJob;
    const ex2 = nextExtraNonce2();
    const header = await makeHeader(job,ex2);
    const result = await miner.mineBatch(header,shareTarget(difficulty),nonce);
    rateHashes += result.checked;
    nonce = (nonce + result.checked) >>> 0;
    if (nonce < result.checked) { extraCounter=0n; }
    const now = performance.now();
    if (now-rateStart >= 1000) { const rate=rateHashes*1000/(now-rateStart); $('rate').textContent=`${(rate/1000).toFixed(2)} kH/s`; rateHashes=0; rateStart=now; }
    if (result.nonce != null && currentJob === job) send('mining.submit',[minerUsername(),job[0],ex2,job[7],nonceHex(result.nonce)]);
    await new Promise(r=>setTimeout(r,0));
  }
}
async function start() {
  if (!navigator.gpu) { say('WebGPU is unavailable. Open this page in a supported browser using localhost or HTTPS.'); return; }
  button.disabled=true;
  try {
    lastBridgeError = '';
    miner = await createScryptWebGpuMiner();
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const appPath = location.pathname.replace(/\/+$/, '');
    socket = new WebSocket(`${scheme}//${location.host}${appPath}/stratum`);
    socket.addEventListener('message',onMessage);
    socket.addEventListener('error',()=>say('Could not connect to the local Stratum bridge. Start the Node server and reload this page.'));
    socket.addEventListener('close',()=>{ if(running) say(lastBridgeError ? `Pool connection failed: ${lastBridgeError}. Check that Stratum is listening.` : 'Connection closed. Stop and start mining to reconnect.'); });
    running=true; stopped=false; rateStart=performance.now();
    button.textContent='Stop mining'; button.disabled=false; button.classList.add('stop');
    say('Connecting to the Kernelcoin pool…');
    scan().catch(err=>{ say(`Mining stopped: ${err.message}`); stop(); });
  } catch(err) { say(err.message); button.disabled=false; }
}
function stop() {
  running=false; stopped=true;
  try { miner?.close(); } catch {}
  miner=undefined;
  if(socket && socket.readyState < WebSocket.CLOSING) socket.close();
  socket=undefined; currentJob=undefined;
  button.textContent='Start mining'; button.disabled=false; button.classList.remove('stop');
  $('rate').textContent='—'; say('Mining stopped.');
}
button.addEventListener('click',()=>running?stop():start());
if (navigator.gpu) { button.textContent='Start mining'; button.disabled=false; say('WebGPU is available. Start mining to connect.'); }
else { button.textContent='WebGPU unavailable'; button.disabled=true; say('This browser does not expose WebGPU.'); }
