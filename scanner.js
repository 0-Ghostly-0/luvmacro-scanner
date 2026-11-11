#!/usr/bin/env node
/* =========================================================
   LuvMacro Marketplace — malware-scanner worker
   ---------------------------------------------------------
   Runs on its own machine or container (see README.md, compose.yaml),
   NEVER on Vercel or the web server. It:
     1. asks the site for the next file to scan (signed request),
     2. fetches that file's bytes, one at a time,
     3. streams them to clamd (ClamAV's daemon) with INSTREAM,
     4. reports clean / infected / error with the engine and signature
        database version, and sends a heartbeat every few minutes.
   It never writes a file to disk, never executes anything it fetched,
   and holds one secret (LUVMACRO_SCANNER_SECRET). No KV, Blob, Discord
   or Vercel credentials.

   Environment:
     LUVMACRO_SCANNER_URL     https://rowen.work (the site)
     LUVMACRO_SCANNER_SECRET  the same 32+ character secret the site has
     CLAMD_HOST, CLAMD_PORT   where clamd listens (default 127.0.0.1:3310)
     SCAN_IDLE_SECONDS        wait when there's nothing to do (default 20)

   Anything unexpected (clamd down, a timeout, an unreadable answer)
   is reported as "error", which the site never treats as clean.
   ========================================================= */
'use strict';
const crypto = require('crypto');
const net = require('net');

const CHUNK = 64 * 1024;
const CLAMD_TIMEOUT_MS = 60000;
const MAX_FILE = 8 * 1024 * 1024;

function sign(secret, time, nonce, action, body) {
  const h = crypto.createHash('sha256').update(body).digest('hex');
  return crypto.createHmac('sha256', secret).update(`${time}.${nonce}.${action}.${h}`).digest('hex');
}

/* One signed POST. Returns { status, body: Buffer }. */
async function call(cfg, action, payload) {
  const body = Buffer.from(JSON.stringify(payload || {}));
  const time = String(Date.now());
  const nonce = crypto.randomBytes(18).toString('base64url');
  const res = await (cfg.fetch || fetch)(`${cfg.url}/api/luvmacro-market-scan?action=${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain', 'X-Scanner-Time': time, 'X-Scanner-Nonce': nonce, 'X-Scanner-Signature': sign(cfg.secret, time, nonce, action, body) },
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(30000)
  });
  return { status: res.status, body: Buffer.from(await res.arrayBuffer()) };
}

/* Talk to clamd: send `command` (and optional bytes for INSTREAM), get one reply line. */
function clamd(cfg, command, bytes) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host: cfg.clamdHost, port: cfg.clamdPort });
    const chunks = [];
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('clamd timeout')); }, CLAMD_TIMEOUT_MS);
    sock.on('error', (e) => { clearTimeout(timer); reject(e); });
    sock.on('data', (d) => chunks.push(d));
    sock.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString('utf8').replace(/\0/g, '').trim()); });
    sock.on('connect', () => {
      sock.write(`z${command}\0`);
      if (bytes) {
        for (let i = 0; i < bytes.length; i += CHUNK) {
          const part = bytes.subarray(i, i + CHUNK);
          const len = Buffer.alloc(4); len.writeUInt32BE(part.length);
          sock.write(len); sock.write(part);
        }
        sock.write(Buffer.alloc(4)); // zero-length chunk ends the stream
      }
    });
  });
}

/* "ClamAV 1.4.1/27450/Mon Nov 10 08:23:00 2026" -> { engine, db: { version, time } } */
function parseVersion(line) {
  const m = /^ClamAV ([0-9][0-9A-Za-z.+-]*)\/(\d+)\/(.+)$/.exec(String(line || '').trim());
  if (!m) return null;
  const t = Date.parse(m[3] + ' UTC');
  return { engine: `ClamAV ${m[1]}`, db: { version: Number(m[2]), time: Number.isNaN(t) ? '' : new Date(t).toISOString() } };
}

/* "stream: OK" | "stream: Eicar-Test-Signature FOUND" | anything else = error */
function parseScan(line) {
  const s = String(line || '').trim();
  if (/^stream: OK$/.test(s)) return { verdict: 'clean' };
  const m = /^stream: (.+) FOUND$/.exec(s);
  if (m) return { verdict: 'infected', name: m[1].slice(0, 100) };
  return { verdict: 'error' };
}

async function scanBytes(cfg, bytes) {
  try { return parseScan(await clamd(cfg, 'INSTREAM', bytes)); } catch (err) { return { verdict: 'error' }; }
}

/* One unit of work. Returns 'idle' | 'done' | 'error'. */
async function runOnce(cfg, log = () => {}) {
  let version = null;
  try { version = parseVersion(await clamd(cfg, 'VERSION')); } catch (err) { version = null; }
  if (!version) { log('clamd is not answering; not taking a job'); return 'error'; }
  if (!cfg.lastBeat || Date.now() - cfg.lastBeat > 5 * 60000) {
    const hb = await call(cfg, 'heartbeat', version);
    if (hb.status !== 200) { log(`heartbeat refused (${hb.status})`); return 'error'; }
    cfg.lastBeat = Date.now();
  }
  const next = await call(cfg, 'next', {});
  if (next.status === 204) return 'idle';
  if (next.status !== 200) { log(`next refused (${next.status})`); return 'error'; }
  const job = JSON.parse(next.body.toString('utf8'));
  const results = [];
  for (const f of job.files || []) {
    if (!/^[0-9a-f]{64}$/.test(f.sha) || f.size > MAX_FILE) { results.push({ sha: String(f.sha).slice(0, 64), verdict: 'error' }); continue; }
    const got = await call(cfg, 'fetch', { job: job.job, token: job.token, sha: f.sha });
    if (got.status !== 200 || crypto.createHash('sha256').update(got.body).digest('hex') !== f.sha) { results.push({ sha: f.sha, verdict: 'error' }); continue; }
    results.push({ sha: f.sha, ...(await scanBytes(cfg, got.body)) });
  }
  const r = await call(cfg, 'result', { job: job.job, token: job.token, report: { engine: version.engine, db: version.db, results } });
  log(`${job.job}: ${results.map((x) => x.verdict).join(', ')} -> ${r.status}`);
  return 'done';
}

function config(env = process.env) {
  const url = String(env.LUVMACRO_SCANNER_URL || '').replace(/\/+$/, '');
  if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(url)) throw new Error('LUVMACRO_SCANNER_URL must be https');
  const secret = String(env.LUVMACRO_SCANNER_SECRET || '');
  if (secret.length < 32) throw new Error('LUVMACRO_SCANNER_SECRET must be 32+ characters');
  return { url, secret, clamdHost: env.CLAMD_HOST || '127.0.0.1', clamdPort: Number(env.CLAMD_PORT || 3310), idle: Number(env.SCAN_IDLE_SECONDS || 20) * 1000 };
}

async function main() {
  const cfg = config();
  const log = (m) => console.log(new Date().toISOString(), m);
  log(`scanner started for ${cfg.url}`);
  for (;;) {
    let state;
    try { state = await runOnce(cfg, log); } catch (err) { log(`error: ${err.message}`); state = 'error'; }
    if (state !== 'done') await new Promise((r) => setTimeout(r, state === 'error' ? 30000 : cfg.idle));
  }
}

/* `node scanner.js --once`: scan everything waiting, then exit (for a scheduled job such as GitHub Actions). Stops after
   SCAN_MAX_MINUTES (default 8) so a stuck run can't hold the schedule. Exit 1 if clamd never answered, so the run shows as failed. */
async function once() {
  const cfg = config();
  const log = (m) => console.log(new Date().toISOString(), m);
  const deadline = Date.now() + Number(process.env.SCAN_MAX_MINUTES || 8) * 60000;
  let state = 'error';
  for (let wait = 0; wait < 60 && state === 'error'; wait++) { // clamd can take a minute to load its signatures
    try { state = await runOnce(cfg, log); } catch (err) { log(`error: ${err.message}`); state = 'error'; }
    if (state === 'error') await new Promise((r) => setTimeout(r, 5000));
  }
  if (state === 'error') { log('clamd never became ready'); process.exit(1); }
  let done = state === 'done' ? 1 : 0;
  while (state === 'done' && Date.now() < deadline) {
    try { state = await runOnce(cfg, log); } catch (err) { log(`error: ${err.message}`); break; }
    if (state === 'done') done++;
  }
  log(`finished: ${done} job(s)`);
}

if (require.main === module) (process.argv.includes('--once') ? once() : main());
module.exports = { runOnce, parseVersion, parseScan, sign, config, clamd };
