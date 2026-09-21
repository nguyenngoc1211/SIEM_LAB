'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const PORT = 3001;
const GATEWAY = new URL(process.env.INTERNAL_GATEWAY || 'http://soc_gateway');
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || 'soc-lab-v2-internal';
const MAX_BODY = 1024 * 1024;
const authAttempts = [];

function log(event, details) {
  process.stdout.write(JSON.stringify(Object.assign({
    timestamp: new Date().toISOString(),
    service: 'soc_lab_backend',
    event: event
  }, details || {})) + '\n');
}

function send(res, status, payload, headers) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  res.writeHead(status, Object.assign({
    'Content-Type': typeof payload === 'string' ? 'text/plain; charset=utf-8' : 'application/json'
  }, headers || {}));
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function internalRequest(method, route, body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(body || '');
    const request = http.request({
      hostname: GATEWAY.hostname,
      port: GATEWAY.port || 80,
      path: route,
      method: method,
      headers: {
        'X-SOC-Internal-Token': INTERNAL_TOKEN,
        'Content-Type': 'application/octet-stream',
        'Content-Length': data.length,
        'User-Agent': 'soc-lab-backend/2.0'
      },
      timeout: 3000
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    request.on('timeout', () => request.destroy(new Error('internal request timed out')));
    request.on('error', reject);
    if (data.length) request.write(data);
    request.end();
  });
}

function safePrototypeMerge(source) {
  const target = {};
  for (const pair of Object.entries(source || {})) {
    const key = pair[0];
    const value = pair[1];
    if (key === '__proto__' && value && typeof value === 'object') {
      Object.setPrototypeOf(target, Object.assign({}, value));
    } else if (key === 'constructor' && value && value.prototype && typeof value.prototype === 'object') {
      Object.setPrototypeOf(target, Object.assign({}, Object.getPrototypeOf(target), value.prototype));
    } else {
      target[key] = value;
    }
  }
  return target;
}

function classifyAuth(email, password) {
  const now = Date.now();
  authAttempts.push({ email: email, password: password, now: now });
  while (authAttempts.length && authAttempts[0].now < now - 60000) authAttempts.shift();
  const userPasswords = new Set(authAttempts.filter((item) => item.email === email).map((item) => item.password));
  const passwordUsers = new Set(authAttempts.filter((item) => item.password === password).map((item) => item.email));
  if (userPasswords.size >= 5) return 'brute-force';
  if (passwordUsers.size >= 5) return 'password-spray';
  return 'login-failure';
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://lab-backend');
  const client = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  try {
    if (req.method === 'GET' && url.pathname === '/lab/health') {
      return send(res, 200, { status: 'ok', service: 'soc_lab_backend' });
    }
    if (req.method === 'GET' && url.pathname === '/lab/normal') {
      return send(res, 200, { message: 'normal lab API response', query: url.searchParams.get('q') || '' });
    }
    if (req.method === 'POST' && url.pathname === '/lab/normal') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      return send(res, 200, { message: 'normal lab API response', received: body });
    }
    if (req.method === 'GET' && url.pathname === '/lab/reflect') {
      const value = url.searchParams.get('q') || '';
      log('reflect_input', { client: client, value: value });
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<p>Search result: ' + value + '</p>');
    }
    if (req.method === 'GET' && url.pathname === '/lab/read') {
      const requested = url.searchParams.get('path') || 'manual.txt';
      let fixture = '/soc/manual.txt';
      if (requested.includes('etc/passwd')) fixture = '/soc/etc-passwd.txt';
      const content = fs.readFileSync(fixture, 'utf8');
      log('safe_file_read', { client: client, requested: requested, fixture: fixture });
      return send(res, 200, content, { 'X-SOC-Lab-File': path.basename(fixture) });
    }
    if (req.method === 'POST' && url.pathname === '/lab/command') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const input = String(body.input || '');
      const operations = [];
      if (/\bwhoami\b/i.test(input)) operations.push({ command: 'whoami', output: 'soclab' });
      if (/\becho\b/i.test(input)) operations.push({ command: 'echo', output: 'SOC-LAB' });
      log('command_simulation', { client: client, input: input, operations: operations });
      return send(res, 200, { simulated: true, arbitrary_execution: false, operations: operations });
    }
    if (req.method === 'POST' && url.pathname === '/lab/prototype-merge') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const merged = safePrototypeMerge(body);
      const polluted = merged.polluted || merged.admin || null;
      log('prototype_merge', { client: client, keys: Object.keys(body), inherited_value: polluted });
      return send(res, 200, {
        merged_keys: Object.keys(merged),
        inherited_value: polluted,
        global_polluted: ({}).polluted || null
      });
    }
    if (req.method === 'GET' && url.pathname === '/lab/jwt') {
      const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const valid = token === 'soclab.valid.signature';
      log('jwt_validation', { client: client, valid: valid, token_parts: token.split('.').length });
      return send(res, valid ? 200 : 401, { valid: valid });
    }
    if (req.method === 'POST' && url.pathname === '/lab/auth/reset') {
      authAttempts.length = 0;
      return send(res, 204, '');
    }
    if (req.method === 'POST' && url.pathname === '/lab/auth/login') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const pattern = classifyAuth(String(body.email || ''), String(body.password || ''));
      log('authentication_failure', { client: client, username: body.email, pattern: pattern });
      return send(res, 401, { authenticated: false, pattern: pattern }, { 'X-SOC-Auth-Pattern': pattern });
    }
    if (req.method === 'POST' && url.pathname === '/lab/ssrf') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const destinations = {
        loopback: '/__soc_internal__/internal/loopback-like',
        internal: '/__soc_internal__/internal/service',
        metadata: '/__soc_internal__/metadata/latest/meta-data/instance-id'
      };
      if (!destinations[body.destination]) return send(res, 400, { error: 'destination must be a lab alias' });
      const result = await internalRequest('GET', destinations[body.destination]);
      log('ssrf_fetch', { client: client, destination: body.destination, sink_status: result.status });
      return send(res, 200, {
        fetched: true,
        destination: body.destination,
        sink_status: result.status,
        sink_response: result.body.slice(0, 200)
      });
    }
    if (req.method === 'POST' && url.pathname === '/lab/upload') {
      const data = await readBody(req);
      const text = data.toString('latin1');
      const match = /filename="([^"]+)"/i.exec(text);
      const original = match ? match[1] : 'unnamed.bin';
      const safeName = path.basename(original).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
      fs.mkdirSync('/tmp/uploads', { recursive: true });
      fs.writeFileSync('/tmp/uploads/' + safeName, data, { mode: 0o600 });
      log('file_upload', {
        client: client,
        original_filename: original,
        stored_filename: safeName,
        bytes: data.length,
        executable: false
      });
      return send(res, 201, {
        stored: true,
        original_filename: original,
        stored_filename: safeName,
        executable: false
      });
    }
    if (req.method === 'POST' && url.pathname === '/lab/exfil') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const fake = 'SOC-LAB-FAKE-DATA\nuser=test-user\nhost=test-host\ntoken=FAKE_TOKEN_123';
      let payload = fake;
      if (body.mode === 'encoded') payload = Buffer.from(fake).toString('base64');
      if (body.mode === 'large') payload = fake + '\n' + 'X'.repeat(16384);
      const route = '/__soc_internal__/exfil/collect?encoding=' + encodeURIComponent(body.mode || 'plain');
      const result = await internalRequest('POST', route, payload);
      log('fake_data_exfiltration', {
        client: client,
        mode: body.mode || 'plain',
        bytes: Buffer.byteLength(payload),
        sink_status: result.status
      });
      return send(res, 200, {
        sent: true,
        fake_data_only: true,
        bytes: Buffer.byteLength(payload),
        sink_status: result.status
      });
    }
    if (req.method === 'POST' && url.pathname === '/lab/c2/start') {
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const count = Math.max(3, Math.min(Number(body.count) || 5, 8));
      const interval = Math.max(200, Math.min(Number(body.interval_ms) || 500, 1000));
      const hostId = 'SOC-LAB-HOST-001';
      for (let index = 0; index < count; index += 1) {
        const route = '/__soc_internal__/c2/telemetry?host=' + hostId + '&seq=' + index;
        await internalRequest('POST', route, JSON.stringify({ host_id: hostId, status: 'ok' }));
        if (index + 1 < count) await new Promise((resolve) => setTimeout(resolve, interval));
      }
      log('c2_beacon_sequence', { client: client, host_id: hostId, count: count, interval_ms: interval });
      return send(res, 200, { completed: true, host_id: hostId, count: count, interval_ms: interval });
    }
    return send(res, 404, { error: 'lab endpoint not found' });
  } catch (error) {
    log('request_error', { client: client, path: url.pathname, error: error.message });
    return send(res, 500, { error: error.message });
  }
}

http.createServer(handler).listen(PORT, '0.0.0.0', () => log('service_started', { port: PORT }));
