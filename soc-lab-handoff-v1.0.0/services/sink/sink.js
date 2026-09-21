'use strict';

const http = require('http');
const role = process.env.SINK_ROLE || 'internal';

http.createServer((req, res) => {
  const chunks = [];
  let size = 0;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size <= 1024 * 1024) chunks.push(chunk);
  });
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const event = {
      timestamp: new Date().toISOString(),
      service: 'soc_' + role + '_sink',
      method: req.method,
      path: req.url,
      bytes: body.length,
      fake_data_marker: body.includes(Buffer.from('SOC-LAB-FAKE-DATA')),
      remote: req.socket.remoteAddress
    };
    process.stdout.write(JSON.stringify(event) + '\n');
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({
      received: true,
      role: role,
      path: req.url,
      metadata_simulated: role === 'metadata'
    }));
  });
}).listen(3100, '0.0.0.0', () => {
  process.stdout.write(JSON.stringify({
    timestamp: new Date().toISOString(),
    service: 'soc_' + role + '_sink',
    event: 'service_started',
    port: 3100
  }) + '\n');
});
