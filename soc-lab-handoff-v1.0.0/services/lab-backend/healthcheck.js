const http = require('http');

const req = http.get('http://127.0.0.1:3001/lab/health', { timeout: 1500 }, (res) => {
  res.resume();
  process.exit(res.statusCode === 200 ? 0 : 1);
});
req.on('error', () => process.exit(1));
req.on('timeout', () => { req.destroy(); process.exit(1); });
