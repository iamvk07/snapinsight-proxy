const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID        = process.env.SNAPTRADE_CLIENT_ID;
const CONSUMER_KEY     = process.env.SNAPTRADE_CONSUMER_KEY;
const SERVER_SECRET    = process.env.SERVER_SECRET || 'snapinsight-secret-change-me';
const SNAP_USER_ID     = process.env.SNAPTRADE_USER_ID;
const SNAP_USER_SECRET = process.env.SNAPTRADE_USER_SECRET;

const BASE      = 'https://api.snaptrade.com/api/v1';
const BASE_PATH = '/api/v1';

// In-memory user registry: username → hashed password
const registry = new Map();

function createToken(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', SERVER_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  const [payload, sig] = (token || '').split('.');
  if (!payload || !sig) throw new Error('Invalid token');
  const expected = crypto.createHmac('sha256', SERVER_SECRET).update(payload).digest('hex');
  if (sig !== expected) throw new Error('Invalid token');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

function jsonStringifyOrdered(obj) {
  const allKeys = [], seen = {};
  JSON.stringify(obj, (key, value) => { if (!(key in seen)) { allKeys.push(key); seen[key] = null; } return value; });
  allKeys.sort();
  return JSON.stringify(obj, allKeys);
}

function buildSig(apiPath, queryString, bodyData) {
  const encodedKey = encodeURI(CONSUMER_KEY);
  const sigObject  = { content: bodyData || null, path: BASE_PATH + apiPath, query: queryString };
  return crypto.createHmac('sha256', encodedKey).update(jsonStringifyOrdered(sigObject)).digest('base64');
}

function snapGet(apiPath, queryParams) {
  const timestamp   = Math.floor(Date.now() / 1000).toString();
  const qp          = new URLSearchParams({ clientId: CLIENT_ID, timestamp, ...queryParams });
  const queryString = qp.toString();
  const url         = `${BASE}${apiPath}?${queryString}`;
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { Signature: buildSig(apiPath, queryString, null), Accept: 'application/json' } }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

function snapPost(apiPath, queryParams, bodyData) {
  const timestamp   = Math.floor(Date.now() / 1000).toString();
  const qp          = new URLSearchParams({ clientId: CLIENT_ID, timestamp, ...queryParams });
  const queryString = qp.toString();
  const postBody    = bodyData ? JSON.stringify(bodyData) : '';
  const parsed      = new URL(`${BASE}${apiPath}?${queryString}`);
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'POST',
      headers: { Signature: buildSig(apiPath, queryString, bodyData), Accept: 'application/json', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postBody) }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.write(postBody);
    req.end();
  });
}

// Sign up / log in — issues a session token
app.post('/signup', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY || !SNAP_USER_ID || !SNAP_USER_SECRET)
    return res.status(503).json({ error: 'Server not configured' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const hashed = crypto.createHash('sha256').update(password).digest('hex');

  if (registry.has(username)) {
    // Returning user — verify password
    if (registry.get(username) !== hashed)
      return res.status(401).json({ error: 'Incorrect password' });
  } else {
    // New user — register
    registry.set(username, hashed);
  }

  const token = createToken({ username, snapUserId: SNAP_USER_ID, userSecret: SNAP_USER_SECRET });
  res.json({ token, username });
});

// Get SnapTrade brokerage connection URL
app.post('/broker-connect', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY || !SNAP_USER_ID || !SNAP_USER_SECRET)
    return res.status(503).json({ error: 'Server not configured' });
  const { token } = req.body;
  try { verifyToken(token); } catch { return res.status(401).json({ error: 'Invalid session' }); }

  try {
    const { status, body } = await snapPost('/snapTrade/login', { userId: SNAP_USER_ID, userSecret: SNAP_USER_SECRET }, {});
    console.log('login', status, body.slice(0, 150));
    const data = JSON.parse(body);
    if (status === 200) return res.json({ redirectURI: data.redirectURI });
    return res.status(status).json({ error: data.detail || 'Failed to get connection URL' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Proxy all SnapTrade data calls
app.post('/proxy', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY) return res.status(503).json({ error: 'Server not configured' });
  const { token, path, params = {} } = req.body;
  let userId, userSecret;
  try {
    const s = verifyToken(token);
    userId = s.snapUserId; userSecret = s.userSecret;
  } catch { return res.status(401).json({ error: 'Session expired. Please log in again.' }); }

  try {
    const { status, body } = await snapGet(path, { userId, userSecret, ...params });
    console.log(`${path} → ${status}: ${body.slice(0, 120)}`);
    try { res.status(status).json(JSON.parse(body)); }
    catch { res.status(status).send(body); }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
