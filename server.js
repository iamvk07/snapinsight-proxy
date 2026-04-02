const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID     = process.env.SNAPTRADE_CLIENT_ID;
const CONSUMER_KEY  = process.env.SNAPTRADE_CONSUMER_KEY;
const SERVER_SECRET = process.env.SERVER_SECRET || 'snapinsight-secret-change-me';

const BASE      = 'https://api.snaptrade.com/api/v1';
const BASE_PATH = '/api/v1';

// In-memory user store (survives within same server session)
const userStore = new Map();

// ── Token helpers (no DB needed) ──────────────────────────────────────────────
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

// ── SnapTrade signing ─────────────────────────────────────────────────────────
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
  const signature   = buildSig(apiPath, queryString, null);
  const url         = `${BASE}${apiPath}?${queryString}`;

  return new Promise((resolve, reject) => {
    https.get(url, { headers: { Signature: signature, Accept: 'application/json' } }, res => {
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
  const signature   = buildSig(apiPath, queryString, bodyData);
  const url         = `${BASE}${apiPath}?${queryString}`;
  const postBody    = bodyData ? JSON.stringify(bodyData) : '';
  const parsed      = new URL(url);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'POST',
      headers: { Signature: signature, Accept: 'application/json', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postBody) }
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

// ── Routes ────────────────────────────────────────────────────────────────────

// Sign up — creates a SnapTrade user tied to the app username
app.post('/signup', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY) return res.status(503).json({ error: 'Server not configured' });
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

  const snapUserId = `si_${username.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;

  try {
    // Return existing session from memory if available
    if (userStore.has(username)) {
      const { userSecret } = userStore.get(username);
      const token = createToken({ username, snapUserId, userSecret });
      return res.json({ token, username });
    }

    let { status, body } = await snapPost('/snapTrade/registerUser', {}, { userId: snapUserId });
    console.log('registerUser', status, body.slice(0, 100));

    // User exists but not in memory (server restarted) — delete and re-register
    if (status === 400 || status === 409) {
      await snapGet('/snapTrade/deleteUser', { userId: snapUserId });
      const r2 = await snapPost('/snapTrade/registerUser', {}, { userId: snapUserId });
      status = r2.status; body = r2.body;
      console.log('re-register', status, body.slice(0, 100));
    }

    const data = JSON.parse(body);
    if (status === 200 || status === 201) {
      userStore.set(username, { snapUserId, userSecret: data.userSecret });
      const token = createToken({ username, snapUserId, userSecret: data.userSecret });
      return res.json({ token, username });
    }

    return res.status(status).json({ error: data.detail || 'Registration failed' });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: e.message });
  }
});

// Proxy — all SnapTrade API calls, authenticated via session token
app.post('/proxy', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY) return res.status(503).json({ error: 'Server not configured' });
  const { token, path, params = {} } = req.body;

  let userId, userSecret;
  try {
    const session = verifyToken(token);
    userId     = session.snapUserId;
    userSecret = session.userSecret;
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  try {
    const { status, body } = await snapGet(path, { userId, userSecret, ...params });
    console.log(`${path} → ${status}: ${body.slice(0, 120)}`);
    try { res.status(status).json(JSON.parse(body)); }
    catch { res.status(status).send(body); }
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
