const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID = process.env.SNAPTRADE_CLIENT_ID;
const CONSUMER_KEY = process.env.SNAPTRADE_CONSUMER_KEY;

const BASE = 'https://api.snaptrade.com/api/v1';
const BASE_PATH = '/api/v1';

function jsonStringifyOrdered(obj) {
  const allKeys = [];
  const seen = {};
  JSON.stringify(obj, function(key, value) {
    if (!(key in seen)) { allKeys.push(key); seen[key] = null; }
    return value;
  });
  allKeys.sort();
  return JSON.stringify(obj, allKeys);
}

function computeSignature(apiPath, queryString) {
  const encodedKey = encodeURI(CONSUMER_KEY);
  const sigObject = { content: null, path: BASE_PATH + apiPath, query: queryString };
  const message = jsonStringifyOrdered(sigObject);
  return crypto.createHmac('sha256', encodedKey).update(message).digest('base64');
}

function snapFetch(apiPath, queryParams) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const qp = new URLSearchParams({ clientId: CLIENT_ID, timestamp, ...queryParams });
  const queryString = qp.toString();
  const signature = computeSignature(apiPath, queryString);
  const url = `${BASE}${apiPath}?${queryString}`;

  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { 'Signature': signature, 'Accept': 'application/json' }
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
  });
}

function snapPost(apiPath, queryParams, bodyData) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const qp = new URLSearchParams({ clientId: CLIENT_ID, timestamp, ...queryParams });
  const queryString = qp.toString();
  const encodedKey = encodeURI(CONSUMER_KEY);
  const sigObject = { content: bodyData || null, path: BASE_PATH + apiPath, query: queryString };
  const message = jsonStringifyOrdered(sigObject);
  const signature = crypto.createHmac('sha256', encodedKey).update(message).digest('base64');
  const url = `${BASE}${apiPath}?${queryString}`;
  const postBody = bodyData ? JSON.stringify(bodyData) : '';

  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Signature': signature,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postBody)
      }
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.write(postBody);
    req.end();
  });
}

// Register or retrieve a user — returns userSecret
app.post('/connect', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY) return res.status(503).json({ error: 'Server credentials not configured' });
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  try {
    // Try registering — if user exists SnapTrade returns 409
    const { status, body } = await snapPost('/snapTrade/registerUser', {}, { userId });
    const data = JSON.parse(body);
    console.log('registerUser', status, body.slice(0, 120));

    if (status === 200 || status === 201) {
      return res.json({ userId, userSecret: data.userSecret });
    }
    if (status === 409) {
      // User already exists — delete and re-register to get fresh secret
      // OR just tell frontend the user is already registered and ask for secret
      // Best approach without a DB: return a flag so frontend knows to ask for secret
      return res.json({ userId, exists: true });
    }
    return res.status(status).json(data);
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/proxy', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY) return res.status(503).json({ error: 'Server credentials not configured' });
  try {
    const { path, params = {} } = req.body;
    if (!path) return res.status(400).json({ error: 'Missing path' });

    const { userId, userSecret, ...rest } = params;
    const query = { userId, userSecret, ...rest };

    const { status, body } = await snapFetch(path, query);
    console.log(`${path} → ${status}: ${body.slice(0, 150)}`);

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
