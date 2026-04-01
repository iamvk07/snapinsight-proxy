const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const BASE = 'https://api.snaptrade.com/api/v1';
const BASE_PATH = '/api/v1';

// Exact algorithm from SnapTrade SDK requestAfterHook.js
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

function computeSignature(consumerKey, apiPath, queryString, body) {
  const encodedKey = encodeURI(consumerKey);
  const content = (body && Object.keys(body).length > 0) ? body : null;
  const sigObject = { content, path: BASE_PATH + apiPath, query: queryString };
  const message = jsonStringifyOrdered(sigObject);
  return crypto.createHmac('sha256', encodedKey).update(message).digest('base64');
}

function snapFetch(consumerKey, clientId, apiPath, queryParams) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const qp = new URLSearchParams({ clientId, timestamp, ...queryParams });
  const queryString = qp.toString();
  const signature = computeSignature(consumerKey, apiPath, queryString, null);
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

app.post('/proxy', async (req, res) => {
  try {
    const { clientId, consumerKey, path, params = {} } = req.body;
    if (!clientId || !consumerKey || !path) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const { userId, userSecret, ...rest } = params;
    const query = { userId, userSecret, ...rest };

    const { status, body } = await snapFetch(consumerKey, clientId, path, query);
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
