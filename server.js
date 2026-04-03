const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID    = process.env.SNAPTRADE_CLIENT_ID;
const CONSUMER_KEY = process.env.SNAPTRADE_CONSUMER_KEY;
const SERVER_SECRET = process.env.SERVER_SECRET || 'snapinsight-secret-change-me';

const BASE      = 'https://api.snaptrade.com/api/v1';
const BASE_PATH = '/api/v1';

// In-memory registry: userId → userSecret
const registry = new Map();

// Preload known user from env vars so they survive server restarts
if (process.env.SNAPTRADE_USER_ID && process.env.SNAPTRADE_USER_SECRET) {
  registry.set(process.env.SNAPTRADE_USER_ID, process.env.SNAPTRADE_USER_SECRET);
}

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

function snapDelete(apiPath, queryParams) {
  const timestamp   = Math.floor(Date.now() / 1000).toString();
  const qp          = new URLSearchParams({ clientId: CLIENT_ID, timestamp, ...queryParams });
  const queryString = qp.toString();
  const parsed      = new URL(`${BASE}${apiPath}?${queryString}`);
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'DELETE',
      headers: { Signature: buildSig(apiPath, queryString, null), Accept: 'application/json' }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

// Sign up / log in
app.post('/signup', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY)
    return res.status(503).json({ error: 'Server not configured' });
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'User ID is required' });

  let userSecret;

  if (registry.has(username)) {
    // Returning user — use stored secret
    userSecret = registry.get(username);
  } else {
    // New user — register on SnapTrade
    try {
      const { status, body } = await snapPost('/snapTrade/registerUser', {}, { userId: username });
      const data = JSON.parse(body);
      if (status === 200 || status === 201) {
        userSecret = data.userSecret;
        registry.set(username, userSecret);
      } else if (status === 400 && body.includes('already exist')) {
        // User exists on SnapTrade but not in our registry (server restarted)
        // Delete and re-register to get a fresh userSecret
        try {
          await snapDelete('/snapTrade/deleteUser', { userId: username });
          const r2 = await snapPost('/snapTrade/registerUser', {}, { userId: username });
          const d2 = JSON.parse(r2.body);
          if (r2.status === 200 || r2.status === 201) {
            userSecret = d2.userSecret;
            registry.set(username, userSecret);
          } else {
            return res.status(500).json({ error: 'Could not restore session. Please try a different User ID.' });
          }
        } catch (e) {
          return res.status(500).json({ error: e.message });
        }
      } else {
        return res.status(status).json({ error: data.detail || 'Registration failed' });
      }
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  const token = createToken({ username, snapUserId: username, userSecret });
  res.json({ token, username });
});

// Get SnapTrade brokerage connection URL
app.post('/broker-connect', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY)
    return res.status(503).json({ error: 'Server not configured' });
  const { token } = req.body;
  let userId, userSecret;
  try {
    const s = verifyToken(token);
    userId = s.snapUserId; userSecret = s.userSecret;
  } catch { return res.status(401).json({ error: 'Invalid session' }); }

  try {
    const { status, body } = await snapPost('/snapTrade/login', { userId, userSecret }, null);
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

// Yahoo Finance helper
function yahooGet(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    https.get({ hostname: parsed.hostname, path: parsed.pathname + parsed.search,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Accept': 'application/json' }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

const SECTOR_ETFS = {
  XLK:'Technology', XLF:'Financials', XLV:'Healthcare', XLE:'Energy',
  XLI:'Industrials', XLP:'Consumer Staples', XLY:'Consumer Disc.', XLRE:'Real Estate',
  XLU:'Utilities', XLC:'Comm. Services', XLB:'Materials'
};

// Market sector performance
app.get('/market/sectors', async (req, res) => {
  try {
    const symbols = Object.keys(SECTOR_ETFS).join(',');
    const r = await yahooGet(`https://query1.finance.yahoo.com/v7/finance/quote?symbols=${symbols}&fields=regularMarketPrice,regularMarketChangePercent`);
    const d = JSON.parse(r.body);
    const results = (d.quoteResponse?.result || []).map(q => ({
      symbol: q.symbol,
      name: SECTOR_ETFS[q.symbol] || q.symbol,
      change: q.regularMarketChangePercent || 0,
      price: q.regularMarketPrice || 0
    }));
    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Quote info (sector, beta) for holdings
app.post('/market/quotes', async (req, res) => {
  const { symbols } = req.body;
  if (!symbols?.length) return res.json([]);
  try {
    const symsStr = symbols.join(',');
    const r = await yahooGet(`https://query1.finance.yahoo.com/v7/finance/quote?symbols=${symsStr}&fields=regularMarketChangePercent,beta,sector`);
    const d = JSON.parse(r.body);
    const results = (d.quoteResponse?.result || []).map(q => ({
      symbol: q.symbol,
      sector: q.sector || 'Other',
      beta: q.beta || null,
      changePercent: q.regularMarketChangePercent || 0
    }));
    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// S&P 500 benchmark
app.get('/market/benchmark', async (req, res) => {
  try {
    const r = await yahooGet('https://query1.finance.yahoo.com/v7/finance/quote?symbols=%5EGSPC&fields=regularMarketPrice,regularMarketChangePercent,regularMarketPreviousClose');
    const d = JSON.parse(r.body);
    const q = d.quoteResponse?.result?.[0];
    if (!q) return res.status(404).json({ error: 'No data' });
    res.json({ price: q.regularMarketPrice, changePercent: q.regularMarketChangePercent, prevClose: q.regularMarketPreviousClose });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
