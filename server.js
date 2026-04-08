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

// In-memory registry: userId → { userSecret, passwordHash }
const registry = new Map();

function hashPassword(pw) {
  return crypto.createHmac('sha256', SERVER_SECRET).update(pw).digest('hex');
}

// Preload known user from env vars so they survive server restarts
if (process.env.SNAPTRADE_USER_ID && process.env.SNAPTRADE_USER_SECRET) {
  registry.set(process.env.SNAPTRADE_USER_ID, {
    userSecret: process.env.SNAPTRADE_USER_SECRET,
    passwordHash: process.env.SNAPTRADE_USER_PASSWORD ? hashPassword(process.env.SNAPTRADE_USER_PASSWORD) : null
  });
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


// Sign up / log in
app.post('/signup', async (req, res) => {
  if (!CLIENT_ID || !CONSUMER_KEY)
    return res.status(503).json({ error: 'Server not configured' });
  const { username, password, token: existingToken } = req.body;
  if (!username) return res.status(400).json({ error: 'User ID is required' });
  if (!password)  return res.status(400).json({ error: 'Password is required' });

  let userSecret;

  if (registry.has(username)) {
    // Returning user — verify password
    const entry = registry.get(username);
    if (entry.passwordHash && entry.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    if (!entry.passwordHash) entry.passwordHash = hashPassword(password);
    userSecret = entry.userSecret;
  } else {
    // Not in registry (new user or server restarted) — try SnapTrade
    try {
      const { status, body } = await snapPost('/snapTrade/registerUser', {}, { userId: username });
      const data = JSON.parse(body);
      if (status === 200 || status === 201) {
        // Brand new user
        userSecret = data.userSecret;
        registry.set(username, { userSecret, passwordHash: hashPassword(password) });
      } else if (status === 400 && body.includes('exist')) {
        // User exists on SnapTrade but registry lost (server restart)
        // Try to recover userSecret from the client's saved token
        let recovered = false;
        if (existingToken) {
          try {
            const decoded = verifyToken(existingToken);
            if (decoded.snapUserId === username && decoded.userSecret) {
              userSecret = decoded.userSecret;
              registry.set(username, { userSecret, passwordHash: hashPassword(password) });
              recovered = true;
            }
          } catch (_) { /* invalid token, fall through */ }
        }
        if (!recovered) {
          return res.status(409).json({ error: 'Account exists but session was lost. Please use "Remember me" next time, or choose a different User ID.' });
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
    const redirectURI = 'https://iamvk07.github.io/snap-insight/';
    const { status, body } = await snapPost('/snapTrade/login', { userId, userSecret }, { redirectURI });
    console.log('login', status, body.slice(0, 150));
    const data = JSON.parse(body);
    if (status === 200) return res.json({ redirectURI: data.redirectURI });
    return res.status(status).json({ error: data.detail || 'Failed to get connection URL' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
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

// Finnhub helper
const FINNHUB_KEY = process.env.FINNHUB_KEY;
function finnhubGet(path) {
  return new Promise((resolve, reject) => {
    const url = new URL(`https://finnhub.io/api/v1${path}`);
    url.searchParams.set('token', FINNHUB_KEY);
    https.get({ hostname: url.hostname, path: url.pathname + url.search,
      headers: { 'Accept': 'application/json' }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch(e) { resolve({}); }
      });
    }).on('error', reject);
  });
}

const SECTOR_ETFS = {
  XLK:'Technology', XLF:'Financials', XLV:'Healthcare', XLE:'Energy',
  XLI:'Industrials', XLP:'Consumer Staples', XLY:'Consumer Disc.', XLRE:'Real Estate',
  XLU:'Utilities', XLC:'Comm. Services', XLB:'Materials'
};

// Market sector performance
app.get('/market/sectors', async (_, res) => {
  if (!FINNHUB_KEY) return res.status(503).json({ error: 'FINNHUB_KEY not configured' });
  try {
    const entries = Object.entries(SECTOR_ETFS);
    const settled = await Promise.allSettled(entries.map(([sym]) => finnhubGet(`/quote?symbol=${sym}`)));
    const results = entries.map(([sym, name], i) => {
      const q = settled[i].status === 'fulfilled' ? settled[i].value : {};
      return { symbol: sym, name, change: q.dp || 0, price: q.c || 0 };
    });
    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Quote info (sector, beta) for holdings
app.post('/market/quotes', async (req, res) => {
  if (!FINNHUB_KEY) return res.status(503).json({ error: 'FINNHUB_KEY not configured' });
  const { symbols } = req.body;
  if (!symbols?.length) return res.json([]);
  try {
    const results = await Promise.allSettled(symbols.map(async sym => {
      const [profile, metrics, quote] = await Promise.allSettled([
        finnhubGet(`/stock/profile2?symbol=${sym}`),
        finnhubGet(`/stock/metric?symbol=${sym}&metric=all`),
        finnhubGet(`/quote?symbol=${sym}`)
      ]);
      const p = profile.status === 'fulfilled' ? profile.value : {};
      const m = metrics.status === 'fulfilled' ? metrics.value : {};
      const q = quote.status === 'fulfilled' ? quote.value : {};
      return { symbol: sym, sector: p.finnhubIndustry || 'Other', beta: m.metric?.beta || null, changePercent: q.dp || 0 };
    }));
    res.json(results.filter(r => r.status === 'fulfilled').map(r => r.value));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// S&P 500 benchmark (use SPY as proxy — Finnhub free tier doesn't support indices)
app.get('/market/benchmark', async (req, res) => {
  if (!FINNHUB_KEY) return res.status(503).json({ error: 'FINNHUB_KEY not configured' });
  try {
    const q = await finnhubGet('/quote?symbol=SPY');
    if (!q.c) return res.status(404).json({ error: 'No data' });
    res.json({ price: q.c, changePercent: q.dp || 0, prevClose: q.pc || 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// SPY historical candle data for performance chart
app.get('/market/spy-history', async (req, res) => {
  if (!FINNHUB_KEY) return res.status(503).json({ error: 'FINNHUB_KEY not configured' });
  const range = req.query.range || '1M';
  const to = Math.floor(Date.now() / 1000);
  const days = { '1W': 7, '1M': 30, '3M': 90, '6M': 180, '1Y': 365 }[range] || 30;
  const from = to - days * 86400;
  try {
    const data = await finnhubGet(`/stock/candle?symbol=SPY&resolution=D&from=${from}&to=${to}`);
    if (!data.c || data.s === 'no_data') return res.json({ dates: [], prices: [] });
    res.json({
      dates: data.t.map(ts => new Date(ts * 1000).toISOString().slice(0, 10)),
      prices: data.c
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SnapInsight proxy listening on port ${PORT}`);
});
