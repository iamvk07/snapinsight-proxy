const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const BASE = 'https://api.snaptrade.com/api/v1';

function sign(clientId, consumerKey, path) {
  const ts = Date.now().toString();
  const msg = clientId + ts + path;
  const sig = crypto.createHmac('sha256', consumerKey).update(msg).digest('hex');
  return { ts, sig };
}

// Generic proxy endpoint
// POST /proxy  body: { clientId, consumerKey, path, params }
app.post('/proxy', async (req, res) => {
  try {
    const { clientId, consumerKey, path, params = {} } = req.body;
    if (!clientId || !consumerKey || !path) {
      return res.status(400).json({ error: 'Missing clientId, consumerKey, or path' });
    }
    const { ts, sig } = sign(clientId, consumerKey, path);
    const allParams = new URLSearchParams({ clientId, timestamp: ts, ...params });
    const url = `${BASE}${path}?${allParams}`;
    const r = await fetch(url, {
      headers: { Signature: sig, timestamp: ts, Accept: 'application/json' }
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SnapInsight proxy running on port ${PORT}`));
