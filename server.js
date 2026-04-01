const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const BASE = 'https://api.snaptrade.com/api/v1';

app.post('/proxy', async (req, res) => {
  try {
    const { clientId, consumerKey, path, params = {} } = req.body;
    if (!clientId || !consumerKey || !path) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const ts = Math.floor(Date.now() / 1000).toString();
    const msg = clientId + ts + path;
    const sig = crypto.createHmac('sha256', consumerKey).update(msg).digest('hex');

    // Build query string — clientId and timestamp go in query
    const qp = new URLSearchParams({ clientId, timestamp: ts });
    // Add extra params (userId, userSecret, etc)
    Object.entries(params).forEach(([k,v]) => qp.append(k, v));

    const url = `${BASE}${path}?${qp.toString()}`;
    console.log('Calling:', url.replace(consumerKey, '***'));

    const r = await fetch(url, {
      headers: {
        'Signature': sig,
        'Timestamp': ts,
        'Accept': 'application/json'
      }
    });

    const text = await r.text();
    console.log('SnapTrade status:', r.status, text.slice(0, 200));

    try {
      res.status(r.status).json(JSON.parse(text));
    } catch {
      res.status(r.status).send(text);
    }

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
