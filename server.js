const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

const BASE = 'https://api.snaptrade.com/api/v1';

function sign(consumerKey, clientId, timestamp, path) {
  const msg = clientId + timestamp + path;
  return crypto.createHmac('sha256', consumerKey).update(msg).digest('hex');
}

function snapFetch(consumerKey, clientId, apiPath, queryParams) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sig = sign(consumerKey, clientId, timestamp, apiPath);

  const qp = new URLSearchParams({ clientId, timestamp, ...queryParams });
  const url = `${BASE}${apiPath}?${qp.toString()}`;

  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'Signature': sig,
        'timestamp': timestamp,
        'Accept': 'application/json'
      }
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
    console.log(`${path} → ${status}: ${body.slice(0, 120)}`);

    try {
      res.status(status).json(JSON.parse(body));
    } catch {
      res.status(status).send(body);
    }
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
