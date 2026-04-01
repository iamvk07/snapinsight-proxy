const express = require('express');
const cors = require('cors');
const { Snaptrade } = require('snaptrade-typescript-sdk');

const app = express();
app.use(cors());
app.use(express.json());

app.post('/proxy', async (req, res) => {
  try {
    const { clientId, consumerKey, path, params = {} } = req.body;
    if (!clientId || !consumerKey || !path) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const snaptrade = new Snaptrade({ clientId, consumerKey });
    const { userId, userSecret, ...rest } = params;

    let data;

    // /accounts
    if (path === '/accounts') {
      const r = await snaptrade.accountInformation.listUserAccounts({ userId, userSecret });
      data = r.data;

    // /accounts/:id/holdings
    } else if (/^\/accounts\/[^/]+\/holdings$/.test(path)) {
      const accountId = path.split('/')[2];
      const r = await snaptrade.accountInformation.getUserAccountHoldings({ userId, userSecret, accountId });
      data = r.data;

    // /accounts/:id/activities
    } else if (/^\/accounts\/[^/]+\/activities$/.test(path)) {
      const accountId = path.split('/')[2];
      const r = await snaptrade.transactionsAndReporting.getActivities({ userId, userSecret, accounts: accountId, ...rest });
      data = r.data;

    // /holdings (all accounts)
    } else if (path === '/holdings') {
      const r = await snaptrade.accountInformation.getAllUserHoldings({ userId, userSecret });
      data = r.data;

    } else if (path === '/login') {
      const r = await snaptrade.authentication.loginSnapTradeUser({ userId, userSecret });
      data = r.data;

    } else if (path === '/registerUser') {
      const r = await snaptrade.authentication.registerSnapTradeUser({ userId });
      data = r.data;

    } else if (path === '/deleteUser') {
      const r = await snaptrade.authentication.deleteSnapTradeUser({ userId });
      data = r.data;

    } else {
      return res.status(400).json({ error: `Unknown path: ${path}` });
    }

    res.json(data);
  } catch (e) {
    console.error(e?.response?.data || e.message);
    const status = e?.response?.status || 500;
    res.status(status).json(e?.response?.data || { error: e.message });
  }
});


app.get('/health', (_, res) => res.json({ status: 'ok', service: 'snapinsight-proxy' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
