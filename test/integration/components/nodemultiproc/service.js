const express = require('express');
const axios = require('axios');

const app = express();

/**
 * CLI Usage:
 * node service.js <route> <port> [upstreamURL]
 */
const [route = 'a', port = 5001, upstream] = process.argv.slice(2);

app.get(`/${route}`, async (req, res) => {
  if (upstream) {
    try {
      const response = await axios.get(upstream);
      res.send(`Service ${route.toUpperCase()} → ${response.data} <br>`);
    } catch (err) {
      console.error(`Error forwarding in Service ${route.toUpperCase()}:`, err.message);
      res.status(500).send(`Error forwarding to upstream: ${err.message}`);
    }
  } else {
    res.send(`Hello from Service ${route.toUpperCase()}`);
  }
});

app.listen(port, () => {
  console.log(`Service ${route.toUpperCase()} running on port ${port}`);
  console.log(upstream ? `Forwarding to: ${upstream}` : `No upstream; responding directly`);
});

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});
