const express = require('express');
const axios = require('axios');

const app = express();

app.get('/r', async (req, res) => {
    try {
        // Set a value in Redis for your test (this could be a trace, message, etc.)
        res.send(`Service R`);
    } catch (err) {
        console.error('Error in Service R:', err);
        res.status(500).send('Error interacting with R');
    }
});

app.get('/q', async (req, res) => {
    try {
        // Set a value in Redis for your test (this could be a trace, message, etc.)
        res.send(`Service Q`);
    } catch (err) {
        console.error('Error in Service Q:', err);
        res.status(500).send('Error interacting with Q');
    }
});

app.get('/p', async (req, res) => {
    try {
        // Set a value in Redis for your test (this could be a trace, message, etc.)
        res.send(`Service P`);
    } catch (err) {
        console.error('Error in Service P:', err);
        res.status(500).send('Error interacting with P');
    }
});

app.listen(5006, () => console.log('Service R running on port 5006'));

