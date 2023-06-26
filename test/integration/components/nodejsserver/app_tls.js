const https = require('https');
const fs = require('fs');

var express = require("express");
var app = express();
const port = 3033;

app.get("/greeting", (req, res, next) => {
    res.json("Hello!");
});

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});

const options = {
    key: fs.readFileSync(__dirname + '/key.pem', 'utf8'),
   cert: fs.readFileSync(__dirname + '/cert.pem', 'utf8')
};
  
var server = https.createServer(options, app).listen(port, () => {
    console.log("Server running on port " + port);
});