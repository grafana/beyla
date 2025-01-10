const https = require('https');
const fs = require('fs');

var express = require("express");
var app = express();
const port = 3033;

app.use(express.json({limit: "50mb"}));

app.get("/greeting", (req, res, next) => {
    res.json("Hello!");
});

app.post("/greeting", (req, res, next) => {
    res.json(req.body);
});

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});

app.get("/traceme", (req, res, next) => {
    https.get('https://pytestserverssl:8380/tracemetoo', {rejectUnauthorized: false}, (r) => {
        if (r.statusCode !== 200) {
          console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
          res.sendStatus(500)
          return
        }
        res.sendStatus(200)
    });
})

const options = {
    key: fs.readFileSync(__dirname + '/key.pem', 'utf8'),
   cert: fs.readFileSync(__dirname + '/cert.pem', 'utf8')
};
  
var server = https.createServer(options, app).listen(port, () => {
    console.log("Server running on port " + port);
});