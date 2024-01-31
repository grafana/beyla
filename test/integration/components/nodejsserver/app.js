var express = require("express");
const http = require('http');
var app = express();
const port = 3030;

app.use(express.json({limit: "50mb"}));

app.get("/greeting", (req, res, next) => {
    res.json("Hello!");
});

app.post("/greeting", (req, res, next) => {
    res.json(req.body);
});

app.get("/bye", (req, res, next) => {
    res.json("Goodbye!");
});

app.post("/bye", (req, res, next) => {
    res.json(req.body);
});

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});

app.get("/dist", (req, res, next) => {
    http.get('http://grafana.com', {}, (r) => {
        if (r.statusCode !== 301) {
          console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
          res.sendStatus(500)
          return
        }
        res.sendStatus(200)
    });
})

app.get("/traceme", (req, res, next) => {
    http.get('http://testserver:8080/gotracemetoo', {}, (r) => {
        if (r.statusCode !== 200) {
          console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
          res.sendStatus(500)
          return
        }
        res.sendStatus(200)
    });
})

app.listen(port, () => {
    console.log("Server running on port " + port);
});