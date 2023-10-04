var express = require("express");
var app = express();
const port = 3030;

app.get("/greeting", (req, res, next) => {
    res.json("Hello!");
});

app.get("/bye", (req, res, next) => {
    res.json("Goodbye!");
});

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});

app.listen(port, () => {
    console.log("Server running on port " + port);
});