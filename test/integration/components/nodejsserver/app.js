var express = require("express");
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

app.get("/smoke", (req, res, next) => {
    res.sendStatus(200)
});

app.listen(port, () => {
    console.log("Server running on port " + port);
});