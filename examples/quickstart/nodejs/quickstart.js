var express = require("express");
var app = express();
const port = 8080;

app.use(express.json({limit: "50mb"}));

app.get(/(.+)/, (req, res, next) => {
    console.log("received request" + req.url)
    res.json("Hello!");
});

app.listen(port, () => {
    console.log("Server running on port " + port);
});