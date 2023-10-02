const http = require('http');
const url = 'http://grafana.com';

var count = 1

function smoke() {
    console.log("Calling: " + url)

    const traceStr = count.toString().padStart(16, "0")

    const options = {
        headers: {
            "traceParent": "00-" + traceStr + "0000000000000000-" + traceStr + "-01"
        }
    }

    count += 1;

    http.get(url, options, (res) => {
        if (res.statusCode !== 301) {
          console.error(`Did not get an OK from the server. Code: ${res.statusCode}`);
          res.resume();
          return;
        }
    });
}

function smokeLoop() {
    setInterval(() => {
        smoke();
    }, 1000);
}

smoke();
smokeLoop();