const https = require('https');
const url = 'https://grafana.com';

var count = 1

function smoke() {
    console.log("Calling: " + url)

    const traceStr = count.toString().padStart(16, "0")

    const options = {
        headers: {
            "traceParent": "00-" + traceStr + "0000000000000001-" + traceStr + "-01"
        }
    }

    count += 1;

    https.get(url, options, (res) => {
        if (res.statusCode !== 200) {
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

//smoke();
smokeLoop();
