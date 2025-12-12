var express = require("express");
const http = require("http");
const https = require("https");
var app = express();
const port = 3030;

app.use(express.json({ limit: "50mb" }));

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
  res.sendStatus(200);
});

app.get("/users/:userId", (req, res, next) => {
  res.json("Hello! " + req.params.userId);
});


app.get("/dist", (req, res, next) => {
  http.get("http://grafana.com", {}, (r) => {
    if (r.statusCode !== 301) {
      console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
      res.sendStatus(500);
      return;
    }
    res.sendStatus(200);
  });
});

app.get("/traceme", (req, res, next) => {
  http.get("http://testserver:8080/gotracemetoo", {}, (r) => {
    if (r.statusCode !== 200) {
      console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
      res.sendStatus(500);
      return;
    }
    res.sendStatus(200);
  });
});

// Helper function to make HTTPS requests
function makeHttpsRequest(hostname, path) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: hostname,
      path: path,
      method: "GET",
      timeout: 10000,
      headers: {
        "User-Agent": "OBI-APM-Test/1.0.0",
      },
    };

    const req = https.request(options, (res) => {
      let data = "";

      res.on("data", (chunk) => {
        data += chunk;
      });

      res.on("end", () => {
        try {
          const jsonData = JSON.parse(data);
          resolve(jsonData);
        } catch (parseError) {
          resolve({ raw: data, statusCode: res.statusCode });
        }
      });
    });

    req.on("error", (error) => {
      reject(error);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });

    req.end();
  });
}

app.get("/api/test-apm", async (req, res) => {
  const results = {
    message: "APM test completed - external API calls made for tracing",
    Api: { status: "unknown", success: false, data: null },
    SecondApi: { status: "unknown", success: false, data: null },
  };

  try {
    // Call first external API with a lot of data
    try {
      const firstResponse = await makeHttpsRequest("opentelemetry.io", "/");
      results.Api.status = "success";
      results.Api.success = true;
      results.Api.data = firstResponse;
    } catch (error) {
      results.Api.status = `error: ${error.message}`;
      results.Api.success = false;
    }

    // Call second external API with a lot of data
    try {
      const secondResponse = await makeHttpsRequest("www.cncf.io", "/");
      results.SecondApi.status = "success";
      results.SecondApi.success = true;
      results.SecondApi.data = secondResponse;
    } catch (error) {
      results.SecondApi.status = `error: ${error.message}`;
      results.SecondApi.success = false;
    }

    res.json(results);
  } catch (error) {
    console.error("APM test error:", error);
    res.status(500).json({
      message: "APM test failed",
      error: error.message,
      ...results,
    });
  }
});

app.listen(port, () => {
  console.log("Server running on port " + port);
});
