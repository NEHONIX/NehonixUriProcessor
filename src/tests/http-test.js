// const http = require("http");
import http  from "http"

const postData = JSON.stringify({
  url: "https://malicious.com/login?obj[__proto__][polluted]=true",
});

const options = {
  hostname: "localhost",
  port: 1982,
  path: "/api/secure",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Host: "malicious.com",
    "Content-Length": Buffer.byteLength(postData),
  },
};

const req = http.request(options, (res) => {
  let data = "";
  res.on("data", (chunk) => (data += chunk));
  res.on("end", () => console.log(JSON.parse(data)));
});

req.on("error", (e) => console.error(`Request error: ${e.message}`));
req.write(postData);
req.end();
