const fs = require('fs');
const key = fs.readFileSync('./key.pem');
const cert = fs.readFileSync('./cert.pem');
const helmet = require("helmet");
const express = require('express');
const app = express();
const robots = require("express-robots-txt");
const https = require('https');
const server = https.createServer({ key, cert }, app);
const port = 443;
const rateLimit = require('express-rate-limit')
const timeout = require("connect-timeout");
const rateLimiterMiddleware = require("./lib/rate-limiter");
const haltOnTimedout = require("./lib/timeout");
const bodyParser = require("body-parser");
var exec = require('child_process').exec;

const limiter = rateLimit({
	windowMs: 1 * 60 * 1000, // 1 minutes
	max: 5, // Limit each IP to 100 requests per `window` (here, per 1 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})

const pack = `
server|127.0.0.1
port|17095
type|1
#maint|Sky Anti DDoS
beta_server|127.0.0.1
beta_port|17091

beta_type|1
meta|defined
RTENDMARKERBS1001|unknown
`;

const Sky = `<center>Sky AntiDDoS</center>`;


app.use(timeout("6s"));
app.use(rateLimiterMiddleware);
app.use(helmet());
app.use(
  robots({
    UserAgent: "*",
    Disallow: "/",
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(haltOnTimedout);


app.post("/growtopia/server_data.php", limiter, (req, res) => {
  res.status(200).send(pack).end();
});

app.post("/nusantara.php", limiter, (req, res) => {
  res.status(200).send(Sky).end();
});

app.get("/", limiter, (req, res) => {
 res.writeHead(301);
    process.env.BLACKLIST
    res.end();
});

exec('clear', function callback(error, stdout, stderr) {
  // result
});
server.listen(port, () => {
  console.log(`

INGAT KAWAN TIDAK ADA YANG SETIA DI DUNIA INI SELAIN IBU

 SKY-HTTPS Made By Sky
 Anti DDoS Status:Online https://127.0.0.1:${port}`);
});
