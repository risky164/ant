const fs = require('fs');
const key = fs.readFileSync('./key.pem');
const cert = fs.readFileSync('./cert.pem');

const express = require('express');
const app = express();
const {
    exec
} = require('child_process');
const http = require("http");
const {
  RateLimiterMemory
} = require('rate-limiter-flexible');
const rateLimiter = new RateLimiterMemory({
  points: 5,
  duration: 1
});
rateLimiter.consume(3)
const https = require('https');
const server = https.createServer({ key, cert }, app);
const port = 443;
const prompt = require("prompt-sync")();
var readline = require('readline');
var blacklist = new Map();
const rancolor = require("randomcolor");
const request = require("request");
const os = require("os");
//const ipvps = prompt("SUBSERVER IP : ");
//const youripvpsbro = prompt("VPS IP : ");
//const udpport = prompt("UDP Port (Default 17091) : ");
let data = `server|20.121.137.237\nport|17091\ntype|1\n#maint|Server is under maintenance. We will be back online shortly. Thank you for your patience!\n\nbeta_server|127.0.0.1\nbeta_port|17091\n\nbeta_type|1\nmeta|localhost\nRTENDMARKERBS1001\n`;

const pack = `
server|20.121.137.237
port|17091
type|1
#maint|Server is under maintenance. We will be back online shortly. Thank you for your patience!
beta_server|20.121.137.237
beta_port|17091

beta_type|1
meta|defined
RTENDMARKERBS1001|unknown
`;


app.post("/growtopia/server_data.php", (req, res) => {
  res.status(200).send(pack).end();
});

// don't accept all method
app.use((req, res) => {
	return res.destroy();
    return req.connection.destroy();
	return req.socket.destroy();
	return;
});
server.listen(port, () => {
  console.log(`Sky Protection`);
});

//Custom Item
/******************************************/
if (!fs.existsSync('./assets')){
  fs.mkdirSync('./assets');
}
if (!fs.existsSync('./assets/game')){
  fs.mkdirSync('./assets/game');
}
if (!fs.existsSync('./assets/social')){
  fs.mkdirSync('./assets/social');
}
if (!fs.existsSync('./assets/interface')){
  fs.mkdirSync('./assets/interface');
}
if (!fs.existsSync('./assets/interface/large')){
  fs.mkdirSync('./assets/interface/large');
}
/******************************************/
var files = new Map();
for (var _i = 0, _a = fs.readdirSync("assets/game"); _i < _a.length; _i++) {
  var file = _a[_i];
  if (!file.endsWith(".rttex")) continue;
  files.set(file, fs.readFileSync("assets/game/" + file));
};
for (var _i = 0, _a = fs.readdirSync("assets/social"); _i < _a.length; _i++) {
  var file1 = _a[_i];
  if (!file1.endsWith(".rttex")) continue;
  files.set(file1, fs.readFileSync("assets/social/" + file1));
};
for (var _i = 0, _a = fs.readdirSync("assets/interface/large"); _i < _a.length; _i++) {
  var file2 = _a[_i];
  if (!file2.endsWith(".rttex")) continue;
  files.set(file2, fs.readFileSync("assets/interface/large/" + file2));
};
//Custom Item End

const servers = http.createServer(function(req, res) {
    if (req.url == "/" && req.headers["user-agent"] == "CheckHost (https://check-host.net/)" || req.headers["content-length"] == "0" || req.headers["content-length"] == 0 || req.headers["content-type"] == "application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n" && req.connection.bytesRead > 1000) {
        if (req.method == "POST" || req.method == "GET" || req.method == "HEAD" || req.method == "TRACE" || req.method == "PATCH" || req.method == "DELETE" || req.method == "CONNECT") {
			res.writeHead(301, `DUNIA ITU MEMANGLAH KEJAM` );
            process.env.BLACKLIST
            res.end();
        }
    }
    else if (req.url == "/growtopia/server_data.php") {
        if (req.method == "POST") {
            res.write(data);
			res.end();
        }
        else {
			return res.destroy();
            return req.connection.destroy();
			return req.socket.destroy();
	        return;
        }
    }
    else {
		return res.destroy();
        return req.connection.destroy();
		return req.socket.destroy();
	    return;
    }
});
servers.listen(80);

function add_address(address) {
    blacklist.set(address, Date.now() + 10000);
	return;
    socket.destroy();
    socket.end();
}

servers.on("connection", function (socket) {
    if (!blacklist.has(socket.remoteAddress)) {
        add_address(socket.remoteAddress);
		return;
        socket.destroy();
	    socket.end();
    }
    else {
        var not_allowed = blacklist.get(socket.remoteAddress);
        if (Date.now() > not_allowed) {
            blacklist.delete(socket.remoteAddress);
        }
        else
			return;
            socket.destroy();
			socket.end();
    }
});

function add_address(address) {
    blacklist.set(address, Date.now() + 10000);
	return;
    socket.destroy();
    socket.end();
}

server.on("connection", function (socket) {
    if (!blacklist.has(socket.remoteAddress)) {
        add_address(socket.remoteAddress);
		return;
        socket.destroy();
	    socket.end();
    }
    else {
        var not_allowed = blacklist.get(socket.remoteAddress);
        if (Date.now() > not_allowed) {
            blacklist.delete(socket.remoteAddress);
        }
        else
			return;
            socket.destroy();
			socket.end();
    }
});