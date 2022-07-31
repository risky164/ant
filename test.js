
const express = require("express")
const app = express();
var log4js = require('log4js');
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const colors = require("colors");
const ask = require("prompt-sync")();
const request = require("request");
const os = require("os");
log4js.configure({
  appenders: {
    multi: { type: 'multiFile', base: 'logs/', property: 'categoryName', extension: '.log' }
  },
  categories: {
    default: { appenders: [ 'multi' ], level: 'debug' }
  }
});
const httplog = log4js.getLogger('httplog');

var clear = require('console-clear')

var blacklist = new Map();
var helmet = require('helmet');
var RateLimit = require('express-rate-limit');
var RateLimiter = require('limiter').RateLimiter;


var setTitle = require('console-title');
setTitle('Razor Protection 3.0 | Anti DDoS');

var readline = require('readline'); 
var rl = readline.createInterface({ 
input: process.stdin, 
output: process.stdout 
});

rl.question("Welcome To Anti Protect By Razor: ", function(password) {
        if (password === "Razor")
        {
		console.clear ()
const expresslimit = require('express');
var prompt = require('prompt-sync')();
var ipvps = prompt('Fill In IP Server: ');
var nane = prompt('Fill In Name Server: ');
var tcpport = prompt("YOUR PORT (default 80) : ");
var udpport = prompt("YOUR UDP PORT (default 17091) : ");
var local = prompt('Meta Server ( default: localhost ): ');
var packet = `server|${ipvps}\nport|${udpport}\ntype|1\n#maint|Protected By Razor Http\n\nbeta_server|127.0.0.1\nbeta_port|17091\n\nbeta_type|1\nmeta|localhost\nRTENDMARKERBS1001`;
const http = require("http");
const opts = new RateLimiterMemory({
var visit = 0;


let statusCodes;

if (typeof process.env.STATUS_CODES !== 'undefined' && process.env.STATUS_CODES !== null) {
    statusCodes = JSON.parse(process.env.STATUS_CODES);
} else {
    statusCodes = [2, 5, 10, 20, 100, 200, 201, 301, 304, 307, 350, 400, 401, 403, 404, 500, 502, 503, 598, 999];
}

const getRandomStatusCode = () => {
    return statusCodes[Math.floor(Math.random() * statusCodes.length)];
};

const requestHandler = (request, response) => {
    response.statusCode = getRandomStatusCode();
    response.end();
};
const { createProxyMiddleware } = require('http-proxy-middleware');
        const httpProxy = require('http-proxy');

        var proxy = new httpProxy.createProxyServer({});
        proxy.on('proxyReq', function (proxyReq, req, res, options) {
            proxyReq.setHeader('X-Special-Proxy-Header', 'foobar');
        });
        proxy.on('upgrade', function (req, socket, head) {
            proxy.ws(req, socket, head);
        });
		var express = require("express");
        var app = express();
const client = http.createServer(function(req, res) {
	        var helmet = require("helmet");
            //for use helmet
            app.use(helmet());
			var RateLimiter = require('limiter').RateLimiter;
			
			//for use helmet
            app.use(helmet());
			var RateLimiter = require('limiter').RateLimiter;
			
			//for use helmet
            app.use(helmet());
			var RateLimiter = require('limiter').RateLimiter;
         
var limiter = new RateLimiter(150, 'hour');
            limiter.removeTokens(1, function(err, remainingRequests) {
            
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(1, 250);
            
            limiter.removeTokens(1, function() {
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(150, 'hour', true);  
            limiter.removeTokens(1, function(err, remainingRequests) {
            if (remainingRequests < 0) {
            response.writeHead(200, {'Content-Type': 'text/html;charset=UTF-8'});
            response.end('200 Too Many Requests - your IP is being rate limited');
            } 
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(10, 'second');
            
            if (limiter.tryRemoveTokens(5))
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(1, 250);
            
            limiter.getTokensRemaining();
            var BURST_RATE = 1024 * 1024 * 150; 
            var FILL_RATE = 1024 * 1024 * 50; 
            var TokenBucket = require('limiter').TokenBucket;
            var bucket = new TokenBucket(BURST_RATE, FILL_RATE, 'second', null);
            
            var opts = new RateLimiterMemory
                windowMs: 15*60*1000, 
                max: 100,
                delayMs: 0, 
                points: 50, // 10 points
                duration: 1 // per second 
            });
            var limiter = new RateLimit({
                windowMs: 15 * 60 * 1000,
                max: 100,
                delayMs: 0,
                message: ""
});
var limiter = new RateLimit({
    windowMs: 15*60*1000, 
    max: 100,
    delayMs: 0, 
    lookup: ['connection.remoteAddress'],
    total: 100,
    expire: 1000 * 60 * 60
        });
        var limiter = new RateLimit({
          windowMs: 1000,
          max: 15,
          delayMs: 0, 
          statusCode: 429,
          lookup: ['connection.remoteAddress'],
          rateLimitBy: ['connection.remoteAddress'],
          total:15,
          expire: 1000*60*60,
            });
            const slowDown = require("express-slow-down");
            const speedLimiter = slowDown({
            windowMs: 20 * 60 * 100, // 20 minutes
            delayAfter: 40, // allow 40 requests per 20 minutes, then...
            delayMs: 200 // begin adding 200ms of delay per request above 100:
            // request # 71 is delayed by  200ms
            // request # 72 is delayed by 400ms
            // request # 73 is delayed by 600ms
            // etc.
            });
            
//  apply to all requests
app.use(speedLimiter);

app.get("/test", (req, res) => {
  // logic
});

app.listen(3000, () => console.log(`App is running`));
            
            const rateLimiter = new RateLimiterMemory({
                points: 50, // 10 points
                duration: 5 // per second  
      
        });
		
var FastRateLimit = require("fast-ratelimit").FastRateLimit;
var messageLimiter = new FastRateLimit({
  threshold : 20,
  ttl       : 60 
});

const rateLimits = require('rate-limit-promise')
 
let requests = rateLimits(50, 1000) // 1 request per 1000ms = 1 second
Promise.all([requests(), requests(), requests()]).then(() => {
});

var ExpressBrute = require('express-brute');

var expressDefend = require('express-defend');
 
app.use(expressDefend.protect({ 
    maxAttempts: 5,                   // (default: 5) number of attempts until "onMaxAttemptsReached" gets triggered
    dropSuspiciousRequest: true,      // respond 403 Forbidden when max attempts count is reached
    consoleLogging: true,             // (default: true) enable console logging
    logFile: 'suspicious.log',        // if specified, express-defend will log it's output here
    onMaxAttemptsReached: function(ipAddress, url){
        console.log('IP address ' + ipAddress + ' is considered to be malicious, URL: ' + url);
    } 
}));

// stores state locally, don't use this in production
var store = new ExpressBrute.MemoryStore();
var bruteforce = new ExpressBrute(store);

app.post('/auth',
	bruteforce.prevent, // error 429 if we hit this route too often
	function (req, res, next) {
		res.send('Success!');
	}
);

const StreamLimiter = require('stream-limiter')
const { Readable } = require('stream') 
 
const rs = new Readable()
rs.push(Buffer.from([77, 97, 114, 115, 104, 97, 108, 108]))
rs.push(null)
 
const sl = StreamLimiter(7)
 
rs.pipe(sl).pipe(process.stdout)

const rateLimit = require("express-rate-limit");

// Enable if you're behind a reverse proxy (Heroku, Bluemix, AWS ELB or API Gateway, Nginx, etc)
// see https://expressjs.com/en/guide/behind-proxies.html
// app.set('trust proxy')

var socket
var io
const socketio = require('socket.io')
const redis = require('redis');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const redisClient = redis.createClient({
  enable_offline_queue: false,
});

const maxWrongAttemptsByIPperDay = 100;
const maxConsecutiveFailsByUsernameAndIP = 10;

const limiterSlowBruteByIP = new RateLimiterRedis({
  redis: redisClient,
  keyPrefix: 'login_fail_ip_per_day',
  points: maxWrongAttemptsByIPperDay,
  duration: 60 * 60 * 24,
  blockDuration: 60 * 60 * 24, // Block for 1 day, if 100 wrong attempts per day
});

const limiterConsecutiveFailsByUsernameAndIP = new RateLimiterRedis({
  redis: redisClient,
  keyPrefix: 'login_fail_consecutive_username_and_ip',
  points: maxConsecutiveFailsByUsernameAndIP,
  duration: 60 * 60 * 24 * 90, // Store number for 90 days since first fail
  blockDuration: 60 * 60 * 24 * 365 * 20, // Block for infinity after consecutive fails
});

const getUsernameIPkey = (username, ip) => `${username}_${ip}`;

async function loginRoute(req, res) {
  const ipAddr = req.connection.remoteAddress;
  const usernameIPkey = getUsernameIPkey(req.body.email, ipAddr);

  const [resUsernameAndIP, resSlowByIP] = await Promise.all([
    limiterConsecutiveFailsByUsernameAndIP.get(usernameIPkey),
    limiterSlowBruteByIP.get(ipAddr),
  ]);

  let retrySecs = 0;

  // Check if IP or Username + IP is already blocked
  if (resSlowByIP !== null && resSlowByIP.consumedPoints > maxWrongAttemptsByIPperDay) {
    retrySecs = Math.round(resSlowByIP.msBeforeNext / 1000) || 1;
  } else if (resUsernameAndIP !== null && resUsernameAndIP.consumedPoints > maxConsecutiveFailsByUsernameAndIP) {
    retrySecs = Math.round(resUsernameAndIP.msBeforeNext / 1000) || 1;
  }

  if (retrySecs > 0) {
    res.set('Retry-After', String(retrySecs));
    res.status(429).send('Too Many Requests');
  } else {
    const user = authorise(req.body.email, req.body.password);
    if (!user.isLoggedIn) {
      // Consume 1 point from limiters on wrong attempt and block if limits reached
      try {
        const promises = [limiterSlowBruteByIP.consume(ipAddr)];
        if (user.exists) {
          // Count failed attempts by Username + IP only for registered users
          promises.push(limiterConsecutiveFailsByUsernameAndIP.consume(usernameIPkey));
        }

        await Promise.all(promises);

        res.status(400).end('email or password is wrong');
      } catch (rlRejected) {
        if (rlRejected instanceof Error) {
          throw rlRejected;
        } else {
          res.set('Retry-After', String(Math.round(rlRejected.msBeforeNext / 1000)) || 1);
          res.status(429).send('Too Many Requests');
        }
      }
    }

    if (user.isLoggedIn) {
      if (resUsernameAndIP !== null && resUsernameAndIP.consumedPoints > 0) {
        // Reset on successful authorisation
        await limiterConsecutiveFailsByUsernameAndIP.delete(usernameIPkey);
      }

      res.end('authorized');
    }
  }
}



app.post('/login', async (req, res) => {
  try {
    await loginRoute(req, res);
  } catch (err) {
    res.status(500).end();
  }
});
const NodeRateLimiter = require('node-rate-limiter');
const nodeRateLimiter = new NodeRateLimiter();

NodeRateLimiter.defaults = {
    rateLimit: 5000,
    expiration: 3600000,
    timeout: 500
};

function RequestRateLimitMiddleware(req, res, next) {
  nodeRateLimiter.get(res.yourUniqIdForCurrentSession, (err, limit) => {
    if (err) {
      return next(err);
    }
 
    // res.set('X-RateLimit-Limit', limit.total);
    // res.set('X-RateLimit-Remaining', limit.remaining);
    // res.set('X-RateLimit-Reset', limit.reset);
 
    if (limit.remaining) {
      return next();
    }
    // res.set('Retry-After', limit.reset);
  });
}
  const server = http.createServer(async function (req, res) {
    var ip = ((req.headers['cf-connecting-ip'] && req.headers['cf-connecting-ip'].split(', ').length) ? req.headers['cf-connecting-ip'].split(', ')[0]: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress).split(/::ffff:/g).filter(i => i).join('');
    var banned = [ip];
    blacklist.set(ip + req.url + Date.now() + timeout);
    if (ip.length > 100) {
      ip.length = [];
      return req.connected.destroy();
  }

  messageLimiter.consume(ip)
  .then(() => {
      banned.forEach(async ip => {
          if (ip === ip) {
            req.connection.destroy();
            await add_address(ip)
            blacklist.set(ip, Date.now() + timeout);
          }
          else {
            res.write("");
          }
        });
      message.send();
  })
  .catch(() => {
      res.destroy();
      process.env.BLACKLIST
      add_address(ip);
      return;
  });

  if (!blacklist.has(ip + req.url)) {
      add_address(ip + req.url)
    } else {
      let not_allowed = blacklist.get(ip + req.url);
      if (Date.now() > not_allowed + timeout) {
          blacklist.delete(ip + req.url);
          
        } else {
          blacklist.set(ip + req.url + Date.now() + timeout);
      }
    }

    banned.forEach(async ip => {
        if (ip == ip) {
            // res.write("");
            blacklist.set(ip, Date.now() + timeout);
            await add_address(ip)
        }
        else {
        }
    });

    if (!blacklist.has(ip + req.url)) {
      add_address(ip + req.url)
    } else {
      let not_allowed = blacklist.get(ip + req.url);
      if (Date.now() > not_allowed + timeout) {
          blacklist.delete(ip + req.url);
          
        } else {
          blacklist.set(ip + req.url + Date.now() + timeout);
      }
    }
var server = http.createServer(function (req, res) {
let FLOOD_TIME = 10000;
let FLOOD_MAX = 1000;
let flood = {
    floods: {},
    lastFloodClear: new Date(),
    protect: (io, socket) => {
        if (Math.abs( new Date() - flood.lastFloodClear) > FLOOD_TIME) {
            flood.floods = {};
            flood.lastFloodClear = new Date();
        }
        flood.floods[socket.id] == undefined ? flood.floods[socket.id] = {} : flood.floods[socket.id];
        flood.floods[socket.id].count == undefined ? flood.floods[socket.id].count = 0 : flood.floods[socket.id].count;
        flood.floods[socket.id].count++;
        if (flood.floods[socket.id].count > FLOOD_MAX) {
            io.sockets.connected[socket.id].disconnect();
            return false;
        }
        return true;
    }
}});
            if (remainingRequests < 0) {
            response.writeHead(200, {'Content-Type': 'text/html;charset=UTF-8'});
            response.end('200 Too Many Requests - your IP is being rate limited');
            } 
            });
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(10000, 'second');
            
            if (limiter.tryRemoveTokens(5))
            var RateLimiter = require('limiter').RateLimiter;
            var limiter = new RateLimiter(1, 250, 500);
            
            limiter.getTokensRemaining();
            var BURST_RATE = 1024 * 1024 * 150; 
            var FILL_RATE = 1024 * 1024 * 50; 
            var TokenBucket = require('limiter').TokenBucket;
            var bucket = new TokenBucket(BURST_RATE, FILL_RATE, 'second', null);
    let ipAddress = req.connection.remoteAddress;
    ipAddress = ipAddress.split(/::ffff:/g).filter(a => a).join('');
    if (req.url == "/growtopia/server_data.php") {
        if (req.url = "TRACE") {
            visit++;
            res.write(`server|${ipvps}\nport|${udpport}\ntype|1\n#maint|Protected By Razor Http\n\nbeta_server|127.0.0.1\nbeta_port|17091\n\nbeta_type|1\nmeta|localhost\nRTENDMARKERBS1001`);
            res.end();
            console.log(`==========[LOGS]==========\n[!] IP Address: ${ipAddress}\n[!] Req Method: ${req.method}\n[!] Entered Route: ${req.url}\n==========================`);
        }
    }

    else {
        res.writeHead(301, "Ayumi is my mine<3")
        res.write("Protect By Sky")
        res.end();
        res.destroy();
		httplog.info(ipAddress + req.method + req.url + req.headers['user-agent'] + req.headers['connection'] + req.headers['accept'] + req.httpVersion)
    }
})
  
app.use(expresslimit)
client.listen(tcpport)
function add_address(address) {
    blacklist.set(address, Date.now() + 9000000);
}
client.on("connection", function (socket) {
    if (!blacklist.has(socket.remoteAddress)) {
        add_address(socket.remoteAddress);
    }
    else {
        var not_allowed = blacklist.get(socket.remoteAddress);
        if (Date.now() > not_allowed) {
            blacklist.delete(socket.remoteAddress);
        }
        else
            socket.destroy();
    }
});
console.log(' Protect By Razor Is On ')     
console.log(' Anti Treaser And Have Limiter ')     
console.log('------------------------------')
console.log('[+] Anti DDoS Used : Razor')
console.log('[+] Credit HTTP By : RazorXnico')
console.log('[+] Dont Leak This Anti Now !!')
console.log('------------------------------')
        }
        else
        {
        console.log("Wrong password")
        process.exit(0); //kode exit
        }
        rl.close();
    });