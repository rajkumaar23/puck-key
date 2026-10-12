// auth_sim.js — protocol simulator for the puck-key challenge/response flow.
//
// Loads fob/puck.js into a vm sandbox with mocked Espruino globals and runs it
// against a fake BLE receiver written to the same contract:
//   CHAL 0002: READ, receiver hands out a fresh 16-byte challenge per read
//   RESP 0003: WRITE, fob sends the full 32-byte HMAC-SHA256(SECRET, challenge)
// Response is single-use: the first write (right or wrong) consumes the armed
// challenge; wrong length, replay, stale and nothing-armed writes are rejected.
//
// Run from anywhere:  node test/auth_sim.js

var fs = require("fs");
var path = require("path");
var vm = require("vm");
var nodeCrypto = require("crypto");

var ROOT = path.resolve(__dirname, "..");
var PUCK_PATH = path.join(ROOT, "fob", "puck.js");

var SERVICE = "f1e2d3c4-0001-4a5b-8c9d-000000000001";
var CHAL    = "f1e2d3c4-0002-4a5b-8c9d-000000000001";
var RESP    = "f1e2d3c4-0003-4a5b-8c9d-000000000001";

var SECRET = "test-secret-do-not-use-in-production";
var WRONG_SECRET = "totally-wrong-secret-key";

// Simulated link latencies in ms.
var L = { connect: 70, discover: 40, op: 15, verify: 1 };

var failures = [];
function check(name, cond, detail) {
  if (cond) {
    console.log("  PASS  " + name);
  } else {
    console.log("  FAIL  " + name + (detail ? " — " + detail : ""));
    failures.push(name);
  }
}

function bytesToHex(u8) {
  return Array.prototype.map.call(u8, function (b) {
    return ("0" + b.toString(16)).slice(-2);
  }).join("");
}
function hexToBytes(hex) {
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function ctEq(a, b) {
  if (a.length !== b.length) return false;
  return nodeCrypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------------------
// Fake receiver: models the GATT server with per-op latency and single-use
// challenge semantics.
// ---------------------------------------------------------------------------
function Receiver(secret) {
  this.secret = secret;
  this.unlocks = 0;
  this.rejects = { length: 0, stale: 0, nothingArmed: 0, mismatch: 0 };
  this.lastError = null;
}

Receiver.prototype.connect = function () {
  var self = this;
  var conn = {
    _armed: null,       // current single-use challenge (Uint8Array) or null
    _everArmed: false,  // was anything ever armed on this connection
    disconnected: false,
    disconnects: 0,
    lastWrite: null,
    writeRejected: false
  };
  conn.readChallenge = function () {
    if (conn.disconnected) return Promise.reject(new Error("disconnected"));
    return delay(L.op, function () {
      // fresh random challenge per read, supersedes any outstanding one
      conn._armed = new Uint8Array(nodeCrypto.randomBytes(16));
      conn._everArmed = true;
      // Espruino's readValue() resolves with a plain ArrayBuffer, not a view.
      return conn._armed.buffer;
    });
  };
  conn.writeResponse = function (view) {
    if (conn.disconnected) return Promise.reject(new Error("disconnected"));
    return delay(L.op, function () {
      self.lastError = null;
      var got = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      if (got.length !== 32) {
        self.rejects.length++; self.lastError = "bad length " + got.length;
        conn.writeRejected = true;
        throw new Error("write rejected: bad length");
      }
      if (!conn._armed) {
        self.rejects[conn._everArmed ? "stale" : "nothingArmed"]++;
        self.lastError = conn._armed ? "consumed" : "nothing armed";
        conn.writeRejected = true;
        throw new Error("write rejected: no armed challenge");
      }
      var expected = new Uint8Array(
        nodeCrypto.createHmac("sha256", self.secret).update(conn._armed).digest());
      // response arrives: the armed challenge is consumed either way
      var armed = conn._armed;
      conn._armed = null;
      return delay(L.verify, function () {
        if (!ctEq(got, expected)) {
          self.rejects.mismatch++; self.lastError = "hmac mismatch";
          conn.writeRejected = true;
          throw new Error("write rejected: auth failed");
        }
        self.unlocks++;
        conn.lastWrite = { challenge: armed, response: got, receivedAt: Date.now() };
        conn.writeRejected = false;
        return undefined;
      });
    });
  };
  conn.disconnect = function () {
    return delay(L.op, function () {
      conn.disconnects++;
      conn.disconnected = true;
      conn._armed = null;
    });
  };
  return delay(L.connect, function () { return conn; });
};

Receiver.prototype.getPrimaryService = function (uuid) {
  var self = this;
  if (uuid !== SERVICE) return delay(L.discover, function () { throw new Error("no service"); });
  return delay(L.discover, function () {
    return {
      // Espruino runs one GATT discovery task at a time: a parallel
      // getCharacteristic() rejects with 'BLE task CHAR is already in
      // progress'. Enforce that here so the sim can never bless a parallel
      // discovery design the hardware would reject.
      getCharacteristic: function (cuuid) {
        if (self._conn._charBusy) {
          return delay(1, function () {
            throw new Error("BLE task CHAR is already in progress");
          });
        }
        self._conn._charBusy = true;
        var done = function () { self._conn._charBusy = false; };
        var inner;
        if (cuuid !== CHAL && cuuid !== RESP) {
          inner = delay(L.op, function () { throw new Error("no char"); });
        } else {
          inner = delay(L.op, function () {
            return {
              uuid: cuuid,
              readValue: function () {
                if (cuuid !== CHAL) return delay(L.op, function () { throw new Error("not readable"); });
                return self._conn.readChallenge();
              },
              writeValue: function (v) {
                if (cuuid !== RESP) return delay(L.op, function () { throw new Error("not writable"); });
                return self._conn.writeResponse(v);
              }
            };
          });
        }
        return inner.then(function (r) { done(); return r; },
                          function (e) { done(); throw e; });
      }
    };
  });
};


// Espruino readValue() resolves with a plain ArrayBuffer; accept both shapes.
function toU8(v) {
  return (v instanceof ArrayBuffer)
    ? new Uint8Array(v)
    : toU8(v);
}

function delay(ms, fn) {
  return new Promise(function (res, rej) {
    setTimeout(function () {
      try { res(fn()); } catch (e) { rej(e); }
    }, ms);
  });
}

// ---------------------------------------------------------------------------
// Espruino sandbox: runs puck.js source with mocked globals and records LED
// events. A fresh sandbox per secret; shared receiver drives the connection.
// ---------------------------------------------------------------------------
function makeFob(secret, receiver) {
  var fob = {
    ledEvents: [],
    prints: [],
    unlockFn: null,
    receiver: receiver
  };

  var storageMod = {
    readJSON: function () { return { secret: secret, door: "aa:bb:cc:dd:ee:ff public" }; }
  };
  var cryptoMod = {
    SHA256: function (data) {
      var buf = data instanceof ArrayBuffer ? Buffer.from(new Uint8Array(data)) : Buffer.from(data);
      return new Uint8Array(nodeCrypto.createHash("sha256").update(buf).digest()).buffer;
    }
  };
  function req(name) {
    if (name === "Storage") return storageMod;
    if (name === "crypto") return cryptoMod;
    throw new Error("unknown module " + name);
  }

  var ledOn = false;
  var ctx = {
    require: function (name) { return req(name); },
    __req: req,
    E: {
      // Espruino strings are byte strings: each char code is one byte.
      toArrayBuffer: function (s) {
        s = String(s);
        var b = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
        return b.buffer;
      }
    },
    crypto: cryptoMod,
    Storage: storageMod,
    getTime: function () { return Date.now() / 1000; },
    setTimeout: function () { return setTimeout.apply(null, arguments); },
    clearTimeout: function () { return clearTimeout.apply(null, arguments); },
    Math: Math, Date: Date, JSON: JSON, Promise: Promise,
    Uint8Array: Uint8Array, ArrayBuffer: ArrayBuffer, DataView: DataView,
    print: function () {
      fob.prints.push(Array.prototype.slice.call(arguments).join(" "));
    },
    LED1: 1, LED2: 2, BTN: 3,
    digitalWrite: function (pin, v) {
      if (pin === 2) { ledOn = !!v; fob.ledEvents.push({ t: "set2", v: v ? 1 : 0 }); }
    },
    digitalPulse: function (pin, reps, ms) {
      fob.ledEvents.push({ t: "pulse", pin: pin, ms: ms });
    },
    setWatch: function (fn, btn, opts) { fob.unlockFn = fn; },
    NRF: {
      connect: function (addr, opts) {
        return receiver.connect().then(function (conn) {
          receiver._conn = conn;
          return {
            getPrimaryService: function (uuid) { return receiver.getPrimaryService(uuid); },
            disconnect: function () { return conn.disconnect(); }
          };
        });
      }
    }
  };
  ctx.global = ctx;
  vm.createContext(ctx);

  var src = fs.readFileSync(PUCK_PATH, "utf8");
  // Test hook only: expose hmacSha256 for the RFC 4231 parity check.
  vm.runInContext(src + "\n;globalThis.__hmac = hmacSha256;\n", ctx, { filename: "fob/puck.js" });
  fob.hmac = ctx.__hmac;
  fob.greenSuccess = function () {
    return fob.ledEvents.some(function (e) { return e.t === "pulse" && e.pin === 2 && e.ms === 200; });
  };
  fob.redFail = function () {
    return fob.ledEvents.some(function (e) { return e.t === "pulse" && e.pin === 1 && e.ms === 500; });
  };
  return fob;
}

// Run one button press; resolves when the fob settles. Returns latency from
// press until the response write reached the receiver, plus LED state.
function press(fob) {
  var t0 = Date.now();
  var before = fob.receiver.unlocks;
  fob.receiver._conn = null;                 // don't mistake a previous conn for this press
  fob.unlockFn();
  function poll() {
    return new Promise(function (res) { setTimeout(res, 5); }).then(function () {
      var idle = fob.receiver._conn && (fob.receiver._conn.disconnected || fob.receiver._conn.writeRejected);
      if (idle) return true;
      if (Date.now() - t0 > 5000) return true;
      return poll();
    });
  }
  return poll().then(function () {
    return new Promise(function (res) { setTimeout(res, 30); });
  }).then(function () {
    var conn = fob.receiver._conn;
    return {
      latency: conn && conn.lastWrite && conn.lastWrite.receivedAt ? conn.lastWrite.receivedAt - t0 : null,
      unlocked: fob.receiver.unlocks > before,
      green: fob.greenSuccess(),
      red: fob.redFail(),
      conn: conn
    };
  });
}

// ---------------------------------------------------------------------------
// Session 1: 30 happy paths.
// ---------------------------------------------------------------------------
function percentile(sorted, p) {
  var idx = Math.ceil(p * sorted.length) - 1;
  if (idx < 0) idx = 0;
  if (idx >= sorted.length) idx = sorted.length - 1;
  return sorted[idx];
}

function runHappyPaths(n) {
  var latencies = [];
  var receiver = new Receiver(SECRET);
  var fob = makeFob(SECRET, receiver);
  var chain = Promise.resolve();
  for (var i = 0; i < n; i++) {
    chain = chain.then(function () {
      return press(fob).then(function (r) {
        latencies.push(r.latency);
        if (!r.unlocked || !r.green || r.red || r.conn.disconnects !== 1) {
          failures.push("happy path session (unlock=" + r.unlocked + " green=" + r.green +
            " red=" + r.red + " disconnects=" + r.conn.disconnects + ")");
        }
      });
    });
  }
  return chain.then(function () {
    console.log("\n[1] " + n + " happy-path sessions");
    check("all " + n + " sessions unlocked with clean disconnect", failures.length === 0,
      failures.length ? failures.join("; ") : "");
    var sorted = latencies.slice().sort(function (a, b) { return a - b; });
    var p50 = percentile(sorted, 0.5), p95 = percentile(sorted, 0.95);
    console.log("      latency p50=" + p50 + " ms  p95=" + p95 + " ms (n=" + latencies.length + ")");
    check("press-to-response p95 < 250 ms", p95 < 250, "p95=" + p95);
    return { receiver: receiver, p50: p50, p95: p95, last: fob };
  });
}

// ---------------------------------------------------------------------------
// Session 2: adversarial cases, none may unlock.
// ---------------------------------------------------------------------------
function fresh(receiver, secret) {
  var fob = makeFob(secret || SECRET, receiver);
  return fob;
}

// Drive the receiver directly at GATT level (client-side attacker).
function rawSession(receiver) {
  return receiver.connect().then(function (conn) {
    receiver._conn = conn;
    return conn;
  });
}

function runAdversarial(happy) {
  console.log("\n[2] adversarial sessions");
  var baseUnlocks = happy.receiver.unlocks;
  var chain = Promise.resolve();
  var results = {};

  // a) wrong-secret fob through the real fob code
  chain = chain.then(function () {
    var r = new Receiver(SECRET);
    var fob = fresh(r, WRONG_SECRET);
    return press(fob).then(function (res) {
      results.wrongSecret = res.unlocked === false && res.red === true && res.green === false &&
        r.rejects.mismatch === 1;
      check("wrong-secret fob rejected, red LED", results.wrongSecret);
    });
  });

  // b) replay of a previous connection's valid response
  chain = chain.then(function () {
    var prior = happy.last.receiver._conn.lastWrite;
    var r = new Receiver(SECRET);
    return rawSession(r).then(function (conn) {
      return conn.readChallenge().then(function () {
        return conn.writeResponse(new DataView(prior.response.buffer.slice(0)));
      }).then(function () {
        results.replay = false;
      }, function () {
        results.replay = r.rejects.mismatch === 1;
        return conn.disconnect();
      });
    }).then(function () {
      check("replayed response from a previous connection rejected", results.replay);
    });
  });

  // c) response for a stale (superseded) challenge
  chain = chain.then(function () {
    var r = new Receiver(SECRET);
    var c1, c2, resp1;
    return rawSession(r).then(function (conn) {
      return conn.readChallenge().then(function (v) {
        c1 = toU8(v);
        resp1 = new Uint8Array(nodeCrypto.createHmac("sha256", SECRET).update(c1).digest());
        return conn.readChallenge();
      }).then(function (v) {
        c2 = toU8(v);
        check("second read supersedes: challenges differ", !ctEq(c1, c2));
        return conn.writeResponse(new DataView(resp1.buffer));
      }).then(function () {
        results.stale = false;
      }, function () {
        results.stale = r.rejects.mismatch === 1;
        return conn.disconnect();
      });
    }).then(function () {
      check("response to superseded challenge rejected", results.stale);
    });
  });

  // d) second write after a correct one (challenge consumed)
  chain = chain.then(function () {
    var r = new Receiver(SECRET);
    var ch;
    return rawSession(r).then(function (conn) {
      return conn.readChallenge().then(function (v) {
        ch = toU8(v);
        return conn;
      });
    }).then(function (conn) {
      var good = new Uint8Array(nodeCrypto.createHmac("sha256", SECRET).update(ch).digest());
      return conn.writeResponse(new DataView(good.buffer.slice(0))).then(function () {
        return conn.writeResponse(new DataView(good.buffer.slice(0))).then(function () {
          results.double = false;
        }, function () {
          // retrying the correct response now that it is consumed must fail
          return conn.writeResponse(new DataView(good.buffer.slice(0))).then(function () {
            results.double = false;
          }, function () {
            results.double = r.unlocks === 1 && r.rejects.stale === 2;
          });
        });
      });
    }).then(function () {
      check("second write after correct one rejected (challenge consumed)", results.double);
    });
  });

  // e/f) wrong-length writes: 16 and 33 bytes
  [16, 33].forEach(function (len) {
    chain = chain.then(function () {
      var r = new Receiver(SECRET);
      return rawSession(r).then(function (conn) {
        return conn.writeResponse(new DataView(new Uint8Array(len).buffer)).then(function () {
          results["len" + len] = false;
        }, function () {
          results["len" + len] = r.rejects.length === 1;
          return conn.disconnect();
        });
      }).then(function () {
        check(len + "-byte response rejected (no armed challenge, bad length)", results["len" + len]);
      });
    });
  });

  // g) write with nothing armed on a fresh connection
  chain = chain.then(function () {
    var r = new Receiver(SECRET);
    return rawSession(r).then(function (conn) {
      var mac = new Uint8Array(nodeCrypto.createHmac("sha256", SECRET).update(new Uint8Array(16)).digest());
      return conn.writeResponse(new DataView(mac.buffer)).then(function () {
        results.nothingArmed = false;
      }, function () {
        results.nothingArmed = r.rejects.nothingArmed === 1;
        return conn.disconnect();
      });
    }).then(function () {
      check("write with nothing armed rejected", results.nothingArmed);
    });
  });

  return chain.then(function () {
    check("no adversarial session unlocked", happy.receiver.unlocks === baseUnlocks);
  });
}

// ---------------------------------------------------------------------------
// Session 3: HMAC parity vs Node crypto (RFC 4231 vectors + >64-byte key).
// ---------------------------------------------------------------------------
function runHmacParity() {
  console.log("\n[3] HMAC-SHA256 parity vs Node crypto");
  var fob = makeFob(SECRET, new Receiver(SECRET));
  var vecs = [
    { name: "RFC4231 TC1 (20-byte key)", key: new Uint8Array(20).fill(0x0b),
      msg: Buffer.from("Hi There", "utf8") },
    { name: "RFC4231 TC2 (string key)", key: Buffer.from("Jefe", "utf8"),
      msg: Buffer.from("what do ya want for nothing?", "utf8") },
    { name: "RFC4231 TC3 (repeated key/msg)", key: new Uint8Array(20).fill(0xaa),
      msg: new Uint8Array(50).fill(0xdd) },
    { name: "RFC4231 TC6 key >64 bytes", key: new Uint8Array(131).fill(0xaa),
      msg: Buffer.from("Test using a Large Test Key and a Short Data", "utf8") }
  ];
  vecs.forEach(function (v) {
    // puck.js takes the key as a string; byte-per-byte via String.fromCharCode
    // (matches Espruino byte-string semantics in the E.toArrayBuffer mock).
    var keyStr = String.fromCharCode.apply(null, Array.prototype.slice.call(v.key));
    var keyBuf = Buffer.from(v.key);
    var got = new Uint8Array(fob.hmac(keyStr, v.msg));
    var want = new Uint8Array(nodeCrypto.createHmac("sha256", keyBuf).update(v.msg).digest());
    check(v.name, ctEq(got, want), "got " + bytesToHex(got) + " want " + bytesToHex(want));
  });
  // long string key via hex form as well (exercises the >64-byte hash path)
  var hexKey = bytesToHex(new Uint8Array(131).fill(0xaa));
  var msg = new Uint8Array(100).fill(0xcd);
  var got = new Uint8Array(fob.hmac(hexKey, msg));
  var want = new Uint8Array(nodeCrypto.createHmac("sha256", hexKey).update(msg).digest());
  check("hex string key >64 bytes", ctEq(got, want));
}

// ---------------------------------------------------------------------------
function main() {
  console.log("puck-key auth sim — read-based challenge, full 32-byte response");
  return runHappyPaths(30)
    .then(function (happy) { return runAdversarial(happy); })
    .then(function () { runHmacParity(); })
    .then(function () {
      console.log("");
      if (failures.length) {
        console.log("FAIL — " + failures.length + " assertion(s) failed:");
        failures.forEach(function (f) { console.log("  - " + f); });
        process.exit(1);
      }
      console.log("PASS — all assertions passed");
      process.exit(0);
    }, function (e) {
      console.log("FAIL — unexpected error: " + (e && e.stack || e));
      process.exit(1);
    });
}

main();
