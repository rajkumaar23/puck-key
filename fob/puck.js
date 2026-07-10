// puck-key fob (Puck.js)
// ----------------------
// On a button press, connect to the door receiver and write a time-based rolling
// code: HMAC-SHA256(SECRET, floor(unixtime / STEP)). The receiver recomputes the
// same value and unlocks if it matches (see receiver/ble_auth.cpp).
//
// Config comes from flash, written once by fob/provision.example.js:
//   cfg.secret : shared secret, must equal SECRET in the receiver's secrets.h
//   cfg.door   : BLE address of the receiver (from its "BLE address:" boot log)
// That provisioning step also sets the Puck's clock, which the rolling code needs.
var cfg = require("Storage").readJSON("cfg", true) || {};
var SECRET = cfg.secret;
var DOOR   = cfg.door;

var SERVICE   = "f1e2d3c4-0001-4a5b-8c9d-000000000001";
var RESP_CHAR = "f1e2d3c4-0003-4a5b-8c9d-000000000001";
var STEP = 30;   // seconds per rolling-code window (must match TOTP_STEP on the receiver)

// HMAC-SHA256(keyStr, msgBytes) using the built-in crypto module. Returns a
// 32-byte ArrayBuffer. No external module to install.
function hmacSha256(keyStr, msgBytes) {
  var crypto = require("crypto");
  var BLOCK = 64;
  var key = new Uint8Array(E.toArrayBuffer(keyStr));
  if (key.length > BLOCK) key = new Uint8Array(crypto.SHA256(key.buffer));
  var k = new Uint8Array(BLOCK); k.set(key);            // zero-padded key
  var inner = new Uint8Array(BLOCK + msgBytes.length);
  var opad  = new Uint8Array(BLOCK);
  for (var i = 0; i < BLOCK; i++) {
    inner[i] = k[i] ^ 0x36;                              // ipad
    opad[i]  = k[i] ^ 0x5c;                              // opad
  }
  inner.set(msgBytes, BLOCK);
  var innerHash = new Uint8Array(crypto.SHA256(inner.buffer));
  var outer = new Uint8Array(BLOCK + 32);
  outer.set(opad, 0);
  outer.set(innerHash, BLOCK);
  return crypto.SHA256(outer.buffer);
}

// The current rolling code: HMAC over the 8-byte big-endian time counter.
function rollingCode() {
  var counter = Math.floor(getTime() / STEP);
  var msg = new Uint8Array(8);
  for (var i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  return hmacSha256(SECRET, msg);
}

var busy = false, busySince = 0, gatt = null;

// Drop any half-open connection and clear the busy flag.
function cleanup() {
  if (gatt) { try { gatt.disconnect(); } catch (e) {} gatt = null; }
  busy = false;
}

// Button handler: connect, write the rolling code, disconnect. Green = sent,
// red = connect failed. A single in-flight press at a time; stale locks reset.
function unlock() {
  if (busy && (getTime() - busySince) > 5) cleanup();   // stale lock -> force reset
  if (busy) return;
  busy = true; busySince = getTime();
  digitalWrite(LED2, 1);
  NRF.connect(DOOR, { minInterval: 7.5, maxInterval: 11.25 }).then(function(g) {
    gatt = g;
    return gatt.getPrimaryService(SERVICE);
  }).then(function(s) {
    return s.getCharacteristic(RESP_CHAR);
  }).then(function(rc) {
    return rc.writeValue(rollingCode());
  }).then(function() {
    return gatt.disconnect();
  }).then(function() {
    digitalWrite(LED2, 0); digitalPulse(LED2, 1, 200);
    gatt = null; busy = false;
  }).catch(function(e) {
    digitalWrite(LED2, 0); digitalPulse(LED1, 1, 500);
    print(e);
    cleanup();
  });
}

setWatch(unlock, BTN, { edge: "rising", debounce: 50, repeat: true });
