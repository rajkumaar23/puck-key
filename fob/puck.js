// puck-key fob (Puck.js)
// ----------------------
// On a button press, connect to the door receiver, read its fresh 16-byte
// challenge and write back HMAC-SHA256(SECRET, challenge) (full 32 bytes),
// then disconnect. The receiver verifies and unlocks (see receiver/ble_auth.cpp).
//
// Config comes from flash, written once by fob/provision.example.js:
//   cfg.secret : shared secret, must equal SECRET in the receiver's secrets.h
//   cfg.door   : BLE address of the receiver (from its "BLE address:" boot log)
// No clock is needed: the challenge is fresh randomness, not time.
var cfg = require("Storage").readJSON("cfg", true) || {};
var SECRET = cfg.secret;
var DOOR   = cfg.door;

var SERVICE = "f1e2d3c4-0001-4a5b-8c9d-000000000001";
var CHAL    = "f1e2d3c4-0002-4a5b-8c9d-000000000001";  // read:   fob -> receiver, 16-byte fresh challenge
var RESP    = "f1e2d3c4-0003-4a5b-8c9d-000000000001";  // write:  fob -> receiver, 32-byte HMAC response
var CHAL_LEN = 16;    // challenge length in bytes
var RESP_LEN = 32;    // response length in bytes (full HMAC-SHA256)

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

var busy = false, busySince = 0, gatt = null;

// Drop any half-open connection and clear the busy flag.
function cleanup() {
  if (gatt) { try { gatt.disconnect(); } catch (e) {} gatt = null; }
  busy = false;
}

// Button handler: connect, read the challenge, write its HMAC, disconnect.
// Green = response sent, red = connect or protocol failure. A single in-flight
// press at a time; stale locks reset.
function unlock() {
  if (busy && (getTime() - busySince) > 5) cleanup();   // stale lock -> force reset
  if (busy) return;
  busy = true; busySince = getTime();
  digitalWrite(LED2, 1);
  var chalCh = null, respCh = null;
  NRF.connect(DOOR, { minInterval: 7.5, maxInterval: 11.25 }).then(function(g) {
    gatt = g;
    return gatt.getPrimaryService(SERVICE);
  }).then(function(s) {
    // Sequential, not Promise.all: Espruino's GATT client runs one discovery
    // task at a time and rejects a parallel characteristic request
    // ("BLE task CHAR is already in progress").
    return s.getCharacteristic(CHAL).then(function(cc) {
      chalCh = cc;
      return s.getCharacteristic(RESP);
    }).then(function(rc) {
      respCh = rc;
    });
  }).then(function() {
    return chalCh.readValue();
  }).then(function(v) {
    // readValue() resolves with a plain ArrayBuffer on Espruino; accept the
    // ArrayBufferView shape too for robustness.
    var chal = (v instanceof ArrayBuffer)
      ? new Uint8Array(v)
      : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    if (chal.length !== CHAL_LEN) throw "bad challenge length";
    var resp = new Uint8Array(hmacSha256(SECRET, chal));
    if (resp.length !== RESP_LEN) throw "bad response length";
    return respCh.writeValue(resp);
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
