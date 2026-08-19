#include "smartrent.h"
#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include "mbedtls/base64.h"
#include "config.h"
#include "secrets.h"
#include "crypto.h"
#include "notify.h"

static String srToken = "";
static time_t srTokenExp = 0;    // epoch seconds when the current access token expires
static WiFiClientSecure srNet;   // persistent TLS socket, kept warm for fast unlocks

// Browser-ish headers every SmartRent request needs to get past Cloudflare.
static void srCommonHeaders(HTTPClient& http) {
  http.setUserAgent(SR_USER_AGENT);
  http.addHeader("Accept", "application/json");
  http.addHeader("Accept-Language", "en-US;q=1.0");
  http.addHeader("Content-Type", "application/json");
}

// Pull a "key":"value" string field out of a JSON body ("" if absent).
static String extractStr(const String& b, const char* key) {
  String pat = String("\"") + key + "\":\"";
  int k = b.indexOf(pat);
  if (k < 0) return "";
  k += pat.length();
  int e = b.indexOf("\"", k);
  return (e < 0) ? "" : b.substring(k, e);
}

// Pull the "exp" (epoch seconds) claim from a JWT so we know when to refresh it.
static time_t parseJwtExp(const String& jwt) {
  int p1 = jwt.indexOf('.');
  int p2 = jwt.indexOf('.', p1 + 1);
  if (p1 < 0 || p2 < 0) return 0;
  String payload = jwt.substring(p1 + 1, p2);   // middle segment = claims
  payload.replace('-', '+');                     // base64url -> base64
  payload.replace('_', '/');
  while (payload.length() % 4) payload += '=';
  uint8_t buf[1024]; size_t olen = 0;
  if (mbedtls_base64_decode(buf, sizeof(buf) - 1, &olen,
                            (const uint8_t*)payload.c_str(), payload.length()) != 0) return 0;
  buf[olen] = 0;
  const char* p = strstr((const char*)buf, "\"exp\":");
  if (!p) return 0;
  return (time_t)strtoll(p + 6, nullptr, 10);
}

// Complete SmartRent's 2FA step: exchange the tfa_api_token + current TOTP for a token.
static String completeTfa(const String& tfaApiToken) {
  String code = totpNow(SR_TFA_SECRET);
  if (code == "") { Serial.println("[auth] TOTP generation failed (bad seed or clock)"); return ""; }
  Serial.printf("[auth] TOTP=%s  clock=%ld\n", code.c_str(), (long)time(nullptr));
  WiFiClientSecure c; c.setInsecure();
  HTTPClient http;
  if (!http.begin(c, String(SR_BASE_URL) + "/authentication/sessions/tfa")) return "";
  srCommonHeaders(http);
  int status = http.POST(String("{\"tfa_api_token\":\"") + tfaApiToken + "\",\"token\":\"" + code + "\"}");
  String tok = (status == 200 || status == 201) ? extractStr(http.getString(), "access_token") : "";
  http.end();
  Serial.printf("[auth] tfa -> HTTP %d  token=%s\n", status, tok == "" ? "MISSING" : "ok");
  return tok;
}

// Send the unlock command over the warm socket (locked -> false). Returns HTTP code.
static int patchUnlock() {
  bool warm = srNet.connected();
  if (!warm) smartrentPrewarm();          // fall back to a cold handshake if it wasn't warmed
  if (!srNet.connected()) return -1;

  unsigned long a = millis();
  String body = "{\"attributes\":[{\"name\":\"locked\",\"state\":\"false\"}]}";
  // Write straight to the warm TLS socket. "Connection: close" means the server
  // hangs up after replying, so there's no body to drain; the loop's keep-warm
  // reopens the socket a moment later for the next press.
  srNet.print(String("PATCH /api/v3/hubs/") + SR_HUB_ID + "/devices/" + SR_DEVICE_ID + " HTTP/1.1\r\n");
  srNet.print("Host: " SR_HOST "\r\n");
  srNet.print("User-Agent: " SR_USER_AGENT "\r\n");
  srNet.print("Accept: application/json\r\n");
  srNet.print("Content-Type: application/json\r\n");
  srNet.print("X-AppVersion: " SR_APP_VERSION "\r\n");
  srNet.print(String("Authorization: Bearer ") + srToken + "\r\n");
  srNet.print(String("Content-Length: ") + body.length() + "\r\n");
  srNet.print("Connection: close\r\n\r\n");
  srNet.print(body);

  // Parse the HTTP status out of the first response line ("HTTP/1.1 200 OK").
  unsigned long t0 = millis();
  while (srNet.connected() && !srNet.available() && millis() - t0 < 6000) delay(2);
  String line = srNet.readStringUntil('\n');
  int code = -1, sp = line.indexOf(' ');
  if (sp > 0) code = line.substring(sp + 1, sp + 4).toInt();
  srNet.stop();
  Serial.printf("[unlock] PATCH over %s socket -> %lu ms\n", warm ? "warm" : "cold", millis() - a);
  return code;
}

// One-time init: allow TLS to the SmartRent host without cert pinning.
void smartrentBegin() {
  srNet.setInsecure();   // SmartRent TLS without cert pinning
}

// Log in (handling 2FA) and cache the access token and its expiry. True on success.
bool smartrentLogin() {
  WiFiClientSecure c; c.setInsecure();
  HTTPClient http;
  if (!http.begin(c, String(SR_BASE_URL) + "/authentication/sessions")) return false;
  srCommonHeaders(http);
  int code = http.POST(String("{\"email\":\"") + SR_EMAIL + "\",\"password\":\"" + SR_PASS + "\"}");
  String body = (code == 200 || code == 201) ? http.getString() : "";
  http.end();
  Serial.printf("[auth] sessions -> HTTP %d\n", code);

  srToken = extractStr(body, "access_token");           // no 2FA -> token straight away
  if (srToken == "") {                                   // 2FA enabled -> finish with a TOTP code
    String tfa = extractStr(body, "tfa_api_token");
    Serial.printf("[auth] tfa_api_token %s\n", tfa == "" ? "MISSING" : "received");
    if (tfa != "") srToken = completeTfa(tfa);
  }
  srTokenExp = (srToken != "") ? parseJwtExp(srToken) : 0;
  return srToken != "";
}

// Whether a non-empty access token is currently cached.
bool smartrentHasToken() { return srToken != ""; }

// Open the persistent TLS socket if it isn't already (the expensive handshake).
void smartrentPrewarm() {
  if (srNet.connected()) return;
  unsigned long t0 = millis();
  if (srNet.connect(SR_HOST, 443)) Serial.printf("[tls] warmed (%lu ms)\n", millis() - t0);
  else Serial.printf("[tls] warm failed (%lu ms)\n", millis() - t0);
}

// Whether the persistent TLS socket is currently connected.
bool smartrentSocketOpen() { return srNet.connected(); }

// Ensure a token, send the unlock PATCH, and retry once if the token had expired.
int smartrentUnlock() {
  if (srToken == "") smartrentLogin();     // normally kept fresh by the loop; safety net
  int code = patchUnlock();
  if (code == 401) {                        // token expired mid-flight -> refresh and retry once
    Serial.println("[unlock] token expired - refreshing");
    if (smartrentLogin()) code = patchUnlock();
  }
  return code;
}

// Refresh the token ahead of expiry so an unlock never pays a login cost. Frees
// the warm socket first so the login handshake has heap. Call while idle.
void smartrentMaintainToken() {
  static unsigned long lastAttempt = 0;
  time_t now = time(nullptr);
  if (now < 1000000000) return;                                   // wait for NTP to set the clock
  bool needs = (srToken == "") ||
               (srTokenExp > 0 && now >= srTokenExp - TOKEN_REFRESH_MARGIN);
  if (!needs) return;
  if (lastAttempt && millis() - lastAttempt < 10000) return;      // back off on repeated failures
  lastAttempt = millis();
  Serial.printf("[token] refreshing (free heap=%u)\n", ESP.getFreeHeap());
  srNet.stop();   // free the warm socket's TLS memory so the login handshake has room
  if (smartrentLogin()) {
    Serial.printf("[token] refreshed, valid for %ld s\n", (long)(srTokenExp - now));
  } else {
    Serial.println("[token] refresh FAILED");
    notifyAlert("login", "SmartRent login failing",
                "token expired and refresh keeps failing - unlocks will 401 until fixed (creds, TFA seed, Cloudflare?)", 15);
  }
}
