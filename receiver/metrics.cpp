// Prometheus metric push for the receiver (see metrics.h).
//
// Builds a text-exposition body from the shared counters and POSTs it to the
// Pushgateway over plain HTTP (no TLS, LAN IP — same transport style as the
// Uptime Kuma heartbeat, so it never touches the warm SmartRent socket).
// Pushing (instead of exposing /metrics for a scrape) keeps the ESP32 free of
// a listening server and works over the one network direction we know routes:
// VLAN -> LAN. A stale puck_last_push_seconds on the dashboard is itself the
// "device went silent" signal.

#include "metrics.h"
#include "config.h"
#include "secrets.h"    // PUSHGATEWAY_URL (optional; #ifdef'd)
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_system.h>

// ---- Shared counters (declared extern in metrics.h) --------------------------
volatile uint32_t mBleSessions, mBleAuthOk, mBleAuthFail, mBleBadLen, mStaleKicks;
volatile int      mLastDiscReason;
volatile uint32_t mUnlockTotal, mUnlockOk, mUnlockFail, mUnlockWarm, mUnlockCold, mUnlockLastMs;
volatile uint32_t mE2eLastMs, mE2eMaxMs, mClickToConnectMs = 0xFFFF;
volatile uint32_t mLogins, mLoginFails;
volatile int      mSessionsStatus, mTfaStatus;
volatile time_t   mLastLoginOk, mTokenExp;
volatile uint32_t mBackoffS;
volatile uint32_t mTlsWarms, mTlsFails, mTlsLastMs;

#ifdef PUSHGATEWAY_URL

// Append "name{labels} value\n" (or "name value\n" with labels == nullptr).
static void line(String& b, const char* name, const char* labels, long long v) {
  b += name;
  if (labels && labels[0]) { b += '{'; b += labels; b += '}'; }
  b += ' '; b += String(v); b += '\n';
}

void metricsPush() {
  time_t now = time(nullptr);
  String b;
  b.reserve(1400);

  line(b, "puck_up", nullptr, 1);
  line(b, "puck_uptime_seconds", nullptr, millis() / 1000);
  line(b, "puck_free_heap_bytes", nullptr, ESP.getFreeHeap());
  line(b, "puck_min_free_heap_bytes", nullptr, ESP.getMinFreeHeap());
  line(b, "puck_wifi_rssi_dbm", nullptr, WiFi.RSSI());
  line(b, "puck_clock_synced", nullptr, now > 1000000000 ? 1 : 0);

  line(b, "puck_ble_sessions_total", nullptr, mBleSessions);
  line(b, "puck_ble_auth_ok_total", nullptr, mBleAuthOk);
  line(b, "puck_ble_auth_fail_total", nullptr, mBleAuthFail);
  line(b, "puck_ble_bad_len_total", nullptr, mBleBadLen);
  line(b, "puck_ble_stale_kicks_total", nullptr, mStaleKicks);
  line(b, "puck_ble_last_disconnect_reason", nullptr, mLastDiscReason);

  line(b, "puck_unlock_total", "result=\"ok\"", mUnlockOk);
  line(b, "puck_unlock_total", "result=\"fail\"", mUnlockFail);
  line(b, "puck_unlock_socket_total", "state=\"warm\"", mUnlockWarm);
  line(b, "puck_unlock_socket_total", "state=\"cold\"", mUnlockCold);
  line(b, "puck_unlock_last_ms", nullptr, mUnlockLastMs);
  line(b, "puck_unlock_e2e_last_ms", nullptr, mE2eLastMs);
  line(b, "puck_unlock_e2e_max_ms", nullptr, mE2eMaxMs);

  line(b, "puck_sr_logins_total", nullptr, mLogins);
  line(b, "puck_sr_login_failures_total", nullptr, mLoginFails);
  line(b, "puck_sr_login_last_sessions_status", nullptr, mSessionsStatus);
  line(b, "puck_sr_login_last_tfa_status", nullptr, mTfaStatus);
  line(b, "puck_sr_last_login_ok_seconds", nullptr, mLastLoginOk);
  line(b, "puck_sr_token_expiry_seconds", nullptr, mTokenExp);
  line(b, "puck_sr_refresh_backoff_seconds", nullptr, mBackoffS);

  line(b, "puck_tls_warms_total", nullptr, mTlsWarms);
  line(b, "puck_tls_fails_total", nullptr, mTlsFails);
  line(b, "puck_tls_last_handshake_ms", nullptr, mTlsLastMs);

  WiFiClient c; HTTPClient http;
  http.setConnectTimeout(3000);
  String url = String(PUSHGATEWAY_URL) + "/metrics/job/puck-key/instance/qt-py-esp32";
  if (!http.begin(c, url)) { http.end(); Serial.println("[metrics] push skipped (http begin)"); return; }
  http.addHeader("Content-Type", "text/plain; version=0.0.4");
  int code = http.POST(b);
  http.end();
  Serial.printf("[metrics] push -> HTTP %d (%u B, heap=%u)\n", code, b.length(), ESP.getFreeHeap());
}

#else
void metricsPush() {}   // PUSHGATEWAY_URL not defined: metrics disabled
#endif
