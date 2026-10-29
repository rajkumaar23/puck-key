#pragma once
// Non-secret, tweakable configuration shared across the receiver modules.
// Anything account- or deployment-specific lives in secrets.h instead.
#include <stdint.h>

// ---- SmartRent cloud API ---------------------------------------------------
#define SR_HOST        "control.smartrent.com"
#define SR_BASE_URL    "https://control.smartrent.com"
#define SR_APP_VERSION "safari-resweb-18.3.0"
// SmartRent sits behind Cloudflare, which 1010-bans non-browser User-Agents.
// Present as Safari so requests aren't blocked.
#define SR_USER_AGENT  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15"
// SmartRent access tokens are short-lived (TTL 900 s), so a refresh is due
// every ~14 min. If logins fail (Cloudflare throttle, transient 5xx), retry
// with exponential backoff instead of hammering the endpoint: 30, 60, 120,
// 240, 480, 900, 900, ... seconds after `failStreak` consecutive failures.
// Repeated fast retries deepen Cloudflare's block and burn heap on TLS
// handshakes; backing off lets temporary bans expire.
#define TOKEN_REFRESH_MARGIN 60    // refresh the access token this many seconds before it expires
#define TOKEN_BACKOFF_BASE   30    // s: first retry delay after a failed login
#define TOKEN_BACKOFF_MAX    900   // s: retry delay ceiling
inline unsigned long tokenBackoffMs(uint32_t failStreak) {
  if (failStreak == 0) return 0;   // first attempt in a cycle is immediate
  unsigned long s = TOKEN_BACKOFF_BASE;
  for (uint32_t i = 1; i < failStreak && s < TOKEN_BACKOFF_MAX; i++) s *= 2;
  return (s > TOKEN_BACKOFF_MAX ? TOKEN_BACKOFF_MAX : s) * 1000UL;
}
// On a TOTP rejection, retry the 2FA step at these clock offsets (seconds).
// Tolerates NTP drift pushing the generated code outside its 30 s window.
#define TOTP_RETRY_OFFSETS { 30, -30 }

// ---- BLE ---------------------------------------------------------------------
// The fob connects by address and discovers this service after connecting, so it
// is deliberately NOT advertised (no name, no service UUID in the ad) to avoid
// telling passive scanners that this device is a door lock.
#define SERVICE_UUID "f1e2d3c4-0001-4a5b-8c9d-000000000001"
#define CHAL_UUID    "f1e2d3c4-0002-4a5b-8c9d-000000000001"  // fob reads the 16-byte challenge here
#define RESP_UUID    "f1e2d3c4-0003-4a5b-8c9d-000000000001"  // fob writes HMAC(SECRET, challenge) here
#define STAT_UUID    "f1e2d3c4-0004-4a5b-8c9d-000000000001"  // fob writes uint16 LE: click->connected ms
#define BLE_STALE_MS 4000  // drop a fob connection that lingers this long without authing

// ---- Uptime heartbeat --------------------------------------------------------
#define HEARTBEAT_INTERVAL 30000  // ms between uptime pushes (keep under 1 minute)

// ---- Prometheus metrics (see metrics.cpp) --------------------------------------
#define METRICS_INTERVAL 60000  // ms between metric pushes to the Pushgateway
