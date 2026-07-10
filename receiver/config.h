#pragma once
// Non-secret, tweakable configuration shared across the receiver modules.
// Anything account- or deployment-specific lives in secrets.h instead.

// ---- SmartRent cloud API ---------------------------------------------------
#define SR_HOST        "control.smartrent.com"
#define SR_BASE_URL    "https://control.smartrent.com"
#define SR_APP_VERSION "safari-resweb-18.3.0"
// SmartRent sits behind Cloudflare, which 1010-bans non-browser User-Agents.
// Present as Safari so requests aren't blocked.
#define SR_USER_AGENT  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15"
#define TOKEN_REFRESH_MARGIN 60   // refresh the access token this many seconds before it expires

// ---- BLE ---------------------------------------------------------------------
// The fob connects by address and discovers this service after connecting, so it
// is deliberately NOT advertised (no name, no service UUID in the ad) to avoid
// telling passive scanners that this device is a door lock.
#define SERVICE_UUID "f1e2d3c4-0001-4a5b-8c9d-000000000001"
#define RESP_UUID    "f1e2d3c4-0003-4a5b-8c9d-000000000001"  // fob writes the rolling code here
#define TOTP_STEP     30   // seconds per rolling-code window (MUST match the fob's STEP)
#define TOTP_WINDOW    1   // also accept +/- this many windows (fob<->ESP32 clock skew)
#define BLE_STALE_MS 4000  // drop a fob connection that lingers this long without authing

// ---- Uptime heartbeat --------------------------------------------------------
#define HEARTBEAT_INTERVAL 30000  // ms between uptime pushes (keep under 1 minute)
