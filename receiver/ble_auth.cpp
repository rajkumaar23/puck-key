#include "ble_auth.h"
#include <Arduino.h>
#include <time.h>
#include <string.h>
#include "crypto.h"
#include "config.h"
#include "secrets.h"

static const size_t SECRET_LEN = sizeof(SECRET) - 1;   // drop trailing null

// Recompute the expected rolling code for the current time window (and +/- WINDOW
// for clock skew) and constant-length-compare it against what the fob wrote.
bool bleCodeValid(const uint8_t* code) {
  time_t now = time(nullptr);
  if (now < 1000000000) return false;                  // no valid clock yet -> can't verify
  uint64_t base = (uint64_t)(now / TOTP_STEP);
  for (int w = -TOTP_WINDOW; w <= TOTP_WINDOW; w++) {
    uint8_t msg[8]; counterBytes(base + w, msg);
    uint8_t expected[32];
    hmacSha256((const uint8_t*)SECRET, SECRET_LEN, msg, 8, expected);
    if (memcmp(expected, code, 32) == 0) return true;
  }
  return false;
}
