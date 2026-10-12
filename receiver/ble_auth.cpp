#include "ble_auth.h"
#include "auth_core.h"
#include "crypto.h"        // hmacSha256 (mbedTLS) — used by auth_core via the shim below
#include "secrets.h"
#include "esp_system.h"    // esp_fill_random

// auth_core.h expects a platform-provided HMAC-SHA256; on the ESP32 that's
// crypto.cpp's mbedTLS wrapper.
namespace authcore {
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  ::hmacSha256(key, keyLen, msg, msgLen, out);
}
}

static const size_t SECRET_LEN = sizeof(SECRET) - 1;   // drop trailing null
static authcore::ChallengeAuth g_auth;

// Fresh 16 random bytes from the ESP32 hardware TRNG, single-use from here on.
void bleAuthArm() {
  uint8_t chal[authcore::CHAL_LEN];
  esp_fill_random(chal, sizeof(chal));   // void return: no failure status to check
  g_auth.arm(chal);
}

const uint8_t* bleAuthChallenge() {
  return g_auth.isArmed() ? g_auth.challenge() : nullptr;
}

bool bleAuthVerify(const uint8_t* resp, size_t len) {
  return g_auth.verify((const uint8_t*)SECRET, SECRET_LEN, resp, len) ==
         authcore::Result::Ok;
}

void bleAuthClear() { g_auth.clear(); }
