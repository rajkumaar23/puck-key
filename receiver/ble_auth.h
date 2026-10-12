#pragma once
#include <stddef.h>
#include <stdint.h>

// BLE challenge-response auth (receiver side). The fob reads a fresh random
// 16-byte challenge off the CHAL characteristic and writes back
// HMAC-SHA256(SECRET, challenge); a match unlocks. No clocks involved.
// The logic lives in auth_core.h (host-tested); this layer adds the ESP32
// TRNG and the SECRET from secrets.h.

// Arm a fresh challenge (call from the CHAL characteristic's onRead callback:
// NimBLE sends the attribute value AFTER onRead runs, so the read response
// carries these exact bytes). Each call supersedes the previous challenge.
void bleAuthArm();

// The armed challenge bytes to publish on the CHAL characteristic (valid
// until the next arm/clear). Returns nullptr when nothing is armed.
const uint8_t* bleAuthChallenge();

// Verify a write to the RESP characteristic against the outstanding
// challenge. Returns true on a full-match (the challenge is consumed either
// way; a second response is always rejected).
bool bleAuthVerify(const uint8_t* resp, size_t len);

// Forget the outstanding challenge (call from the GAP disconnect callback).
void bleAuthClear();
