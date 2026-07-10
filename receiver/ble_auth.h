#pragma once
#include <stdint.h>

// Verify a 32-byte rolling code written by the fob:
// HMAC-SHA256(SECRET, floor(unixtime / TOTP_STEP)), checked across +/- TOTP_WINDOW
// windows to tolerate clock skew. Returns false if the clock isn't set yet.
bool bleCodeValid(const uint8_t* code);
