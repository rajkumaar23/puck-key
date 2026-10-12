#pragma once
// auth_core.h — platform-independent core of the BLE challenge-response auth
// (see ble_auth.h / ble_auth.cpp for the Arduino/GATT layer).
//
// The fob proves knowledge of the shared secret without either clock mattering:
// the receiver arms a fresh random 16-byte challenge per connection, the fob
// answers with HMAC-SHA256(SECRET, challenge), the receiver recomputes and
// unlocks on a match. Everything that is *logic* lives here so it can be unit
// tested on a host (g++/clang) with no Arduino, WiFi, or ESP32 runtime:
//   - constant-time 32-byte compare
//   - the per-connection auth state machine: single-use challenge arming,
//     response verification (consumed right or wrong), unlock latch
//
// The Arduino layer supplies the challenge bytes from the ESP32 TRNG and the
// SECRET define from secrets.h; the host test supplies both as plain data.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace authcore {

constexpr size_t CHAL_LEN = 16;   // random bytes per challenge
constexpr size_t RESP_LEN = 32;   // HMAC-SHA256 output length

// Provided by the platform layer: receiver/crypto.cpp (mbedTLS) when built
// for ESP32, a SHA-256-based implementation in test/auth_core_test.cpp on the
// host. Same signature as crypto.h's helper.
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen, uint8_t out[32]);

// Constant-time compare of two 32-byte buffers: accumulates the difference
// over all bytes so timing does not leak how much of a guess matched.
inline bool constTimeEq32(const uint8_t* a, const uint8_t* b) {
  uint8_t diff = 0;
  for (size_t i = 0; i < RESP_LEN; i++) diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
  return diff == 0;
}

enum class Result : uint8_t { Ok, Length, NoChallenge, Mismatch };

// Per-connection authentication state machine. Exactly one outstanding
// challenge at a time:
//   - arm()   installs fresh random bytes, superseding anything before it
//   - verify() checks a response and ALWAYS consumes the outstanding
//             challenge — a second response is rejected even if it was
//             correct for the one just consumed
// The Arduino layer arms from the CHAL characteristic's NimBLE onRead callback
// (which runs before the ATT read response sends the value, so each read gets
// fresh bytes) and clears on GAP disconnect.
class ChallengeAuth {
 public:
  // Install a fresh challenge; the caller must publish these bytes on the
  // CHAL characteristic so the fob can read them.
  void arm(const uint8_t challenge[CHAL_LEN]) {
    std::memcpy(challenge_, challenge, CHAL_LEN);
    armed_ = true;
    unlocked_ = false;
  }

  // Forget everything (connection closed): nothing armed, nothing unlocked.
  void clear() {
    std::memset(challenge_, 0, sizeof(challenge_));
    armed_ = false;
    unlocked_ = false;
  }

  bool isArmed() const { return armed_; }
  // Valid while armed; the value the fob must hash.
  const uint8_t* challenge() const { return challenge_; }

  // Verify a fob response against the outstanding challenge using the shared
  // secret. Ok on a full-32-byte match; the challenge is consumed either way
  // (except on a wrong length, which says nothing about the challenge and is
  // just rejected). Sets the unlock latch on Ok.
  Result verify(const uint8_t* secret, size_t secretLen,
                const uint8_t* resp, size_t respLen) {
    if (respLen != RESP_LEN) return Result::Length;
    if (!armed_) return Result::NoChallenge;
    uint8_t expected[RESP_LEN];
    hmacSha256(secret, secretLen, challenge_, CHAL_LEN, expected);
    bool ok = constTimeEq32(expected, resp);
    armed_ = false;                       // single-use, right or wrong
    std::memset(expected, 0, sizeof(expected));
    if (ok) unlocked_ = true;
    return ok ? Result::Ok : Result::Mismatch;
  }

  // True after a verified response until the unlock request is taken.
  bool unlocked() const { return unlocked_; }
  void consumeUnlock() { unlocked_ = false; }

 private:
  uint8_t challenge_[CHAL_LEN] = {0};
  bool armed_ = false;
  bool unlocked_ = false;
};

}  // namespace authcore
