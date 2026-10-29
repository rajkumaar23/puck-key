#pragma once
// Prometheus metrics for the receiver: counters incremented from the BLE
// callbacks and the SmartRent client, pushed as text exposition to a
// Pushgateway (see metrics.cpp). All counters are volatile 32-bit so they can
// be bumped from NimBLE task context and read from loop() without a lock.
#include <Arduino.h>
#include <time.h>

// ---- BLE (receiver.ino callbacks) -------------------------------------------
extern volatile uint32_t mBleSessions;      // fob connections
extern volatile uint32_t mBleAuthOk;        // challenge-response verified
extern volatile uint32_t mBleAuthFail;      // wrong response for an armed challenge
extern volatile uint32_t mBleBadLen;        // write with an unexpected length
extern volatile uint32_t mStaleKicks;       // connections dropped by the stale watchdog
extern volatile int      mLastDiscReason;   // last BLE disconnect reason code

// ---- Unlock (smartrent.cpp) ----------------------------------------------------
extern volatile uint32_t mUnlockTotal, mUnlockOk, mUnlockFail;
extern volatile uint32_t mUnlockWarm, mUnlockCold;   // PATCH over warm vs cold socket
extern volatile uint32_t mUnlockLastMs;              // duration of the last PATCH
extern volatile uint32_t mE2eLastMs, mE2eMaxMs;      // click->unlock (fob delta + receiver span)
extern volatile uint32_t mClickToConnectMs;          // last fob-reported click->connected (0xFFFF = none)

// ---- Login / token (smartrent.cpp) ----------------------------------------------
extern volatile uint32_t mLogins, mLoginFails;
extern volatile int      mSessionsStatus;   // HTTP code of the last POST /authentication/sessions
extern volatile int      mTfaStatus;        // HTTP code of the last POST /authentication/sessions/tfa
extern volatile time_t   mLastLoginOk;      // epoch of the last successful login (0 = never)
extern volatile time_t   mTokenExp;         // epoch when the cached token expires
extern volatile uint32_t mBackoffS;         // current refresh backoff (0 = healthy)

// ---- TLS keep-warm (smartrent.cpp) ------------------------------------------------
extern volatile uint32_t mTlsWarms;         // successful TLS handshakes on the warm socket
extern volatile uint32_t mTlsFails;         // failed TLS handshakes
extern volatile uint32_t mTlsLastMs;        // duration of the last handshake

// POST the current metric set to PUSHGATEWAY_URL (no-op if not defined).
void metricsPush();
