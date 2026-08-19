#pragma once
// notify_core.h — platform-independent core of the ESP32 Telegram alerting
// module (see notify.h / notify.cpp for the Arduino layer).
//
// Everything that is *logic* rather than *I/O* lives here so it can be unit
// tested on a host (g++/clang) with no Arduino, WiFi, or ESP32 runtime:
//   - per-tag rate limiter (first failure, then every N min) + recovery
//   - undeliverable-message ring queue with signature dedupe
//   - JSON string escaping
//   - UTC timestamp formatting (degrades when the clock is unsynced)
//   - reset-reason -> human string mapping (stable integer codes)
//
// The Arduino layer (notify.cpp) supplies millis()/time(), WiFi.status(),
// Serial, and the HTTP POST, and maps the core-version-specific
// esp_reset_reason_t enum onto the stable ResetCode values below.
//
// Header-only: state is a single function-local static guarded by an inline
// accessor, so it links to one instance per binary with no ODR issues.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <string>

namespace ncore {

// ---------------------------------------------------------------------------
// Tunables (kept in sync with the firmware defaults).
// ---------------------------------------------------------------------------
constexpr int    QUEUE_CAP = 4;     // max undelivered alerts held in RAM
constexpr size_t MSG_MAX   = 220;   // bytes per queued message
constexpr size_t SIG_MAX   = 80;    // bytes per dedupe signature
constexpr int    SLOT_COUNT = 6;    // distinct alert categories

// ---------------------------------------------------------------------------
// Reset-reason codes: stable, platform-independent. The Arduino layer maps the
// (core-version-specific) esp_reset_reason_t enum onto these so the
// human-readable string table can be tested on a host.
// ---------------------------------------------------------------------------
enum ResetCode : int {
  RC_POWERON     = 1,
  RC_SW          = 2,
  RC_EXT         = 3,
  RC_PANIC       = 4,
  RC_INT_WDT     = 5,
  RC_TASK_WDT    = 6,
  RC_WDT         = 7,
  RC_DEEPSLEEP   = 8,
  RC_BROWNOUT    = 9,
  RC_USB        = 10,
  RC_CPU_LOCKUP = 11,
};

inline const char* resetReasonStr(int code) {
  switch (code) {
    case RC_POWERON:     return "power-on";
    case RC_SW:          return "software restart (ESP.restart)";
    case RC_EXT:         return "external reset pin";
    case RC_PANIC:       return "PANIC - fatal exception";
    case RC_INT_WDT:     return "interrupt watchdog (lockup)";
    case RC_TASK_WDT:    return "task watchdog (lockup)";
    case RC_WDT:         return "watchdog API reset";
    case RC_DEEPSLEEP:   return "deep sleep wake";
    case RC_BROWNOUT:    return "BROWNOUT - voltage dip";
    case RC_USB:         return "USB reset";
    case RC_CPU_LOCKUP:  return "CPU lockup (double exception)";
    default:             return "unknown";
  }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
struct AlertSlot {
  const char* tag;
  bool        failed;   // a failure has been reported (recovery pending)
  uint64_t    last;     // ms timestamp of the last send/queue for this tag
};

struct State {
  AlertSlot slots[SLOT_COUNT];
  char      msg[QUEUE_CAP][MSG_MAX + 1];
  char      sig[QUEUE_CAP][SIG_MAX];
  int       qhead  = 0;   // index of the oldest pending message
  int       qcount = 0;

  // Self-initialize the tag table so a fresh instance is usable WITHOUT a
  // reset() call. The firmware's shared State is a function-local static and
  // never goes through reset() on device; the tags must be set at
  // construction or every tag-based alert silently no-ops.
  State() {
    static const char* tags[SLOT_COUNT] =
        {"wifi", "ntp", "login", "unlock", "auth", "heap"};
    for (int i = 0; i < SLOT_COUNT; i++) {
      slots[i].tag    = tags[i];
      slots[i].failed = false;
      slots[i].last   = 0;
    }
  }
};

// Single shared instance (function-local static = one per binary).
inline State& st() { static State s; return s; }

// (Re)initialize all *runtime* state (failed flags, timers, queue). The tag
// table is set by the State constructor. Called by tests between cases.
inline void reset() {
  State& S = st();
  for (int i = 0; i < SLOT_COUNT; i++) {
    S.slots[i].failed = false;
    S.slots[i].last   = 0;
  }
  std::memset(S.msg, 0, sizeof(S.msg));
  std::memset(S.sig, 0, sizeof(S.sig));
  S.qhead = 0;
  S.qcount = 0;
}

inline AlertSlot* find(const char* tag) {
  State& S = st();
  for (int i = 0; i < SLOT_COUNT; i++)
    if (S.slots[i].tag && std::strcmp(S.slots[i].tag, tag) == 0)
      return &S.slots[i];
  return nullptr;
}

// ---------------------------------------------------------------------------
// Rate limiter + recovery state machine
// ---------------------------------------------------------------------------

// Does `tag` fire a (rate-limited) failure alert at `now_ms`? Mutates state.
//   - first alert for this tag: always fires, arms failed, stamps now_ms
//   - repeat: fires only once every_min has elapsed since the last fire
inline bool alert(const char* tag, uint64_t now_ms, int every_min) {
  AlertSlot* s = find(tag);
  if (!s) return false;
  if (!s->failed) {
    s->failed = true;
    s->last   = now_ms;
    return true;
  }
  if (now_ms - s->last >= (uint64_t)every_min * 60000ULL) {
    s->last = now_ms;
    return true;
  }
  return false;
}

// Fire a recovery ping if (and only if) `tag` is currently in the failed
// state; clears the flag so a later failure fires fresh.
inline bool recovered(const char* tag) {
  AlertSlot* s = find(tag);
  if (!s || !s->failed) return false;
  s->failed = false;
  return true;
}

// One-shot alert that ignores the rate limit (used for "low heap", which we
// only ever want to see once per session). Arms the tag as failed so a
// subsequent alert(tag) is treated as a repeat.
inline bool once(const char* tag, uint64_t now_ms) {
  AlertSlot* s = find(tag);
  if (!s || s->failed) return false;
  s->failed = true;
  s->last   = now_ms;
  return true;
}

// True if `tag` has NOT yet been reported this session (i.e. one-shot has not
// fired). Used by the "recovered" guards in the main loop.
inline bool notSent(const char* tag) {
  AlertSlot* s = find(tag);
  return s && !s->failed;
}

// ---------------------------------------------------------------------------
// Ring queue with signature dedupe
// ---------------------------------------------------------------------------
// qPush return codes:
enum PushResult : int { PQ_STORED = 0, PQ_DEDUPED = 1, PQ_FULL = 2 };

// Store an undeliverable message. Dedupes against *any* queued entry by
// signature (identical ongoing-fault alerts queue once, and a failed
// re-queue of an already-pending message cannot create a copy). When full,
// the newest incoming message is dropped (oldest is preserved).
inline int qPush(const char* msg, const char* sig) {
  State& S = st();
  if (S.qcount > 0) {
    for (int i = 0; i < S.qcount; i++) {
      int idx = (S.qhead + i) % QUEUE_CAP;
      if (std::strncmp(S.sig[idx], sig, SIG_MAX) == 0) return PQ_DEDUPED;
    }
  }
  if (S.qcount >= QUEUE_CAP) return PQ_FULL;
  int idx = (S.qhead + S.qcount) % QUEUE_CAP;
  std::strncpy(S.msg[idx], msg, MSG_MAX);
  S.msg[idx][MSG_MAX] = 0;
  std::strncpy(S.sig[idx], sig, SIG_MAX - 1);
  S.sig[idx][SIG_MAX - 1] = 0;
  S.qcount++;
  return PQ_STORED;
}

// Pop the oldest pending message (and its signature, so a failed re-queue
// keeps dedupe identity) into `out_msg`/`out_sig`. Returns false when empty.
inline bool qPop(std::string* out_msg, std::string* out_sig = nullptr) {
  State& S = st();
  if (S.qcount == 0) return false;
  int idx = S.qhead;
  *out_msg = S.msg[idx];
  if (out_sig) *out_sig = S.sig[idx];
  S.qhead  = (S.qhead + 1) % QUEUE_CAP;
  S.qcount--;
  return true;
}

inline int qSize() { return st().qcount; }

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------

// Escape double-quotes and backslashes for embedding in a JSON string value.
inline std::string jsonEscape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') o.push_back('\\');
    o.push_back(c);
  }
  return o;
}

// UTC timestamp line; returns "(clock unsynced)" when the wall clock has not
// been set by NTP yet (epoch < 1000000000).
inline std::string tsLine(uint64_t now_s) {
  char b[32];
  if (now_s > 1000000000ULL) {
    time_t t = (time_t)now_s;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M UTC", &tmv);
  } else {
    std::strcpy(b, "(clock unsynced)");
  }
  return std::string(b);
}

// Timestamp-free identity of a message: what it is, not when it was built.
// Used as the queue dedupe key so repeated alerts for one fault collapse.
inline std::string msgSig(const char* emoji, const char* title, const char* detail) {
  std::string s;
  s += emoji;
  s += title;
  if (detail && detail[0]) {
    s += '|';
    s += detail;
  }
  return s;
}

// Full message text as sent to Telegram.
inline std::string msgText(const char* emoji, const char* title,
                           const char* detail, uint64_t now_s) {
  std::string t;
  t += emoji;
  t += " puck-key: ";
  t += title;
  if (detail && detail[0]) {
    t += '\n';
    t += detail;
  }
  t += '\n';
  t += tsLine(now_s);
  return t;
}

}  // namespace ncore
