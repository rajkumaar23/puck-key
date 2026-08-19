// Telegram alerting for the ESP32 receiver (see notify.h).
//
// Sends a short message to api.telegram.org over a throwaway TLS client on
// each alert. Per-tag state machine: first failure fires immediately,
// repeats are backoff-limited (everyMin per call site), recovery fires once.
// A persistent fault therefore produces "failed, ...every N min..., recovered"
// instead of a flood.
//
// ALERTS CAN BE UNDELIVERABLE: this device's only uplink is the same WiFi it
// is reporting on. If a send can't be attempted (no WiFi) or fails, the
// message is queued (up to QUEUE_CAP) and drained the next time any send
// succeeds. A boot alert sent before WiFi is up, or a "WiFi down" alert,
// therefore lands as soon as the link is back.
//
// Non-blocking: when WiFi is down, nothing touches the network (a TCP connect
// attempt would block up to ~5 s and stall loop()); messages just queue.
// All entry points are safe to call from loop(); never call from BLE/GATT
// callbacks (the TLS handshake would stall the GATT stack).

#include "notify.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include "esp_system.h"   // esp_reset_reason()

// Credentials from secrets.h. Build still works if you omit either one:
// empty token == alerts silently disabled.
#ifndef TG_BOT_TOKEN
#define TG_BOT_TOKEN ""
#endif
#ifndef TG_CHAT_ID
#define TG_CHAT_ID ""
#endif

static const int QUEUE_CAP = 4;       // max undelivered alerts held in RAM
static const int MSG_MAX   = 220;     // bytes per queued message

struct AlertState {
  const char* tag;
  bool failed;        // a failure has been reported (recovery pending)
  unsigned long last; // millis() of the last send/queue attempt for this tag
};

static AlertState g_slots[] = {
  {"wifi",   false, 0},
  {"ntp",    false, 0},
  {"login",  false, 0},
  {"unlock", false, 0},
  {"auth",   false, 0},
  {"heap",   false, 0},
};

// Pending queue (ring), filled when a send can't be delivered. Each entry
// stores the full message plus a timestamp-free signature used for dedupe
// (identical ongoing-fault alerts queue once, not once per repeat).
static char  g_queue[QUEUE_CAP][MSG_MAX + 1];
static char  g_sig[QUEUE_CAP][80];
static int   g_qhead = 0;   // index of the oldest pending message
static int   g_qcount = 0;

static void queuePush(const char* msg, const char* sig) {
  if (g_qcount > 0) {
    int newest = (g_qhead + g_qcount - 1) % QUEUE_CAP;
    if (strncmp(g_sig[newest], sig, sizeof(g_sig[0])) == 0) return;
  }
  if (g_qcount >= QUEUE_CAP) {
    Serial.println("[notify] queue full, dropping newest");
    return;
  }
  int idx = (g_qhead + g_qcount) % QUEUE_CAP;
  strncpy(g_queue[idx], msg, MSG_MAX);
  g_queue[idx][MSG_MAX] = 0;
  strncpy(g_sig[idx], sig, sizeof(g_sig[0]) - 1);
  g_sig[idx][sizeof(g_sig[0]) - 1] = 0;
  g_qcount++;
}

static void queuePop() {
  g_qhead = (g_qhead + 1) % QUEUE_CAP;
  g_qcount--;
}

static AlertState* findSlot(const char* tag) {
  for (unsigned i = 0; i < sizeof(g_slots) / sizeof(g_slots[0]); i++)
    if (strcmp(g_slots[i].tag, tag) == 0) return &g_slots[i];
  return nullptr;
}

// Escape double quotes / backslashes for the JSON body.
static String tgEscape(const String& s) {
  String o;
  o.reserve(s.length() + 8);
  for (unsigned i = 0; i < s.length(); i++) {
    char ch = s[i];
    if (ch == '"' || ch == '\\') o += '\\';
    o += ch;
  }
  return o;
}

// UTC timestamp line (degrades gracefully when NTP has not set the clock).
static String tsLine() {
  char b[32];
  time_t now = time(nullptr);
  if (now > 1000000000) {
    struct tm t;
    gmtime_r(&now, &t);
    strftime(b, sizeof(b), "%Y-%m-%d %H:%M UTC", &t);
  } else {
    strcpy(b, "(clock unsynced)");
  }
  return String(b);
}

// POST one finished message text. True on success.
static bool postText(const String& text) {
  WiFiClientSecure c;
  c.setInsecure();          // valid cert, no pinning (same policy as SmartRent)
  c.setTimeout(8000);
  HTTPClient http;
  String url = String("https://api.telegram.org/bot") + TG_BOT_TOKEN + "/sendMessage";
  if (!http.begin(c, url)) {
    http.end();
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  String body = String("{\"chat_id\":\"") + TG_CHAT_ID +
                "\",\"text\":\"" + tgEscape(text) +
                "\",\"disable_web_page_preview\":true}";
  int code = http.POST(body);
  http.end();
  Serial.printf("[notify] telegram -> HTTP %d\n", code);
  return code == 200;
}

// Timestamp-free identity of a message: what it is, not when it was built.
static String msgSig(const char* emoji, const char* title, const char* detail) {
  return String(emoji) + title + (detail && detail[0] ? String("|") + detail : String());
}

static bool tgSend(const char* emoji, const char* title, const char* detail) {
  if (TG_BOT_TOKEN[0] == 0) {
    Serial.printf("[notify] disabled: %s %s\n", title, detail ? detail : "");
    return false;
  }
  String text = String(emoji) + " puck-key: " + title +
                (detail && detail[0] ? String("\n") + detail : String()) +
                "\n" + tsLine();
  String sig = msgSig(emoji, title, detail);
  if (WiFi.status() != WL_CONNECTED) {
    // No uplink: queue and return immediately - never block on a connect.
    queuePush(text.c_str(), sig.c_str());
    return false;
  }
  // First try to drain anything queued from earlier.
  while (g_qcount > 0) {
    if (postText(g_queue[g_qhead])) queuePop();
    else break;
  }
  bool ok = postText(text);
  if (!ok) queuePush(text.c_str(), sig.c_str());   // undeliverable now -> later
  return ok;
}

void notifyAlert(const char* tag, const char* title, const char* detail, int everyMin) {
  AlertState* s = findSlot(tag);
  if (!s) return;
  unsigned long now = millis();
  bool fire = false;
  if (!s->failed) {
    s->failed = true;
    s->last = now;
    fire = true;
  } else if (now - s->last >= (unsigned long)everyMin * 60000UL) {
    s->last = now;
    fire = true;
  }
  if (fire) tgSend("\U0001F534", title, detail);   // red circle
}

void notifyRecovered(const char* tag, const char* title) {
  AlertState* s = findSlot(tag);
  if (!s || !s->failed) return;
  s->failed = false;
  tgSend("\U0001F7E2", title, nullptr);             // green circle
}

void notifyOnce(const char* tag, const char* title, const char* detail) {
  AlertState* s = findSlot(tag);
  if (!s || s->failed) return;
  s->failed = true;
  s->last = millis();
  tgSend("\U0001F534", title, detail);
}

bool notifyNotSent(const char* tag) {
  AlertState* s = findSlot(tag);
  return s && !s->failed;
}

void notifyPump() {
  if (TG_BOT_TOKEN[0] == 0 || WiFi.status() != WL_CONNECTED || g_qcount == 0)
    return;
  while (g_qcount > 0) {
    if (postText(g_queue[g_qhead])) queuePop();
    else break;
  }
}

// Reset-reason enum members differ between cores (2.x: RESET_REASON_*,
// 3.x: ESP_RST_*). Each case is guarded so both cores build; unguarded
// reasons fall through to "unknown".
static const char* resetReasonStr(esp_reset_reason_t r) {
  switch (r) {
#if defined(ESP_RST_POWERON)
    case ESP_RST_POWERON:      return "power-on";
    case ESP_RST_SW:           return "software restart (ESP.restart)";
    case ESP_RST_EXT:          return "external reset pin";
    case ESP_RST_PANIC:        return "PANIC - fatal exception";
    case ESP_RST_INT_WDT:      return "interrupt watchdog (lockup)";
    case ESP_RST_TASK_WDT:     return "task watchdog (lockup)";
    case ESP_RST_WDT:          return "watchdog API reset";
    case ESP_RST_DEEPSLEEP:    return "deep sleep wake";
    case ESP_RST_BROWNOUT:     return "BROWNOUT - voltage dip";
    case ESP_RST_USB:          return "USB reset";
    case ESP_RST_CPU_LOCKUP:   return "CPU lockup (double exception)";
#endif
#if defined(RESET_REASON_POWERON)
    case RESET_REASON_POWERON: return "power-on";
#endif
#if defined(RESET_REASON_SW)
    case RESET_REASON_SW:      return "software restart (ESP.restart)";
#endif
#if defined(RESET_REASON_EXT)
    case RESET_REASON_EXT:     return "external reset pin";
#endif
#if defined(RESET_REASON_PANIC)
    case RESET_REASON_PANIC:   return "PANIC - fatal exception";
#endif
#if defined(RESET_REASON_INT_WDT)
    case RESET_REASON_INT_WDT: return "interrupt watchdog (lockup)";
#endif
#if defined(RESET_REASON_TASK_WDT)
    case RESET_REASON_TASK_WDT:return "task watchdog (lockup)";
#endif
#if defined(RESET_REASON_WDT)
    case RESET_REASON_WDT:     return "watchdog API reset";
#endif
#if defined(RESET_REASON_DEEP_SLEEP)
    case RESET_REASON_DEEP_SLEEP: return "deep sleep wake";
#endif
#if defined(RESET_REASON_SYS_BROWN_OUT)
    case RESET_REASON_SYS_BROWN_OUT: return "BROWNOUT - voltage dip";
#endif
    default:                   return "unknown";
  }
}

void notifyBoot() {
  // Best effort: if WiFi is up it delivers now; otherwise the queue carries it
  // to the first successful send (usually right after the link recovers).
  String detail = "reset reason: " + String(resetReasonStr(esp_reset_reason()));
  tgSend("\U0001F7E2", "ESP32 receiver booted", detail.c_str());
}
