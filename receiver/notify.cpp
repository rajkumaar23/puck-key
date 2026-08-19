// Telegram alerting for the ESP32 receiver (see notify.h).
//
// Arduino/ESP32 layer. All *logic* (rate limiting, undeliverable-message
// queue + dedupe, JSON escaping, timestamp, reset-reason mapping) lives in
// notify_core.h, which is platform-independent and unit-tested on a host
// (test/notify_test.cpp). This file only supplies I/O: millis()/time(),
// WiFi.status(), Serial, the HTTP POST to api.telegram.org, and the
// core-version-specific esp_reset_reason_t -> ncore::ResetCode mapping.
//
// ALERTS CAN BE UNDELIVERABLE: this device's only uplink is the same WiFi it
// is reporting on. If a send can't be attempted (no WiFi) or fails, the
// message is queued and drained the next time any send succeeds. A boot
// alert sent before WiFi is up, or a "WiFi down" alert, therefore lands as
// soon as the link is back.
//
// Non-blocking: when WiFi is down, nothing touches the network (a TCP connect
// attempt would block up to ~5 s and stall loop()); messages just queue.
// All entry points are safe to call from loop(); never call from BLE/GATT
// callbacks (the TLS handshake would stall the GATT stack).

#include "notify.h"
#include "notify_core.h"
#include "secrets.h"      // TG_BOT_TOKEN / TG_CHAT_ID (same TU-independence as receiver.ino)
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include "esp_system.h"   // esp_reset_reason()

// Credentials from secrets.h. Build still works if you omit either one:
// empty token == alerts disabled (announced once on the console).
#ifndef TG_BOT_TOKEN
#define TG_BOT_TOKEN ""
#endif
#ifndef TG_CHAT_ID
#define TG_CHAT_ID ""
#endif

// Announce once per boot whether alerting is actually armed, so a missing
// secret never fails silently.
static void tgAnnounce() {
  static bool done = false;
  if (done) return;
  done = true;
  if (TG_BOT_TOKEN[0] && TG_CHAT_ID[0]) {
    Serial.println("[notify] Telegram alerts enabled");
  } else {
    Serial.println("[notify] Telegram alerts DISABLED - set TG_BOT_TOKEN / TG_CHAT_ID in secrets.h");
  }
}

static const char* EMOJI_FAIL = "\U0001F534";   // red circle
static const char* EMOJI_OK   = "\U0001F7E2";   // green circle

// Map the (core-version-specific) esp_reset_reason_t onto a stable ncore code.
// 3.x cores use ESP_RST_*; 2.x cores use RESET_REASON_* names.
static int mapResetReason(esp_reset_reason_t r) {
#if defined(ESP_RST_POWERON)
  switch (r) {
    case ESP_RST_POWERON:    return ncore::RC_POWERON;
    case ESP_RST_SW:         return ncore::RC_SW;
    case ESP_RST_EXT:        return ncore::RC_EXT;
    case ESP_RST_PANIC:      return ncore::RC_PANIC;
    case ESP_RST_INT_WDT:    return ncore::RC_INT_WDT;
    case ESP_RST_TASK_WDT:   return ncore::RC_TASK_WDT;
    case ESP_RST_WDT:        return ncore::RC_WDT;
    case ESP_RST_DEEPSLEEP:  return ncore::RC_DEEPSLEEP;
    case ESP_RST_BROWNOUT:   return ncore::RC_BROWNOUT;
    case ESP_RST_USB:        return ncore::RC_USB;
    case ESP_RST_CPU_LOCKUP: return ncore::RC_CPU_LOCKUP;
  }
#endif
#if defined(RESET_REASON_POWERON)
  switch (r) {
    case RESET_REASON_POWERON:  return ncore::RC_POWERON;
    case RESET_REASON_SW:       return ncore::RC_SW;
    case RESET_REASON_EXT:      return ncore::RC_EXT;
    case RESET_REASON_PANIC:    return ncore::RC_PANIC;
    case RESET_REASON_INT_WDT:  return ncore::RC_INT_WDT;
    case RESET_REASON_TASK_WDT: return ncore::RC_TASK_WDT;
    case RESET_REASON_WDT:      return ncore::RC_WDT;
    case RESET_REASON_DEEP_SLEEP: return ncore::RC_DEEPSLEEP;
#if defined(RESET_REASON_SYS_BROWN_OUT)
    case RESET_REASON_SYS_BROWN_OUT: return ncore::RC_BROWNOUT;
#endif
  }
#endif
  return 0;   // unrecognized reason on this core
}

// POST one finished message text to Telegram. True on success.
static bool postText(const std::string& text) {
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
                "\",\"text\":\"" + ncore::jsonEscape(text).c_str() +
                "\",\"disable_web_page_preview\":true}";
  int code = http.POST(body);
  http.end();
  Serial.printf("[notify] telegram -> HTTP %d\n", code);
  return code == 200;
}

// Build the message, then deliver it (or queue it if undeliverable).
static bool tgSend(const char* emoji, const char* title, const char* detail) {
  if (TG_BOT_TOKEN[0] == 0) {
    Serial.printf("[notify] disabled: %s %s\n", title, detail ? detail : "");
    return false;
  }
  std::string text = ncore::msgText(emoji, title, detail, (uint64_t)time(nullptr));
  if (WiFi.status() != WL_CONNECTED) {
    // No uplink: queue and return immediately - never block on a connect.
    ncore::qPush(text.c_str(), ncore::msgSig(emoji, title, detail).c_str());
    return false;
  }
  // First drain anything queued from earlier.
  std::string queued, queuedSig;
  while (ncore::qPop(&queued, &queuedSig)) {
    if (postText(queued)) continue;
    ncore::qPush(queued.c_str(), queuedSig.c_str());   // re-queue with its own sig
    break;
  }
  bool ok = postText(text);
  if (!ok) ncore::qPush(text.c_str(), ncore::msgSig(emoji, title, detail).c_str());
  return ok;
}

void notifyAlert(const char* tag, const char* title, const char* detail, int everyMin) {
  if (ncore::alert(tag, millis(), everyMin))
    tgSend(EMOJI_FAIL, title, detail);
}

void notifyRecovered(const char* tag, const char* title) {
  if (ncore::recovered(tag))
    tgSend(EMOJI_OK, title, nullptr);
}

void notifyOnce(const char* tag, const char* title, const char* detail) {
  if (ncore::once(tag, millis()))
    tgSend(EMOJI_FAIL, title, detail);
}

bool notifyNotSent(const char* tag) {
  return ncore::notSent(tag);
}

void notifyPump() {
  if (TG_BOT_TOKEN[0] == 0 || WiFi.status() != WL_CONNECTED) return;
  std::string queued, queuedSig;
  while (ncore::qPop(&queued, &queuedSig)) {
    if (postText(queued)) continue;
    ncore::qPush(queued.c_str(), queuedSig.c_str());   // keep for the next try
    break;
  }
}

void notifyBoot() {
  tgAnnounce();
  // Best effort: if WiFi is up it delivers now; otherwise the queue carries it
  // to the first successful send (usually right after the link recovers).
  std::string detail = std::string("reset reason: ") +
      ncore::resetReasonStr(mapResetReason(esp_reset_reason()));
  tgSend(EMOJI_OK, "ESP32 receiver booted", detail.c_str());
}
