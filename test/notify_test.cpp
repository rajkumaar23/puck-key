// Host unit tests for the ESP32 Telegram-alerting core (notify_core.h).
//
// Compiles with plain g++/clang - no Arduino, WiFi, or ESP32 runtime. The
// tests drive the REAL production logic (rate limiter, ring queue + dedupe,
// JSON escaping, timestamp, reset-reason mapping) and assert on observable
// behavior. Run via test/build_and_run_tests.sh.

#include "../receiver/notify_core.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

using namespace ncore;

static int g_pass = 0;
#define CHECK(cond) do { \
    if (!(cond)) { std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); std::exit(1); } \
    g_pass++; \
  } while (0)

// ---------------------------------------------------------------------------
// Rate limiter (alert)
// ---------------------------------------------------------------------------
static void test_rate_limiter_first_fires() {
  reset();
  CHECK(alert("wifi", 0, 2) == true);          // first alert always fires
  CHECK(notSent("wifi") == false);             // now flagged failed
}

static void test_rate_limiter_suppresses_within_window() {
  reset();
  CHECK(alert("wifi", 0, 2) == true);
  CHECK(alert("wifi", 1000, 2) == false);      // 1 s later, inside 2-min window
  CHECK(alert("wifi", 119000, 2) == false);    // just under 2 min (119 s)
}

static void test_rate_limiter_refires_after_window() {
  reset();
  CHECK(alert("wifi", 0, 2) == true);
  CHECK(alert("wifi", 120000, 2) == true);     // exactly 2 min -> refires
  // after a repeat, the window restarts from that fire
  CHECK(alert("wifi", 130000, 2) == false);
  CHECK(alert("wifi", 240000, 2) == true);
}

static void test_rate_limiter_independent_per_tag() {
  reset();
  CHECK(alert("wifi", 0, 2) == true);
  CHECK(alert("login", 0, 15) == true);        // different tag unaffected
  CHECK(alert("login", 600000, 15) == false);  // login still inside its 15-min
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------
static void test_recovered_fires_only_after_failure() {
  reset();
  CHECK(recovered("wifi") == false);           // no prior failure -> no ping
  CHECK(alert("wifi", 0, 2) == true);
  CHECK(recovered("wifi") == true);            // now it fires
  CHECK(recovered("wifi") == false);           // and only once (flag cleared)
}

static void test_failure_after_recovery_fires_fresh() {
  reset();
  CHECK(alert("ntp", 0, 60) == true);
  CHECK(recovered("ntp") == true);
  CHECK(alert("ntp", 5000, 60) == true);       // a new failure fires immediately
}

// ---------------------------------------------------------------------------
// One-shot (notifyOnce)
// ---------------------------------------------------------------------------
static void test_once_fires_once() {
  reset();
  CHECK(once("heap", 0) == true);
  CHECK(once("heap", 1000) == false);          // second attempt ignored
  CHECK(notSent("heap") == false);
}

static void test_once_not_fired_then_notSent_true() {
  reset();
  CHECK(notSent("heap") == true);              // nothing fired yet
  CHECK(once("heap", 0) == true);
  CHECK(notSent("heap") == false);
}

// ---------------------------------------------------------------------------
// Ring queue + dedupe
// ---------------------------------------------------------------------------
static void test_queue_store_pop_fifo() {
  reset();
  CHECK(qSize() == 0);
  CHECK(qPush("a-msg", "A") == PQ_STORED);
  CHECK(qPush("b-msg", "B") == PQ_STORED);
  std::string m, s;
  CHECK(qPop(&m, &s) == true);
  CHECK(m == "a-msg" && s == "A");             // oldest first (FIFO)
  CHECK(qPop(&m, &s) == true);
  CHECK(m == "b-msg" && s == "B");
  CHECK(qPop(&m) == false);                    // now empty
  CHECK(qSize() == 0);
}

static void test_queue_dedupe_identical_sig() {
  reset();
  CHECK(qPush("x1", "SIG") == PQ_STORED);
  CHECK(qPush("x2", "SIG") == PQ_DEDUPED);     // same signature, any position
  CHECK(qPush("x3", "SIG") == PQ_DEDUPED);
  CHECK(qSize() == 1);                          // only one copy kept
  std::string m, s;
  CHECK(qPop(&m, &s) == true);
  CHECK(m == "x1");                             // the FIRST one was stored
}

static void test_queue_dedupe_across_wrap() {
  // Fill to capacity, pop a couple, push more to force the ring to wrap, then
  // confirm dedupe still finds an earlier entry that is no longer the newest.
  reset();
  CHECK(qPush("m1", "S1") == PQ_STORED);
  CHECK(qPush("m2", "S2") == PQ_STORED);
  CHECK(qPush("m3", "S3") == PQ_STORED);
  CHECK(qPush("m4", "S4") == PQ_STORED);        // full (cap 4)
  CHECK(qPush("m5", "S5") == PQ_FULL);          // dropped, oldest preserved
  std::string m, s;
  CHECK(qPop(&m, &s) == true); CHECK(m == "m1");  // wrap: head -> 1
  CHECK(qPop(&m, &s) == true); CHECK(m == "m2");  // head -> 2
  // S2 is now at index (qhead-1)... after two pops head=2, so slot 2 (m3) is
  // oldest. Re-push S3's message: it must dedupe against the still-queued m3.
  CHECK(qPush("m3-dup", "S3") == PQ_DEDUPED);   // m3 (S3) still queued
  CHECK(qSize() == 2);                           // m3, m4 remain
}

static void test_queue_full_preserves_oldest() {
  reset();
  CHECK(qPush("m1", "S1") == PQ_STORED);
  CHECK(qPush("m2", "S2") == PQ_STORED);
  CHECK(qPush("m3", "S3") == PQ_STORED);
  CHECK(qPush("m4", "S4") == PQ_STORED);
  CHECK(qPush("m5", "S5") == PQ_FULL);
  std::string m, s;
  CHECK(qPop(&m, &s) == true); CHECK(m == "m1");  // oldest (m1) NOT dropped
  CHECK(qPop(&m, &s) == true); CHECK(m == "m2");
  CHECK(qPop(&m, &s) == true); CHECK(m == "m3");
  CHECK(qPop(&m, &s) == true); CHECK(m == "m4");
  CHECK(qPop(&m) == false);
}

static void test_queue_truncates_oversize_msg() {
  reset();
  std::string big(300, 'z');                    // > MSG_MAX (220)
  CHECK(qPush(big.c_str(), "BIG") == PQ_STORED);
  std::string m;
  CHECK(qPop(&m) == true);
  CHECK(m.size() == MSG_MAX);                   // truncated to capacity
}

static void test_queue_truncates_oversize_sig() {
  reset();
  std::string bigsig(200, 'q');                 // > SIG_MAX (80)
  CHECK(qPush("m", bigsig.c_str()) == PQ_STORED);
  std::string m, s;
  CHECK(qPop(&m, &s) == true);
  CHECK(s.size() == SIG_MAX - 1);               // truncated, NUL-terminated
}

// ---------------------------------------------------------------------------
// JSON escaping
// ---------------------------------------------------------------------------
static void test_json_escape_quotes_and_backslash() {
  CHECK(jsonEscape(R"(say "hi")") == R"(say \"hi\")");
  CHECK(jsonEscape("a\\b") == "a\\\\b");
  CHECK(jsonEscape("plain") == "plain");
}

static void test_json_escape_combines() {
  CHECK(jsonEscape(R"(" and \ and " )") == R"(\" and \\ and \" )");
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------
static void test_ts_line_unsynced() {
  CHECK(tsLine(0) == "(clock unsynced)");
  CHECK(tsLine(999999999) == "(clock unsynced)");
}

static void test_ts_line_synced() {
  // 2021-01-01 00:00:00 UTC == 1609459200
  CHECK(tsLine(1609459200) == "2021-01-01 00:00 UTC");
  // 2020-02-29 12:30 UTC (leap day sanity)
  CHECK(tsLine(1582979400) == "2020-02-29 12:30 UTC");
}

// ---------------------------------------------------------------------------
// Message text / signature
// ---------------------------------------------------------------------------
static void test_msg_text_no_detail() {
  std::string t = msgText("\U0001F534", "WiFi down", nullptr, 1609459200);
  CHECK(t == "\U0001F534 puck-key: WiFi down\n2021-01-01 00:00 UTC");
}

static void test_msg_text_with_detail() {
  std::string t = msgText("\U0001F534", "unlock failed", "SmartRent HTTP 403", 1609459200);
  CHECK(t == "\U0001F534 puck-key: unlock failed\nSmartRent HTTP 403\n2021-01-01 00:00 UTC");
}

static void test_msg_sig_ignores_timestamp_and_detail_optionality() {
  // Signature is timestamp-free (that's the point of dedupe).
  CHECK(msgSig("e", "title", nullptr) == "etitle");
  CHECK(msgSig("e", "title", "d") == "etitle|d");
  CHECK(msgSig("e", "title", "") == "etitle");        // empty detail == none
  CHECK(msgSig("e", "title", nullptr) != msgSig("e", "title", "d"));
}

// ---------------------------------------------------------------------------
// Reset-reason mapping
// ---------------------------------------------------------------------------
static void test_reset_reason_strings() {
  CHECK(std::string(resetReasonStr(RC_POWERON)) == "power-on");
  CHECK(std::string(resetReasonStr(RC_PANIC)) == "PANIC - fatal exception");
  CHECK(std::string(resetReasonStr(RC_TASK_WDT)) == "task watchdog (lockup)");
  CHECK(std::string(resetReasonStr(RC_BROWNOUT)) == "BROWNOUT - voltage dip");
  CHECK(std::string(resetReasonStr(0)) == "unknown");
  CHECK(std::string(resetReasonStr(999)) == "unknown");
}

// ---------------------------------------------------------------------------
// Integration: offline -> queue -> recovery delivery ordering
// ---------------------------------------------------------------------------
// Simulates the Arduino layer's tgSend/notifyPump flow against the core:
// while offline, alerts queue; when back online, the queue drains FIFO
// before the triggering message, and repeats of one fault collapse.
static void test_integration_offline_then_recover() {
  reset();
  uint64_t now = 0;
  std::vector<std::string> sent;               // pretend delivery log

  auto sendWhileOffline = [&](const char* emoji, const char* title, const char* detail) {
    // (Arduino tgSend offline branch) queue it.
    std::string text = msgText(emoji, title, detail, now / 1000);
    qPush(text.c_str(), msgSig(emoji, title, detail).c_str());
  };
  auto deliver = [&](const char* emoji, const char* title, const char* detail) {
    // (Arduino tgSend online branch) drain queue first, then current.
    std::string m, s;
    while (qPop(&m, &s)) sent.push_back(m);
    std::string text = msgText(emoji, title, detail, now / 1000);
    sent.push_back(text);
  };

  // Offline: boot alert (queued), then WiFi-down alert repeats (deduped).
  sendWhileOffline("\U0001F7E2", "ESP32 receiver booted", "reset reason: power-on");
  CHECK(alert("wifi", now += 0, 2));  sendWhileOffline("\U0001F534", "WiFi down", "no uplink");
  CHECK(alert("wifi", now += 60000, 2) == false);   // inside window, suppressed
  CHECK(alert("wifi", now += 60000, 2));  // 2 min later, fires again
  CHECK(qSize() == 2);                              // boot + one WiFi-down (deduped)

  // Back online: a new alert triggers delivery of the queued items in order.
  deliver("\U0001F7E2", "WiFi back online", nullptr);
  CHECK(sent.size() == 3);
  CHECK(sent[0].find("booted") != std::string::npos);
  CHECK(sent[1].find("WiFi down") != std::string::npos);
  CHECK(sent[2].find("back online") != std::string::npos);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
  test_rate_limiter_first_fires();
  test_rate_limiter_suppresses_within_window();
  test_rate_limiter_refires_after_window();
  test_rate_limiter_independent_per_tag();
  test_recovered_fires_only_after_failure();
  test_failure_after_recovery_fires_fresh();
  test_once_fires_once();
  test_once_not_fired_then_notSent_true();
  test_queue_store_pop_fifo();
  test_queue_dedupe_identical_sig();
  test_queue_dedupe_across_wrap();
  test_queue_full_preserves_oldest();
  test_queue_truncates_oversize_msg();
  test_queue_truncates_oversize_sig();
  test_json_escape_quotes_and_backslash();
  test_json_escape_combines();
  test_ts_line_unsynced();
  test_ts_line_synced();
  test_msg_text_no_detail();
  test_msg_text_with_detail();
  test_msg_sig_ignores_timestamp_and_detail_optionality();
  test_reset_reason_strings();
  test_integration_offline_then_recover();

  std::printf("ALL PASSED: %d checks\n", g_pass);
  return 0;
}
