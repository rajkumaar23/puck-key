// puck-key receiver (ESP32)
// -------------------------
// A Puck.js fob connects over BLE and writes a time-based rolling code. This
// sketch verifies it (ble_auth) and, on success, tells SmartRent to unlock the
// door (smartrent). A persistent TLS socket is kept warm so the unlock is fast.
//
//   crypto.*    - HMAC / base32 / TOTP helpers
//   ble_auth.*  - verify the fob's rolling code
//   smartrent.* - SmartRent login (+2FA), token refresh, unlock PATCH
//   config.h    - non-secret tunables      secrets.h - your credentials (gitignored)

#include <WiFi.h>
#include <HTTPClient.h>
#include <NimBLEDevice.h>
#include <Adafruit_NeoPixel.h>
#include <time.h>
#include "config.h"
#include "secrets.h"
#include "smartrent.h"
#include "ble_auth.h"
#include "notify.h"

Adafruit_NeoPixel pixel(1, PIN_NEOPIXEL, NEO_GRB + NEO_KHZ800);
// Drive the on-board NeoPixel to a solid color (status indicator).
void setLED(uint8_t r, uint8_t g, uint8_t b) {
  pixel.setPixelColor(0, pixel.Color(r, g, b)); pixel.show();
}
#define LED_IDLE()      setLED(0, 0, 40)    // dim blue  = armed / waiting
#define LED_CONNECTED() setLED(60, 35, 0)   // amber     = fob connected
#define LED_SUCCESS()   setLED(0, 60, 0)    // green     = unlocked
#define LED_FAIL()      setLED(60, 0, 0)    // red       = rejected / error

volatile bool doUnlock = false;
volatile bool prewarm = false;         // set by onConnect -> loop() warms the TLS socket
volatile bool needAdvertise = false;
volatile bool clientConnected = false;
unsigned long tConnect = 0;
uint16_t connHandle = 0;

// Log a labelled timestamp relative to the start of the current fob session.
void stamp(const char* label) {
  Serial.printf("[+%5lu ms] %s\n", millis() - tConnect, label);
}

#ifdef HEARTBEAT_URL
// Push a liveness heartbeat to Uptime Kuma. Plain HTTP (no TLS), so it doesn't
// touch the warm SmartRent socket. Optional: undefine HEARTBEAT_URL to disable.
void sendHeartbeat() {
  WiFiClient c; HTTPClient http;
  http.setConnectTimeout(3000);
  int code = http.begin(c, HEARTBEAT_URL) ? http.GET() : -1;
  http.end();
  Serial.printf("[uptime] push -> HTTP %d\n", code);
}
#endif

// Run the SmartRent unlock and reflect the result on the LED. Called from loop()
// once a fob has authenticated, so it never blocks the BLE callbacks.
void performUnlock() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi down"); LED_FAIL();
    notifyAlert("wifi", "unlock request blocked: WiFi down", nullptr, 2);
    return;
  }
  int code = smartrentUnlock();
  Serial.printf("[+%5lu ms] smartrent PATCH -> HTTP %d\n", millis() - tConnect, code);
  if (code == 200) {
    LED_SUCCESS();
    notifyRecovered("unlock", "unlock OK (recovered)");
    notifyRecovered("auth", "fob auth OK (recovered)");
  } else {
    LED_FAIL();
    notifyAlert("unlock", code < 0 ? "unlock failed: TLS socket error"
                                   : "unlock failed",
                code < 0 ? nullptr : ("SmartRent HTTP " + String(code)).c_str(), 15);
  }
  delay(800);
  LED_IDLE();
}

// BLE server (GAP) callbacks: track connect/disconnect and start warming the
// TLS socket the instant a fob connects.
class ServerCallbacks : public NimBLEServerCallbacks {
  // A fob connected: note the handle, start a session timer, and warm the socket.
  void onConnect(NimBLEServer* s, NimBLEConnInfo& i) override {
    clientConnected = true;
    prewarm = true;                 // race the TLS handshake against the BLE write
    connHandle = i.getConnHandle();
    tConnect = millis(); Serial.println("---- fob session ----"); stamp("connected"); LED_CONNECTED();
  }
  // The fob (or the stale-link watchdog) dropped the connection: re-arm advertising.
  void onDisconnect(NimBLEServer* s, NimBLEConnInfo& i, int reason) override {
    char b[48]; snprintf(b, sizeof(b), "disconnected (reason %d)", reason);
    stamp(b); LED_IDLE();
    clientConnected = false;
    needAdvertise = true;
  }
};
// GATT callback for the write characteristic: validate the fob's rolling code and,
// on success, flag an unlock for loop() to perform.
class RespCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& i) override {
    NimBLEAttValue v = c->getValue();
    if (v.length() == 32) {
      if (bleCodeValid(v.data())) { stamp("authenticated"); doUnlock = true; }
      else {
        stamp("AUTH FAILED (bad/expired code)"); LED_FAIL();
        notifyAlert("auth", "fob rejected: bad or expired rolling code",
                    "check the fob clock (re-run provisioning setTime) or SECRET", 60);
      }
    } else stamp("bad code length");
  }
};

// Bring up LED, WiFi, NTP clock, an initial SmartRent token, and the BLE server.
void setup() {
  Serial.begin(115200); delay(1000); Serial.println();
  notifyBoot();
#if defined(NEOPIXEL_POWER)
  pinMode(NEOPIXEL_POWER, OUTPUT); digitalWrite(NEOPIXEL_POWER, HIGH);
#endif
  pixel.begin(); pixel.setBrightness(40); LED_IDLE();
  smartrentBegin();

  Serial.printf("WiFi \"%s\" ", WIFI_SSID);
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 60000) {
    delay(300); Serial.print(".");
  }
  if (WiFi.status() != WL_CONNECTED) {
    // No uplink: keep retrying from loop() and alert; the BLE server is still
    // brought up so a fob press gives immediate local (LED) feedback.
    Serial.println(" - NOT connected, will keep retrying from loop()");
    notifyAlert("wifi", "WiFi not connected at boot",
                "retrying; receiver usable only when back online", 2);
  } else {
    Serial.print(" connected, IP "); Serial.println(WiFi.localIP());
  }

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");   // UTC wall clock for tokens + rolling code
  Serial.print("Syncing time");
  for (int i = 0; i < 20 && time(nullptr) < 1000000000; i++) { delay(300); Serial.print("."); }
  Serial.println();
  if (time(nullptr) < 1000000000)
    notifyAlert("ntp", "NTP clock not synced",
                "rolling-code + TOTP checks will fail until the clock is set", 60);

  smartrentLogin();   // grab a token now so the first press is already fast
  if (smartrentHasToken()) {
    Serial.println("SmartRent token ready");
  } else {
    Serial.println("SmartRent login FAILED");
    notifyAlert("login", "SmartRent login failed at boot",
                "credentials, TFA seed, or Cloudflare block? unlocks will stay broken", 15);
  }

  NimBLEDevice::init("");            // no advertised name -> nothing for scanners to identify
  NimBLEDevice::setMTU(100);
  NimBLEDevice::setPower(9);
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_PUBLIC);
  NimBLEServer* server = NimBLEDevice::createServer();
  server->setCallbacks(new ServerCallbacks());
  server->advertiseOnDisconnect(false);
  NimBLEService* svc = server->createService(SERVICE_UUID);
  // Single write-only characteristic: the fob writes its 32-byte rolling code here.
  svc->createCharacteristic(RESP_UUID, NIMBLE_PROPERTY::WRITE)->setCallbacks(new RespCallbacks());
  svc->start();
  // Advertise connectable but anonymous (no name, no service UUID in the ad).
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->setMinInterval(32); adv->setMaxInterval(48);   // 20-30 ms (units of 0.625 ms) -> faster connect
  adv->start();
  Serial.print("BLE address: "); Serial.println(NimBLEDevice::getAddress().toString().c_str());
  Serial.println("Advertising - ready");
}

// Track whether the wifi failure alert has fired this boot so we can send a
// single "recovered" ping the first time we're back online.
static bool wifiDownFlagged = false;
static unsigned long wifiLastBegin = 0;

// Main loop: service pending flags (unlock, re-advertise), keep the token and TLS
// socket fresh while idle, push the heartbeat, drop stale BLE links, and
// recover WiFi after a dropout.
void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    // Reconnect; alert at 2 min until this is resolved. The 15 s gate only
    // limits redundant explicit WiFi.begin() calls - the ESP32 core keeps
    // trying on its own while disconnected.
    if (millis() - wifiLastBegin > 15000) {
      wifiLastBegin = millis();
      WiFi.begin(WIFI_SSID, WIFI_PASS);
    }
    notifyAlert("wifi", "WiFi down", "no uplink - unlocks impossible until reconnect", 2);
    wifiDownFlagged = true;
  } else if (wifiDownFlagged) {
    wifiDownFlagged = false;
    notifyRecovered("wifi", "WiFi back online");
  }
  notifyPump();   // deliver any queued alerts (no-op while offline)
  if (!clientConnected && WiFi.status() == WL_CONNECTED)
    smartrentMaintainToken();   // keep the token fresh while idle (skip when offline)
  if (notifyNotSent("login") && smartrentHasToken())
    notifyRecovered("login", "SmartRent token recovered");
  if (!notifyNotSent("ntp") && time(nullptr) > 1000000000)
    notifyRecovered("ntp", "NTP clock synced");

  // One-shot alert if the heap is too low for a TLS handshake (OOM would crash
  // the device). Fires at most once per boot.
  if (notifyNotSent("heap") && !clientConnected &&
      ESP.getFreeHeap() < 40 * 1024) {
    notifyOnce("heap", "low free heap",
               ("ESP32 free heap " + String(ESP.getFreeHeap()) + " bytes - a TLS handshake may OOM and crash the receiver").c_str());
  }

  if (needAdvertise) { needAdvertise = false; NimBLEDevice::startAdvertising(); }
  if (prewarm)       { prewarm = false;       smartrentPrewarm(); }   // warm during the BLE write
  if (doUnlock)      { doUnlock = false;      performUnlock(); }

#ifdef HEARTBEAT_URL
  static unsigned long lastPush = 0;
  if (!clientConnected && WiFi.status() == WL_CONNECTED &&
      (lastPush == 0 || millis() - lastPush > HEARTBEAT_INTERVAL)) {
    lastPush = millis();
    sendHeartbeat();
  }
#endif

  // Keep the TLS socket hot while idle so an unlock is just the ~200 ms request.
  static unsigned long lastWarm = 0;
  if (!clientConnected && WiFi.status() == WL_CONNECTED && !smartrentSocketOpen() &&
      millis() - lastWarm > 5000) {
    lastWarm = millis();
    smartrentPrewarm();
  }

  static unsigned long lastBeat = 0;
  if (millis() - lastBeat > 3000) {
    lastBeat = millis();
    Serial.printf("advertising=%d  connected=%d\n",
                  NimBLEDevice::getAdvertising()->isAdvertising(), clientConnected);
  }
  if (clientConnected && millis() - tConnect > BLE_STALE_MS) {   // dead link -> drop it
    Serial.println("stale connection - forcing disconnect");
    NimBLEDevice::getServer()->disconnect(connHandle);           // fires onDisconnect -> re-advertise
  }
  if (!clientConnected && !NimBLEDevice::getAdvertising()->isAdvertising()) {
    NimBLEDevice::startAdvertising();     // keep it up whenever idle
  }
  delay(50);
}
