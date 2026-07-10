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
  if (WiFi.status() != WL_CONNECTED) { Serial.println("WiFi down"); LED_FAIL(); return; }
  int code = smartrentUnlock();
  Serial.printf("[+%5lu ms] smartrent PATCH -> HTTP %d\n", millis() - tConnect, code);
  if (code == 200) LED_SUCCESS(); else LED_FAIL();
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
      else                        { stamp("AUTH FAILED (bad/expired code)"); LED_FAIL(); }
    } else stamp("bad code length");
  }
};

// Bring up LED, WiFi, NTP clock, an initial SmartRent token, and the BLE server.
void setup() {
  Serial.begin(115200); delay(1000); Serial.println();
#if defined(NEOPIXEL_POWER)
  pinMode(NEOPIXEL_POWER, OUTPUT); digitalWrite(NEOPIXEL_POWER, HIGH);
#endif
  pixel.begin(); pixel.setBrightness(40); LED_IDLE();
  smartrentBegin();

  Serial.printf("WiFi \"%s\" ", WIFI_SSID);
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  Serial.print(" connected, IP "); Serial.println(WiFi.localIP());

  configTime(0, 0, "pool.ntp.org", "time.nist.gov");   // UTC wall clock for tokens + rolling code
  Serial.print("Syncing time");
  for (int i = 0; i < 20 && time(nullptr) < 1000000000; i++) { delay(300); Serial.print("."); }
  Serial.println();

  smartrentLogin();   // grab a token now so the first press is already fast
  Serial.println(smartrentHasToken() ? "SmartRent token ready" : "SmartRent login FAILED");

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

// Main loop: service pending flags (unlock, re-advertise), keep the token and TLS
// socket fresh while idle, push the heartbeat, and drop stale BLE links.
void loop() {
  if (needAdvertise) { needAdvertise = false; NimBLEDevice::startAdvertising(); }
  if (prewarm)       { prewarm = false;       smartrentPrewarm(); }   // warm during the BLE write
  if (doUnlock)      { doUnlock = false;      performUnlock(); }
  if (!clientConnected) smartrentMaintainToken();   // keep the token fresh while idle

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
