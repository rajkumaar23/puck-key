#pragma once
// Telegram alerting for the ESP32 receiver.
//
// Every failure the device is aware of (boot/crash, WiFi down/recover, NTP
// unsynced, SmartRent login/refresh failure, unlock failure, BLE auth
// rejection, low free heap) is reported to Telegram with per-category
// rate limiting so a persistent fault pings "first failure, then every N
// minutes" plus a "recovered" message instead of spaming.
//
// Sends use a throwaway WiFiClientSecure (setInsecure) and are never called
// from BLE callbacks - the GATT context would stall during the ~300-500 ms
// TLS handshake. Call notifyAlert() from loop().

// Send (rate-limited) a failure alert.
void notifyAlert(const char* tag, const char* title, const char* detail,
                 int everyMin = 15);
// Announce that tag is healthy again (once, until it fails again).
void notifyRecovered(const char* tag, const char* title);
// One-shot: send tag/title/detail ignoring all rate limiting, then arm
// tag as failed so later notifyAlert(tag, ...) calls are treated as repeats.
void notifyOnce(const char* tag, const char* title, const char* detail);
// Call at the start of setup(): sends a boot message with the reset reason.
void notifyBoot();
// True if notifyOnce(tag, ...) has not fired yet for this boot.
bool notifyNotSent(const char* tag);
// Deliver any queued (earlier undeliverable) alerts now that the uplink may
// be back. Call from loop() whenever WiFi is connected; cheap no-op otherwise.
void notifyPump();
