#pragma once
// Small crypto helpers shared by the BLE rolling code and SmartRent 2FA.
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

void hmacSha1(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[20]);
void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[32]);

// Decode an RFC 4648 base32 string (ignores '=', '-', spaces). Returns byte count, -1 on error.
int base32Decode(const char* in, uint8_t* out, size_t outCap);

// 8-byte big-endian encoding of a rolling-code / TOTP counter.
void counterBytes(uint64_t counter, uint8_t out[8]);

// Current TOTP (RFC 6238, SHA1, 6 digits, 30s step) from a base32 seed. "" on error.
String totpNow(const char* base32Secret);
