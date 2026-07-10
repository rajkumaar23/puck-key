#include "crypto.h"
#include <time.h>
#include "mbedtls/md.h"

// HMAC-SHA1 over msg with key -> 20-byte out (used by the RFC 6238 TOTP).
void hmacSha1(const uint8_t* key, size_t keyLen,
              const uint8_t* msg, size_t msgLen, uint8_t out[20]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, msg, msgLen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// HMAC-SHA256 over msg with key -> 32-byte out (used by the BLE rolling code).
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, msg, msgLen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// Decode a base32 (RFC 4648) string into bytes; returns count written or -1.
int base32Decode(const char* in, uint8_t* out, size_t outCap) {
  uint32_t buffer = 0; int bitsLeft = 0; size_t count = 0;
  for (const char* p = in; *p; p++) {
    char c = *p; int v;
    if (c == '=' || c == '-' || c == ' ') continue;
    if      (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a';
    else if (c >= '2' && c <= '7') v = c - '2' + 26;
    else return -1;
    buffer = (buffer << 5) | v; bitsLeft += 5;
    if (bitsLeft >= 8) {
      if (count >= outCap) return -1;
      out[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
      bitsLeft -= 8;
    }
  }
  return (int)count;
}

// Encode a counter as 8 big-endian bytes (the HMAC message for TOTP/rolling code).
void counterBytes(uint64_t counter, uint8_t out[8]) {
  for (int i = 7; i >= 0; i--) { out[i] = counter & 0xFF; counter >>= 8; }
}

// Compute the current 6-digit TOTP from a base32 seed (SmartRent 2FA).
String totpNow(const char* base32Secret) {
  uint8_t key[64];
  int keyLen = base32Decode(base32Secret, key, sizeof(key));
  if (keyLen <= 0) return "";
  uint8_t msg[8];
  counterBytes((uint64_t)(time(nullptr) / 30), msg);
  uint8_t hmac[20];
  hmacSha1(key, keyLen, msg, 8, hmac);
  int off = hmac[19] & 0x0F;
  uint32_t bin = ((uint32_t)(hmac[off] & 0x7F) << 24) | ((uint32_t)hmac[off + 1] << 16) |
                 ((uint32_t)hmac[off + 2] << 8) | (uint32_t)hmac[off + 3];
  char buf[7];
  snprintf(buf, sizeof(buf), "%06u", (unsigned)(bin % 1000000));
  return String(buf);
}
