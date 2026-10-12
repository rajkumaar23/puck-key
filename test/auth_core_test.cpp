// Host unit tests for the BLE challenge-response auth core (auth_core.h).
//
// Compiles with plain g++/clang - no Arduino, WiFi, or ESP32 runtime. The
// tests drive the REAL production state machine (single-use challenge arming,
// response verification, consume-right-or-wrong, unlock latch) and assert on
// observable behavior. Run via test/build_and_run_tests.sh.
//
// auth_core.h expects a platform-provided hmacSha256; here it is a compact
// SHA-256 + RFC 2104 HMAC built below. The SHA-256 core is itself validated
// against published HMAC-SHA256 vectors (RFC 4231) before any auth test runs,
// so a broken hash fails loudly at test time rather than silently.

#include "../receiver/auth_core.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace authcore;

static int g_pass = 0;
#define CHECK(cond) do { \
    if (!(cond)) { std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); std::exit(1); } \
    g_pass++; \
  } while (0)

// ---------------------------------------------------------------------------
// Minimal SHA-256 (FIPS 180-4) - host-only, stands in for mbedTLS on the ESP32.
// ---------------------------------------------------------------------------
namespace {

struct Sha256 {
  uint32_t h[8]; uint64_t bits = 0;
  uint8_t buf[64]; size_t buflen = 0;

  static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
  static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
  static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
  static uint32_t bsig0(uint32_t x) { return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22); }
  static uint32_t bsig1(uint32_t x) { return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25); }
  static uint32_t ssig0(uint32_t x) { return ror(x, 7) ^ ror(x, 18) ^ (x >> 3); }
  static uint32_t ssig1(uint32_t x) { return ror(x, 17) ^ ror(x, 19) ^ (x >> 10); }

  static constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

  Sha256() {
    h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
    h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
  }

  void block(const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
             ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++)
      w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t t1 = hh + bsig1(e) + ch(e,f,g) + K[i] + w[i];
      uint32_t t2 = bsig0(a) + maj(a,b,c);
      hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }

  void update(const uint8_t* data, size_t len) {
    bits += (uint64_t)len * 8;
    while (len) {
      size_t n = 64 - buflen; if (n > len) n = len;
      std::memcpy(buf + buflen, data, n); buflen += n; data += n; len -= n;
      if (buflen == 64) { block(buf); buflen = 0; }
    }
  }

  void final(uint8_t out[32]) {
    uint64_t msgbits = bits;                 // message length BEFORE padding
    uint8_t pad = 0x80; update(&pad, 1);
    pad = 0;
    while (buflen != 56) update(&pad, 1);
    uint8_t lenb[8];
    for (int i = 7; i >= 0; i--) { lenb[i] = msgbits & 0xFF; msgbits >>= 8; }
    update(lenb, 8);
    for (int i = 0; i < 8; i++) {
      out[i*4]   = h[i] >> 24; out[i*4+1] = h[i] >> 16;
      out[i*4+2] = h[i] >> 8;  out[i*4+3] = h[i];
    }
  }
};

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256 s; s.update(data, len); s.final(out);
}

// RFC 2104 HMAC over the SHA-256 above (same construction as mbedTLS does).
void hostHmacSha256(const uint8_t* key, size_t keyLen,
                    const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  constexpr size_t B = 64;
  uint8_t k[B] = {0};
  if (keyLen > B) { sha256(key, keyLen, k); } else { std::memcpy(k, key, keyLen); }
  uint8_t ipad[B + 64]; // reused for outer too (B + 32 fits)
  uint8_t kdf[B];
  for (size_t i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    kdf[i]  = k[i] ^ 0x5c;
  }
  Sha256 s;
  s.update(ipad, B); s.update(msg, msgLen);
  uint8_t inner[32]; s.final(inner);
  std::memcpy(ipad, kdf, B); std::memcpy(ipad + B, inner, 32);
  Sha256 o; o.update(ipad, B + 32); o.final(out);
}

std::vector<uint8_t> unhex(const std::string& h) {
  std::vector<uint8_t> v;
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    v.push_back((uint8_t)std::stoul(h.substr(i, 2), nullptr, 16));
  return v;
}
std::string tohex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s; for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

}  // namespace

// auth_core.h's platform hook, satisfied by the host HMAC above.
namespace authcore {
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
  hostHmacSha256(key, keyLen, msg, msgLen, out);
}
}

// ---------------------------------------------------------------------------
// Hash sanity: published HMAC-SHA256 vectors (RFC 4231) exercise the SHA-256
// core directly, including the >64-byte key pre-hash path (case 6/7).
// ---------------------------------------------------------------------------
static void test_hmac_vectors() {
  struct V { const char* key; const char* data; const char* mac; };
  static const V vs[] = {
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
    {"4a656665",
     "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
    // 104-byte key -> forces the key = SHA256(key) pre-hash branch
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
     "0b0b0b0b0b0b0b0b",
     "4869205468657265",
     "c852cae6e98c4cce1fd981d5ceb2e66ba66755cf32747632d0f5a623961dc6df"},
  };
  for (const V& v : vs) {
    auto k = unhex(v.key), d = unhex(v.data);
    uint8_t out[32];
    hostHmacSha256(k.data(), k.size(), d.data(), d.size(), out);
    CHECK(tohex(out, 32) == v.mac);
  }
}

// ---------------------------------------------------------------------------
// Constant-time compare
// ---------------------------------------------------------------------------
static void test_const_time_eq() {
  uint8_t a[32], b[32];
  for (int i = 0; i < 32; i++) { a[i] = (uint8_t)(i * 7 + 1); b[i] = a[i]; }
  CHECK(constTimeEq32(a, b));
  for (int bit = 0; bit < 32; bit++) {          // every single byte must matter
    b[bit] ^= 0x01; CHECK(!constTimeEq32(a, b)); b[bit] ^= 0x01;
    CHECK(constTimeEq32(a, b));
  }
  b[31] ^= 0x80; CHECK(!constTimeEq32(a, b));    // last byte differing
}

// ---------------------------------------------------------------------------
// State machine: happy path
// ---------------------------------------------------------------------------
static const uint8_t SECRET[] = "shared-test-secret";
static const size_t SECRET_LEN = sizeof(SECRET) - 1;

static void expectedFor(const uint8_t chal[CHAL_LEN], uint8_t out[32]) {
  hmacSha256(SECRET, SECRET_LEN, chal, CHAL_LEN, out);
}

static void test_happy_path() {
  ChallengeAuth auth;
  uint8_t chal[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)(0xA0 + i);
  auth.arm(chal);
  CHECK(auth.isArmed());
  CHECK(std::memcmp(auth.challenge(), chal, CHAL_LEN) == 0);
  CHECK(!auth.unlocked());

  uint8_t resp[RESP_LEN]; expectedFor(chal, resp);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::Ok);
  CHECK(auth.unlocked());                        // latch set
  auth.consumeUnlock();
  CHECK(!auth.unlocked());                       // latch taken exactly once
}

// ---------------------------------------------------------------------------
// State machine: rejections
// ---------------------------------------------------------------------------
static void test_wrong_secret_rejected() {
  ChallengeAuth auth;
  uint8_t chal[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)i;
  auth.arm(chal);
  uint8_t resp[RESP_LEN];
  const char* bad = "not-the-secret";
  hmacSha256((const uint8_t*)bad, 13, chal, CHAL_LEN, resp);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::Mismatch);
  CHECK(!auth.unlocked());
  CHECK(!auth.isArmed());                        // consumed even on mismatch
}

static void test_single_use_replay_rejected() {
  ChallengeAuth auth;
  uint8_t chal[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)(i * 3);
  auth.arm(chal);
  uint8_t resp[RESP_LEN]; expectedFor(chal, resp);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::Ok);
  // The same (correct!) response replayed on the same connection must fail:
  // the challenge was consumed by the first verify.
  auth.consumeUnlock();
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::NoChallenge);
  CHECK(!auth.unlocked());
}

static void test_stale_challenge_rejected() {
  ChallengeAuth auth;
  uint8_t chal1[CHAL_LEN], chal2[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) { chal1[i] = (uint8_t)i; chal2[i] = (uint8_t)(i + 100); }
  auth.arm(chal1);
  auth.arm(chal2);                               // fob re-read: second supersedes
  uint8_t resp1[RESP_LEN]; expectedFor(chal1, resp1);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp1, RESP_LEN) == Result::Mismatch);
  // ...and it also consumed chal2, so even the *correct* response now fails.
  uint8_t resp2[RESP_LEN]; expectedFor(chal2, resp2);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp2, RESP_LEN) == Result::NoChallenge);
  CHECK(!auth.unlocked());
}

static void test_no_challenge_rejected() {
  ChallengeAuth auth;                            // fresh: never armed
  uint8_t resp[RESP_LEN] = {0};
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::NoChallenge);
  CHECK(!auth.unlocked());
}

static void test_bad_length_rejected_without_consuming() {
  ChallengeAuth auth;
  uint8_t chal[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)(i ^ 0x5A);
  auth.arm(chal);
  uint8_t buf[40]; expectedFor(chal, buf);
  // Truncated / over-long responses are rejected but say nothing about the
  // challenge, so it must stay armed for a correct retry.
  CHECK(auth.verify(SECRET, SECRET_LEN, buf, 31) == Result::Length);
  CHECK(auth.isArmed());
  CHECK(auth.verify(SECRET, SECRET_LEN, buf, 33) == Result::Length);
  CHECK(auth.isArmed());
  CHECK(auth.verify(SECRET, SECRET_LEN, buf, 0) == Result::Length);
  CHECK(auth.isArmed());
  CHECK(auth.verify(SECRET, SECRET_LEN, buf, RESP_LEN) == Result::Ok);
  CHECK(auth.unlocked());
}

static void test_disconnect_clears_state() {
  ChallengeAuth auth;
  uint8_t chal[CHAL_LEN];
  for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)(200 - i);
  auth.arm(chal);
  uint8_t resp[RESP_LEN]; expectedFor(chal, resp);
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::Ok);
  auth.clear();                                  // GAP disconnect
  CHECK(!auth.isArmed());
  CHECK(!auth.unlocked());                       // latched unlock lost with the link
  CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::NoChallenge);
  auth.consumeUnlock();                          // no-op on cleared state
}

// ---------------------------------------------------------------------------
// Challenge freshness: every armed challenge must differ (models TRNG bytes).
// ---------------------------------------------------------------------------
static void test_distinct_challenges_distinct_responses() {
  uint8_t prev[CHAL_LEN] = {0};
  for (int round = 0; round < 16; round++) {
    ChallengeAuth auth;
    uint8_t chal[CHAL_LEN];
    for (size_t i = 0; i < CHAL_LEN; i++) chal[i] = (uint8_t)(round * 17 + i * 31 + 5);
    auth.arm(chal);
    if (round) CHECK(std::memcmp(chal, prev, CHAL_LEN) != 0);
    std::memcpy(prev, chal, CHAL_LEN);
    uint8_t resp[RESP_LEN]; expectedFor(chal, resp);
    CHECK(auth.verify(SECRET, SECRET_LEN, resp, RESP_LEN) == Result::Ok);
    auth.consumeUnlock();
  }
}

int main() {
  test_hmac_vectors();
  test_const_time_eq();
  test_happy_path();
  test_wrong_secret_rejected();
  test_single_use_replay_rejected();
  test_stale_challenge_rejected();
  test_no_challenge_rejected();
  test_bad_length_rejected_without_consuming();
  test_disconnect_clears_state();
  test_distinct_challenges_distinct_responses();
  std::printf("auth_core_test: %d checks passed\n", g_pass);
  return 0;
}
