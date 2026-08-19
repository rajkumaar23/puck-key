// Fresh-boot regression for the SHARED ncore::State.
//
// On device, st() is a function-local static first touched by the very
// first tag-based alert AFTER boot - before reset() is ever called. The
// tag table must already be populated by the State() constructor, or
// find(tag) returns null and every alert (login/ntp/wifi/unlock/auth/heap)
// silently no-ops.
//
// A fresh process (this test) + alert() with NO reset() call mirrors that
// exactly. Against the pre-fix core (no State() constructor) the shared
// st() has null tags, so find() is null and alert() returns false -> this
// test fails. That is the regression we are guarding.

#include "../receiver/notify_core.h"
#include <cstdio>

using namespace ncore;

int main() {
  // NOTE: deliberately NO reset() here - fresh boot state.
  if (find("login") == nullptr) {
    std::printf("FAIL: find(\"login\") is null on fresh boot\n");
    return 1;
  }
  if (alert("login", 0, 15) != true) {
    std::printf("FAIL: alert(\"login\") did not fire on fresh boot\n");
    return 1;
  }
  if (alert("ntp", 0, 60) != true) {
    std::printf("FAIL: alert(\"ntp\") did not fire on fresh boot\n");
    return 1;
  }
  std::printf("fresh-boot shared-State OK\n");
  return 0;
}
