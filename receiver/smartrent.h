#pragma once
// SmartRent cloud client: login (+ 2FA TOTP), token refresh, and the unlock PATCH,
// sent over a persistent TLS socket that's kept warm so an unlock is just the
// ~200 ms request instead of paying a ~900 ms handshake.

void smartrentBegin();          // one-time init (TLS setInsecure on the persistent socket)
bool smartrentLogin();          // login (+2FA); caches the access token; true on success
bool smartrentHasToken();       // is there a cached access token?
int  smartrentUnlock();         // ensure token -> send unlock PATCH (retries once on 401)
void smartrentPrewarm();        // open the persistent TLS socket if it isn't already
bool smartrentSocketOpen();     // is the persistent socket connected?
void smartrentMaintainToken();  // refresh the token ahead of expiry (call while idle)
