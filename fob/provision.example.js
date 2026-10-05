// provision.example.js
// ---------------------
// Run this ONCE in the Puck.js Web IDE console (left-hand REPL, not uploaded as
// the saved program) to provision a fob. It writes the fob's config to flash and
// sets the clock. puck.js then reads this config on every boot.
//
// Copy this to provision.js (gitignored), fill in real values, then paste/run it.

// Store the fob config in flash under the key "cfg". puck.js reads it via
// require("Storage").readJSON("cfg", true).
//   secret : shared secret keying the HMAC-SHA256 rolling code. MUST match the
//            SECRET define in the receiver's secrets.h.
//   door   : BLE address of the receiver, printed on its serial boot log as
//            "BLE address: ...". Include the address-type suffix (e.g. " public").
require("Storage").writeJSON("cfg", {
  secret: "0000000000000000000000000000000000000000000000000000000000000000",
  door:   "aa:bb:cc:dd:ee:ff public"
});

// The rolling code is time-based, so the Puck needs a real UTC clock. NOTE:
// code pasted into the Web IDE console runs ON THE PUCK, so
// setTime(Date.now()/1000) would set the clock to its own drifted value -
// a no-op. Paste a literal timestamp generated on your computer instead:
//   Terminal:  echo "setTime($(date +%s));"
//   then paste the printed line here.
// Re-run whenever the fob has sat unused for hours (its idle RTC drifts).
setTime(PASTE_UNIX_SECONDS_HERE);
