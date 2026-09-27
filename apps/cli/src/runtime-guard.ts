// A side-effect module that stops at the entry any runtime other
// than Bun (e.g. running the npm distribution on Node.js). Placed
// at the head of bin.ts's imports, it is always evaluated before
// the other modules (ES imports are hoisted, so writing this check
// in bin.ts's body would not guard against "changes that touch Bun
// API at import time").
//
// Letting it through would only produce a ReferenceError at the
// first touch of keychain (Bun.secrets) or run (Bun.spawn) — the
// "wrong runtime" cause would never reach the user.

if (typeof globalThis.Bun === "undefined") {
  console.error(
    "The maruhi CLI runs only on the Bun runtime (https://bun.sh). " +
      "Install Bun, or use a precompiled binary from GitHub Releases.",
  );
  process.exit(1);
}
