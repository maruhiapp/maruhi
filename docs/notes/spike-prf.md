# K0 spike: obtaining a passkey PRF (a localhost page + a CLI listener)

Status: 2026-09-12 — the pre-spike of KL3 K5 (passkey PRF). Only **the scope checkable inside this environment** (a Bun listener / Chromium's virtual authenticators) was performed. Items that can only be checked on real hardware (the browser × authenticator support table, port forwarding under Codespaces / WSL) belong to the owner's deferred K0 and are **only enumerated here as "unverified"** (the 2026-09-12 ruling at the end of integration-options.md supplement 19-7). The implementation ruling record is supplement 20 of the same file.

Throwaway code (not committed to the repository): a `node:http` listener on Bun, Playwright (borrowed by absolute path from `apps/site`'s devDependencies — no dependency was added to the CLI) + the bundled Chromium's CDP `WebAuthn.addVirtualAuthenticator`.

## 0. Conclusion (the big picture first)

| Item | Result | Verification status |
|---|---|---|
| Listening on `127.0.0.1:0` (a random port) with `node:http` on Bun 1.4.0 and getting `server.address().port` | Works | **Verified** (in-environment) |
| A one-time token in the URL path / exact `Host` match / exact `Origin` match / consumed by 1 POST / a second one gets 404 / closes on timeout / destroys open connections then `close`s | All as expected (each failure shape confirmed with curl) | **Verified** (in-environment) |
| Under CSP `default-src 'none'; script-src 'self'; …`, a separate-file `app.js` runs (no inline script) | Works | **Verified** (Chromium 141) |
| A browser connecting to a `127.0.0.1`-bound listener via `http://localhost:<port>/`, and `create` / `get` succeeding with **rpId = `localhost`** | Works (an IPv4-only environment) | **Verified** (Chromium 141 + virtual authenticator) / **unverified on environments that have ::1** (§3 below) |
| The PRF extension: `get` with `prf.eval.first = prf_salt` → `results.first` (32 bytes). Deterministic for the same salt, a different value for a different salt, works with `allowCredentials` specified | Works (both virtual authenticator kinds — platform (internal) / roaming (usb)) | **Verified** (virtual authenticators) / **real hardware unverified** |
| `prf.eval` at `create` time returns `enabled: true` and `results.first` (Chromium's behavior) | Returned | **Verified** (virtual authenticators) / real hardware and other browsers unverified. **The implementation does not depend on this** (supplement 20 ruling G) |
| An authenticator without UV (user verification): with `userVerification: "preferred"`, the `get`'s PRF result is **silently missing**. With `"required"`, `create` fails explicitly with `NotAllowedError` | Confirmed | **Verified** (virtual authenticators) → the implementation pins `"required"` (ruling G) |
| A `get` passing only an unknown credential id in `allowCredentials` | `NotAllowedError` | **Verified** (virtual authenticators) |
| A `get` with `prf.evalByCredential` (a per-credential salt; multiple `allowCredentials`) | Works; the value matches `eval.first` | **Verified** (virtual authenticators) |
| Bundling HTML / JS via Bun's `import … with { type: "text" }` | Bundles under all 3 paths: `bun run` / `bun build --target=bun` / `--compile`. However **vitest (Vite) cannot transform the `.html` import, and `bun-types` types `*.html` as `HTMLBundle`** | **Verified** → not adopted (ruling C: a TS string constant) |

## 1. Spike 1 — the listener (Bun + `node:http`)

Shape: `createServer` → `listen(0, "127.0.0.1")` → display the URL `http://localhost:<port>/<token>/`. `token` is 32 random bytes in base64url (43 characters).

| Check | Expected | Measured |
|---|---|---|
| `GET /<token>/` (Host `localhost:<port>`) | 200 + the CSP header | 200, `content-security-policy` present |
| The same URL with `Host: 127.0.0.1:<port>` | 404 | 404 |
| A different token | 404 | 404 |
| `GET /<token>/app.js` | 200 text/javascript | 200 |
| `POST /<token>/prf` — no Origin | 404 | 404 |
| `POST` — `Origin: http://evil.example` | 404 | 404 |
| `POST` — Origin matches, malformed body (not hex) | 404 | 404 |
| `POST` — Origin matches, valid body | 204 → listener stops | 204, `server closed` right after |
| Re-POSTing after stop | connection refused | curl exit 7 (connection refused) |
| Nothing arrives | stops on timeout | `shutdown: timeout` under a 2-second setting |

Note: every failure is **the same 404 response** (no reason disclosed). `Connection: close` is attached, and at shutdown the tracked connections are `destroy`ed before `server.close` (the same precedent as `agent.ts`, where keep-alive connections delay close).

Environment fact: in this environment `localhost` resolves to `127.0.0.1` only, and **`lo` has no `::1`** (binding to `::1` fails). Therefore "on a dual-stack host, do Chrome / Safari try `localhost` as ::1 then 127.0.0.1 and connect via fallback" is **unverified** (§3).

## 2. Spike 2 — the Chromium virtual authenticator + PRF

Chromium 141.0.7390.37 (bundled with Playwright, `/opt/pw-browsers/chromium`), `WebAuthn.enable` → `addVirtualAuthenticator({ protocol: "ctap2", ctap2Version: "ctap2_1", transport, hasResidentKey: true, hasUserVerification, isUserVerified, hasPrf: true, automaticPresenceSimulation: true })`.

The page-side calls (essentials):

```js
// Registration: create (PRF support is read from enabled)
navigator.credentials.create({ publicKey: {
  rp: { id: "localhost", name: "maruhi" },
  user: { id: <16-byte random>, name: "maruhi · <server host>", displayName: same },
  challenge: <32-byte random>,
  pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
  authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  extensions: { prf: { eval: { first: prf_salt } } },
}});
// Retrieval (the same at registration and recovery): get → getClientExtensionResults().prf.results.first
navigator.credentials.get({ publicKey: {
  rpId: "localhost", challenge: <random>,
  allowCredentials: [{ type: "public-key", id: credential_id }],
  userVerification: "required",
  extensions: { prf: { eval: { first: prf_salt } } },
}});
```

| Virtual authenticator | `userVerification` | create `prf.enabled` | create `results.first` | get × 2 (same salt) | different salt | discoverable (empty allow) | Result |
|---|---|---|---|---|---|---|---|
| internal (platform), with UV | preferred | true | returned | match | different value | works (same value) | **works** |
| usb (roaming), with UV | preferred | true | returned | match | different value | works | **works** |
| internal, with UV | required | true | returned | match | different value | works | **works** (a `get` with an unknown id → `NotAllowedError`) |
| internal, **no UV** | preferred | true | returned | **no `results` (null)** | — | `NotAllowedError` | PRF silently missing |
| internal, **no UV** | required | — | — | — | — | — | `create` → `NotAllowedError` (explicit failure) |

Reading:
- CTAP2 hmac-secret produces different output depending on UV presence, and Chromium returns no PRF result without UV. **Pinning `"required"`** avoids creating the shape "registration succeeded but recovery returns no PRF" (the failure is visible at registration time).
- Since a `get` with `allowCredentials` works, at recovery the ledger's `credentialIdHex` values are all passed and the wrap row is selected by the response's `rawId` (supplement 20 ruling F).
- A second POST is 404 (one-time consumption holds even for a `fetch` from Chromium).
- **`prf.evalByCredential`** (re-tested 2026-09-13): passing 2 entries in `allowCredentials` (an unknown id + a real one) and specifying a per-credential salt via `evalByCredential` (keyed by the credential id's base64url), the `get` succeeded with the real credential and `results.first` matched the same-salt `eval.first`. The implementation's recovery path (`recover` in passkey-page.ts) uses this form (identical even for a single entry).
- The page's `fetch` is same-origin with no `credentials`, and gets an `Origin` header of `http://localhost:<port>` (the listener's exact-match check passes).

## 3. Unverified (the owner's deferred K0 — real hardware required)

**Nothing written in this section has been verified. Do not write this section's content into the public docs.**

- The browser × authenticator PRF support table: Chrome / Edge / Safari / Firefox × platform (Touch ID / Windows Hello / Android) / roaming (CTAP2.1 hmac-secret like YubiKeys) / passkey managers (iCloud Keychain / Google Password Manager / 1Password / Bitwarden). In particular: (a) the reliability of `prf.enabled` at `create` time, (b) whether `userVerification: "required"` passes on Windows Hello / Touch ID, (c) whether a synced passkey's PRF returns the same value on another machine (the KEK's portability), (d) how `excludeCredentials` is handled (does it refuse a second passkey on the same authenticator)
- On environments where `localhost` resolution includes ::1 (the macOS / Windows default), whether Chrome / Safari / Firefox reach a `127.0.0.1`-bound listener via fallback. If not, bind `::1` on the same port too (supplement 20 ruling B's fallback plan)
- VS Code desktop (Remote SSH / Dev Containers) automatic port forwarding: if the forwarded URL stays `localhost:<port>`, rpId=localhost should hold (unconfirmed)
- Web Codespaces: the forwarded URL becomes `*.app.github.dev` and rpId=localhost does not hold → whether guidance to pull the port to the local machine via `gh codespace ports forward <port>:<port>` is needed, and its wording
- WSL2: reaching the WSL `localhost:<port>` from the Windows-side browser (localhostForwarding)
- Whether the browser auto-launch (`openBrowser` = `xdg-open` / `open` / `cmd /c start`) passes the URL's token portion (base64url) through intact
- How the display name (`user.name` = `maruhi · <server host>`) actually appears inside passkey managers

## 4. Where the throwaway code lives

Not committed to the repository (scratchpad only). The essentials needed to reproduce are as in §1 / §2, and the CLI-side implementation (`apps/cli/src/passkey-listener.ts` / `passkey-page.ts`) carries the spike-1 shape as-is as an Effect resource. The browser round trip is not built into the CLI's tests (supplement 20 ruling J — Playwright and Chromium are not added to the CLI's dependencies).
