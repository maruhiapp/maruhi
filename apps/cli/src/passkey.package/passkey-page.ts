// Assets of the passkey-PRF acquisition page (CRYPTO_SPEC §8.2 /
// integration-options.md supplement 20 ruling C).
//
// The HTML / JS / CSS of the localhost page the CLI serves on
// 127.0.0.1 are bundled into the binary as **string constants**
// (`import … with { type: "text" }` needs extra infra in vitest and
// tsc, so it is not used — supplement 20 ruling C). The page makes
// only the 2 WebAuthn calls (create / get) and one fetch to the
// CLI, and never puts values or key material onto the DOM.
//
// Invariants (passkey-listener.test.ts checks them mechanically):
//   - No inline script (only the one `<script src="./app.js">`), no
//     `on*=` attributes, no `javascript:`, no inline style (CSS is a
//     separate response)
//   - No third-party scripts / CDN / analytics (no absolute-URL src
//     / href)
//   - CSP is attached as a header by the serving side
//     (passkey-listener.ts): `script-src 'self'` baseline
//
// The page → CLI POST body is only the {@link PrfPagePost} +
// confirmation-code shape. Errors come back as the enumerated
// reason codes (no free-form text flows to the terminal); the CLI
// maps them to English guidance.
//
// Confirmation code (supplement 20 ruling A revision 1): the URL's
// token rides on the browser launch's argv, so a user of a
// different UID on the same machine can read it
// (`/proc/<pid>/cmdline`). Accepting a POST on the token alone
// would let someone seal the master key with a fake PRF (the
// registration path). So the CLI displays a 6-digit confirmation
// code on the terminal, and the code the user types into the page
// rides inside the POST. The code only travels between the user's
// terminal and browser — it is on neither argv nor an HTTP
// response. A POST with a mismatched code does not consume the
// ceremony (the correct page's POST still passes later).

/** The public parameters the page receives for registration / recovery (`GET /<token>/config.json`). */
export type PrfPageConfig =
  | {
      readonly mode: "register";
      readonly rpId: "localhost";
      /** The name shown in the passkey manager (`maruhi · <server host>` — supplement 19-2 ruling I). */
      readonly userName: string;
      /** A per-registration 16-byte random (a deterministic value makes a syncing manager replace the existing one — ruling G). */
      readonly userIdHex: string;
      /** This registration's prf_salt (32 bytes. A public parameter). */
      readonly prfSaltHex: string;
      /** The ledger's existing credentials (prevents making a second one on the same authenticator — excludeCredentials). */
      readonly excludeCredentialIdsHex: readonly string[];
    }
  | {
      readonly mode: "recover";
      readonly rpId: "localhost";
      /** The ledger's passkey rows (allowCredentials + a per-credential prf_salt). */
      readonly credentials: readonly {
        readonly credentialIdHex: string;
        readonly prfSaltHex: string;
      }[];
    };

/** The reason codes for when the page reports a failure (no free-form text is carried). */
export const PRF_PAGE_ERROR_CODES = [
  "not-allowed",
  "already-registered",
  "prf-unsupported",
  "unexpected",
] as const;
export type PrfPageErrorCode = (typeof PRF_PAGE_ERROR_CODES)[number];

/** The body of the page → CLI's one POST (`POST /<token>/prf`) (the listener strips the confirmation code). */
export type PrfPagePost =
  | { readonly credentialIdHex: string; readonly prfHex: string }
  | { readonly error: PrfPageErrorCode };

/** The confirmation code's shape (6 digits. The terminal displays `123 456`; the page ignores spaces). */
export const CONFIRM_CODE_PATTERN = /^[0-9]{6}$/;

/** The page body. The script is only the separately-served `./app.js` (no inline). */
export const PRF_PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>maruhi passkey</title>
<link rel="stylesheet" href="./style.css">
</head>
<body>
<main>
<h1>maruhi passkey</h1>
<p id="status">Starting…</p>
<p id="entry" hidden>
<label for="code">Confirmation code shown in the terminal</label>
<input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" placeholder="123 456">
<button id="continue" type="button">Continue</button>
</p>
<p class="note">This page runs on your own machine (served by the maruhi CLI). Type the code from the terminal, then follow your browser's passkey prompt. You can close this tab when the terminal says the step is done.</p>
</main>
<script src="./app.js"></script>
</body>
</html>
`;

/** Minimal styling (a separate response so there is no inline style). */
export const PRF_PAGE_CSS = `body { margin: 0; font-family: system-ui, sans-serif; background: #fafafa; color: #222; }
main { max-width: 32rem; margin: 4rem auto; padding: 0 1rem; }
h1 { font-size: 1.25rem; font-weight: 600; }
#status { font-size: 1.1rem; }
#entry label { display: block; margin-bottom: 0.25rem; }
#entry input { font-size: 1.25rem; letter-spacing: 0.15em; width: 8rem; padding: 0.25rem 0.5rem; }
#entry button { font-size: 1rem; margin-left: 0.5rem; padding: 0.3rem 0.9rem; }
.note { color: #666; font-size: 0.9rem; }
`;

/**
 * The page's script. The flow:
 *   1. Fetches `./config.json` (public parameters)
 *   2. register: create (checks support via prf.eval) → get
 *      (obtains the PRF with the same salt — taking the value
 *      through the same path as restore structurally rules out
 *      "registered but restore produced a different value". Ruling
 *      G)
 *      recover: get (allowCredentials = the ledger's every
 *      credential; per-credential salt via prf.evalByCredential)
 *   3. POSTs to `./prf` (the terminal's confirmation code +
 *      success = credential id + PRF hex / failure = a reason
 *      code). On a code mismatch (404), retype and resend the same
 *      result (no biometric redo)
 * `userVerification: "required"`: on an authenticator without UV
 * the PRF silently goes missing (spike-prf.md §2).
 */
export const PRF_PAGE_JS = `"use strict";
(function () {
  var statusNode = document.getElementById("status");
  var entryNode = document.getElementById("entry");
  var codeInput = document.getElementById("code");
  var continueButton = document.getElementById("continue");
  var base = new URL("./", location.href).href;
  var pending = null; // the ceremony result kept for retyping the confirmation code (until a POST goes through)

  function say(text) {
    statusNode.textContent = text;
  }
  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
  function bytesToHex(buffer) {
    var bytes = new Uint8Array(buffer);
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return out;
  }
  function base64url(bytes) {
    var text = "";
    for (var i = 0; i < bytes.length; i++) {
      text += String.fromCharCode(bytes[i]);
    }
    return btoa(text).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function challenge() {
    return crypto.getRandomValues(new Uint8Array(32));
  }
  function post(body) {
    return fetch(base + "prf", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }
  function readCode() {
    return codeInput.value.replace(/\\s+/g, "");
  }
  function setEntryEnabled(enabled) {
    codeInput.disabled = !enabled;
    continueButton.disabled = !enabled;
  }
  function prfResult(credential) {
    var ext = credential.getClientExtensionResults();
    return ext.prf && ext.prf.results && ext.prf.results.first ? ext.prf.results.first : null;
  }
  function errorCode(error) {
    var name = error && error.name;
    if (name === "NotAllowedError") return "not-allowed";
    if (name === "InvalidStateError") return "already-registered";
    return "unexpected";
  }

  function register(config) {
    var salt = hexToBytes(config.prfSaltHex);
    say("Create a passkey for maruhi when your browser asks (step 1 of 2)");
    return navigator.credentials
      .create({
        publicKey: {
          rp: { id: config.rpId, name: "maruhi" },
          user: {
            id: hexToBytes(config.userIdHex),
            name: config.userName,
            displayName: config.userName,
          },
          challenge: challenge(),
          pubKeyCredParams: [
            { type: "public-key", alg: -8 },
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          excludeCredentials: config.excludeCredentialIdsHex.map(function (idHex) {
            return { type: "public-key", id: hexToBytes(idHex) };
          }),
          authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
          attestation: "none",
          extensions: { prf: { eval: { first: salt } } },
        },
      })
      .then(function (created) {
        var ext = created.getClientExtensionResults();
        if (!ext.prf || ext.prf.enabled !== true) {
          return { error: "prf-unsupported" };
        }
        var idHex = bytesToHex(created.rawId);
        say("Verify again to derive the wrapping key (step 2 of 2)");
        return navigator.credentials
          .get({
            publicKey: {
              rpId: config.rpId,
              challenge: challenge(),
              allowCredentials: [{ type: "public-key", id: created.rawId }],
              userVerification: "required",
              extensions: { prf: { eval: { first: salt } } },
            },
          })
          .then(function (assertion) {
            var out = prfResult(assertion);
            return out === null
              ? { error: "prf-unsupported" }
              : { credentialIdHex: idHex, prfHex: bytesToHex(out) };
          });
      });
  }

  function recover(config) {
    var allow = [];
    var evalByCredential = {};
    config.credentials.forEach(function (entry) {
      var id = hexToBytes(entry.credentialIdHex);
      allow.push({ type: "public-key", id: id });
      evalByCredential[base64url(id)] = { first: hexToBytes(entry.prfSaltHex) };
    });
    say("Use your maruhi passkey when your browser asks");
    return navigator.credentials
      .get({
        publicKey: {
          rpId: config.rpId,
          challenge: challenge(),
          allowCredentials: allow,
          userVerification: "required",
          extensions: { prf: { evalByCredential: evalByCredential } },
        },
      })
      .then(function (assertion) {
        var out = prfResult(assertion);
        return out === null
          ? { error: "prf-unsupported" }
          : { credentialIdHex: bytesToHex(assertion.rawId), prfHex: bytesToHex(out) };
      });
  }

  function submit(result, code) {
    var body = { code: code };
    Object.keys(result).forEach(function (key) {
      body[key] = result[key];
    });
    return post(body).then(function (response) {
      if (response.status === 204) {
        pending = null;
        entryNode.hidden = true;
        say(
          result.error === undefined
            ? "Done. Return to the terminal (you can close this tab)"
            : "The passkey step did not complete. Return to the terminal for details",
        );
        return;
      }
      // Code mismatch (or the ceremony ended): keep the result so the same one can be resent after a retype
      pending = result;
      setEntryEnabled(true);
      say("The code did not match the terminal. Check it and try again");
    });
  }

  function run(config) {
    var code = readCode();
    if (!/^[0-9]{6}$/.test(code)) {
      say("Enter the 6-digit confirmation code shown in the terminal");
      return;
    }
    setEntryEnabled(false);
    var step = pending !== null
      ? Promise.resolve(pending)
      : (config.mode === "register" ? register(config) : recover(config)).catch(function (error) {
          return { error: errorCode(error) };
        });
    step
      .then(function (result) {
        return submit(result, code);
      })
      .catch(function () {
        say("Could not reach the maruhi CLI. Return to the terminal");
      });
  }

  fetch(base + "config.json")
    .then(function (response) {
      return response.json();
    })
    .then(function (config) {
      say("Type the confirmation code from the terminal, then continue");
      entryNode.hidden = false;
      codeInput.focus();
      continueButton.addEventListener("click", function () {
        run(config);
      });
      codeInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
          run(config);
        }
      });
    })
    .catch(function () {
      say("Could not reach the maruhi CLI. Return to the terminal");
    });
})();
`;
