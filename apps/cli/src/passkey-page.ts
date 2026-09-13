// パスキー PRF 取得ページの資産(CRYPTO_SPEC §8.2 / integration-options.md 補足 20 裁定 C)。
//
// CLI が 127.0.0.1 で配る localhost ページの HTML / JS / CSS を**文字列定数**として
// バイナリに同梱する(`import … with { type: "text" }` は vitest と tsc に追加インフラが
// 要るため採らない — 補足 20 裁定 C)。ページは WebAuthn の 2 呼び出し(create / get)と
// CLI への fetch 1 回だけを行い、値・鍵素材を DOM に出さない。
//
// 不変条件(passkey-page.test.ts が機械検査する):
//   - inline script なし(`<script src="./app.js">` の 1 つだけ)・`on*=` 属性なし・
//     `javascript:` なし・inline style なし(CSS は別応答)
//   - 第三者のスクリプト / CDN / アナリティクスを読み込まない(絶対 URL の src / href なし)
//   - CSP は配信側(passkey-listener.ts)がヘッダで付ける: `script-src 'self'` 基調
//
// ページ → CLI の POST 本文は {@link PrfPagePost} の形だけ。エラーは列挙した理由コードで
// 返し(自由文を端末へ流さない)、CLI 側が英語の案内に写す。

/** 登録 / 復元でページが受け取る公開パラメータ(`GET /<token>/config.json`)。 */
export type PrfPageConfig =
  | {
      readonly mode: "register";
      readonly rpId: "localhost";
      /** パスキーマネージャに表示される名前(`maruhi · <server host>` — 補足 19-2 裁定 I)。 */
      readonly userName: string;
      /** 登録ごとの 16 バイト乱数(決定的な値にすると同期マネージャが既存を置換する — 裁定 G)。 */
      readonly userIdHex: string;
      /** この登録の prf_salt(32 バイト。公開パラメータ)。 */
      readonly prfSaltHex: string;
      /** 台帳の既存 credential(同じ認証器で 2 つ目を作らせない — excludeCredentials)。 */
      readonly excludeCredentialIdsHex: readonly string[];
    }
  | {
      readonly mode: "recover";
      readonly rpId: "localhost";
      /** 台帳の passkey 行(allowCredentials + credential ごとの prf_salt)。 */
      readonly credentials: readonly {
        readonly credentialIdHex: string;
        readonly prfSaltHex: string;
      }[];
    };

/** ページが失敗を報告するときの理由コード(自由文は運ばない)。 */
export const PRF_PAGE_ERROR_CODES = [
  "not-allowed",
  "already-registered",
  "prf-unsupported",
  "unexpected",
] as const;
export type PrfPageErrorCode = (typeof PRF_PAGE_ERROR_CODES)[number];

/** ページ → CLI の 1 POST(`POST /<token>/prf`)。 */
export type PrfPagePost =
  | { readonly credentialIdHex: string; readonly prfHex: string }
  | { readonly error: PrfPageErrorCode };

/** ページ本体。スクリプトは別応答の `./app.js` だけ(inline なし)。 */
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
<p class="note">This page runs on your own machine (served by the maruhi CLI). Follow your browser's passkey prompt. You can close this tab when the terminal says the step is done.</p>
</main>
<script src="./app.js"></script>
</body>
</html>
`;

/** 最小のスタイル(inline style を持たないための別応答)。 */
export const PRF_PAGE_CSS = `body { margin: 0; font-family: system-ui, sans-serif; background: #fafafa; color: #222; }
main { max-width: 32rem; margin: 4rem auto; padding: 0 1rem; }
h1 { font-size: 1.25rem; font-weight: 600; }
#status { font-size: 1.1rem; }
.note { color: #666; font-size: 0.9rem; }
`;

/**
 * ページのスクリプト。流れ:
 *   1. `./config.json` を取る(公開パラメータ)
 *   2. register: create(prf.eval で対応を見る)→ get(同じ salt で PRF を得る — 復元と
 *      同じ経路で値を取ることで「登録できたが復元で違う値」を構造的に排除する。裁定 G)
 *      recover: get(allowCredentials = 台帳の全 credential、prf.evalByCredential で
 *      credential ごとの salt)
 *   3. `./prf` へ 1 回だけ POST(成功 = credential id + PRF hex、失敗 = 理由コード)
 * `userVerification: "required"`: UV の無い認証器では PRF が黙って欠ける(spike-prf.md §2)。
 */
export const PRF_PAGE_JS = `"use strict";
(function () {
  var statusNode = document.getElementById("status");
  var base = new URL("./", location.href).href;

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

  fetch(base + "config.json")
    .then(function (response) {
      return response.json();
    })
    .then(function (config) {
      return config.mode === "register" ? register(config) : recover(config);
    })
    .catch(function (error) {
      return { error: errorCode(error) };
    })
    .then(function (result) {
      return post(result).then(function () {
        say(
          result.error === undefined
            ? "Done. Return to the terminal (you can close this tab)"
            : "The passkey step did not complete. Return to the terminal for details",
        );
      });
    })
    .catch(function () {
      say("Could not reach the maruhi CLI. Return to the terminal");
    });
})();
`;
