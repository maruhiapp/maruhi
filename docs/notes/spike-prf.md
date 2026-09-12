# K0 スパイク: パスキー PRF の取得経路(localhost ページ + CLI リスナー)

Status: 2026-09-12 — KL3 K5(パスキー PRF)の前置スパイク。**環境内で確かめられる範囲**(Bun のリスナー / Chromium の仮想認証器)だけを実施した。実機でしか確かめられない項目(ブラウザ × 認証器の対応表、Codespaces / WSL のポート転送)は所有者の後回し K0 の対象であり、**本ノートでは「未検証」として列挙するだけ**である(integration-options.md 補足 19-7 末尾の 2026-09-12 裁定)。実装の裁定録は同 補足 20。

使い捨てコード(リポジトリに入れない): Bun 上の `node:http` リスナー、Playwright(`apps/site` の devDependency を絶対パスで借用。CLI に依存を足していない)+ 同梱 Chromium の CDP `WebAuthn.addVirtualAuthenticator`。

## 0. 結論(先に全体像)

| 項目 | 結果 | 検証の種別 |
|---|---|---|
| Bun 1.4.0 上の `node:http` で `127.0.0.1:0`(乱数ポート)を聞き、`server.address().port` を得る | 動く | **検証済み**(環境内) |
| URL パスのワンタイムトークン / `Host` 完全一致 / `Origin` 完全一致 / 1 POST で消費 / 2 回目は 404 / タイムアウトで閉じる / 開いている接続を切って `close` | すべて期待どおり(curl で各失敗形を確認) | **検証済み**(環境内) |
| CSP `default-src 'none'; script-src 'self'; …` の下で、別ファイルの `app.js` が動く(inline script なし) | 動く | **検証済み**(Chromium 141) |
| `127.0.0.1` に bind したリスナーへ `http://localhost:<port>/` でブラウザが接続し、**rpId = `localhost`** で `create` / `get` が成立する | 成立(IPv4 のみの環境) | **検証済み**(Chromium 141 + 仮想認証器)/ **::1 のある環境は未検証**(下記 §3) |
| PRF 拡張: `get` の `prf.eval.first = prf_salt` → `results.first`(32 バイト)。同じ salt で決定的、別 salt で別値、`allowCredentials` 指定で成立 | 成立(platform〔internal〕/ roaming〔usb〕の両仮想認証器) | **検証済み**(仮想認証器)/ **実機は未検証** |
| `create` 時の `prf.eval` は `enabled: true` と `results.first` を返す(Chromium の挙動) | 返る | **検証済み**(仮想認証器)/ 実機・他ブラウザは未検証。**実装はこれに依存しない**(補足 20 裁定 G) |
| UV(user verification)を持たない認証器: `userVerification: "preferred"` だと `get` の PRF 結果が**黙って欠ける**。`"required"` なら `create` で `NotAllowedError` として明示的に失敗する | 確認 | **検証済み**(仮想認証器) → 実装は `"required"` 固定(裁定 G) |
| `allowCredentials` に未知の credential id だけを渡した `get` | `NotAllowedError` | **検証済み**(仮想認証器) |
| Bun の `import … with { type: "text" }` による HTML / JS の同梱 | `bun run` / `bun build --target=bun` / `--compile` の 3 経路でバンドルされる。ただし **vitest(Vite)が `.html` の import を変換できず、`bun-types` が `*.html` を `HTMLBundle` 型に取る** | **検証済み** → 採らない(裁定 C: TS の文字列定数) |

## 1. スパイク 1 — リスナー(Bun + `node:http`)

形: `createServer` → `listen(0, "127.0.0.1")` → URL `http://localhost:<port>/<token>/` を表示。`token` は 32 バイト乱数の base64url(43 文字)。

| 検査 | 期待 | 実測 |
|---|---|---|
| `GET /<token>/`(Host `localhost:<port>`) | 200 + CSP ヘッダ | 200、`content-security-policy` あり |
| 同じ URL を `Host: 127.0.0.1:<port>` で | 404 | 404 |
| 別トークン | 404 | 404 |
| `GET /<token>/app.js` | 200 text/javascript | 200 |
| `POST /<token>/prf` — Origin 無し | 404 | 404 |
| `POST` — `Origin: http://evil.example` | 404 | 404 |
| `POST` — Origin 一致・本文不正(hex でない) | 404 | 404 |
| `POST` — Origin 一致・本文正常 | 204 → リスナー停止 | 204、直後に `server closed` |
| 停止後の再 POST | 接続拒否 | curl exit 7(connection refused) |
| 何も来ない | タイムアウトで停止 | 2 秒設定で `shutdown: timeout` |

補足: 失敗はすべて **404 の同一応答**(理由を出さない)。`Connection: close` を付け、停止時は台帳に載せた接続を `destroy` してから `server.close`(keep-alive 接続が close を遅らせる `agent.ts` と同じ先例)。

環境の事実: この環境の `localhost` は `127.0.0.1` のみに解決し、**`lo` に `::1` が無い**(`::1` への bind は失敗)。よって「dual-stack ホストで Chrome / Safari が `localhost` を ::1 → 127.0.0.1 の順で試し、フォールバックで繋がるか」は**未検証**(§3)。

## 2. スパイク 2 — Chromium 仮想認証器 + PRF

Chromium 141.0.7390.37(Playwright 同梱、`/opt/pw-browsers/chromium`)、`WebAuthn.enable` → `addVirtualAuthenticator({ protocol: "ctap2", ctap2Version: "ctap2_1", transport, hasResidentKey: true, hasUserVerification, isUserVerified, hasPrf: true, automaticPresenceSimulation: true })`。

ページ側の呼び出し(要点):

```js
// 登録: create(PRF の可否を enabled で見る)
navigator.credentials.create({ publicKey: {
  rp: { id: "localhost", name: "maruhi" },
  user: { id: <16 バイト乱数>, name: "maruhi · <server host>", displayName: 同 },
  challenge: <32 バイト乱数>,
  pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
  authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  extensions: { prf: { eval: { first: prf_salt } } },
}});
// 取得(登録時も復元時も同じ): get → getClientExtensionResults().prf.results.first
navigator.credentials.get({ publicKey: {
  rpId: "localhost", challenge: <乱数>,
  allowCredentials: [{ type: "public-key", id: credential_id }],
  userVerification: "required",
  extensions: { prf: { eval: { first: prf_salt } } },
}});
```

| 仮想認証器 | `userVerification` | create `prf.enabled` | create `results.first` | get × 2(同 salt) | 別 salt | 発見可能(allow 空) | 結果 |
|---|---|---|---|---|---|---|---|
| internal(platform)、UV あり | preferred | true | 返る | 一致 | 別値 | 成立(同じ値) | **成立** |
| usb(roaming)、UV あり | preferred | true | 返る | 一致 | 別値 | 成立 | **成立** |
| internal、UV あり | required | true | 返る | 一致 | 別値 | 成立 | **成立**(未知 id の `get` は `NotAllowedError`) |
| internal、**UV なし** | preferred | true | 返る | **`results` 無し(null)** | — | `NotAllowedError` | PRF が黙って欠ける |
| internal、**UV なし** | required | — | — | — | — | — | `create` が `NotAllowedError`(明示失敗) |

読み取り:
- CTAP2 hmac-secret は UV の有無で別の出力を持ち、Chromium は UV 無しでは PRF 結果を返さない。**`"required"` に固定**すれば「登録できたのに復元で PRF が返らない」形を作らない(失敗が登録時点で見える)。
- `allowCredentials` を渡す `get` が成立するので、復元では台帳の `credentialIdHex` 全件を渡し、応答の `rawId` で wrap 行を選べる(補足 20 裁定 F)。
- 2 回目の POST は 404(1 回限りの消費が Chromium からの `fetch` でも成立)。
- ページの `fetch` は `credentials` 無し・同一オリジンで、`Origin` ヘッダは `http://localhost:<port>` が付く(リスナーの完全一致検査が通る)。

## 3. 未検証(所有者の後回し K0 の対象 — 実機が要る)

**ここに書いたものは何も検証していない。公開 docs にはこの節の内容を書かない。**

- ブラウザ × 認証器の PRF 対応表: Chrome / Edge / Safari / Firefox × platform(Touch ID / Windows Hello / Android)/ roaming(YubiKey 等の CTAP2.1 hmac-secret)/ パスキーマネージャ(iCloud Keychain / Google Password Manager / 1Password / Bitwarden)。特に (a) `create` 時の `prf.enabled` の信頼性、(b) `userVerification: "required"` で Windows Hello / Touch ID が通るか、(c) 同期パスキーで PRF が別端末でも同じ値を返すか(KEK の可搬性)、(d) `excludeCredentials` の扱い(同じ認証器で 2 つ目を拒むか)
- `localhost` の名前解決が ::1 を含む環境(macOS / Windows の既定)で、`127.0.0.1` bind のリスナーへ Chrome / Safari / Firefox がフォールバックで繋がるか。繋がらなければ `::1` にも同ポートで bind する(補足 20 裁定 B の退避案)
- VS Code desktop(Remote SSH / Dev Containers)のポート自動転送: 転送先の URL が `localhost:<port>` のままなら rpId=localhost が成立するはず(未確認)
- Web 版 Codespaces: 転送 URL が `*.app.github.dev` になり rpId=localhost が成立しない → `gh codespace ports forward <port>:<port>` で手元へ引く案内の要否と文面
- WSL2: Windows 側ブラウザから WSL の `localhost:<port>` への到達(localhostForwarding)
- ブラウザの自動起動(`openBrowser` = `xdg-open` / `open` / `cmd /c start`)が URL のトークン部分(base64url)をそのまま渡すか
- パスキーマネージャ上の表示名(`user.name` = `maruhi · <server host>`)が実際にどう見えるか

## 4. 使い捨てコードの置き場

リポジトリには入れない(scratchpad のみ)。再現に必要な要点は §1 / §2 のとおりで、CLI 側の実装(`apps/cli/src/passkey-listener.ts` / `passkey-page.ts`)がスパイク 1 の形をそのまま Effect の資源として持つ。ブラウザ往復は CLI のテストに組み込まない(補足 20 裁定 J — Playwright と Chromium を CLI の依存に足さない)。
