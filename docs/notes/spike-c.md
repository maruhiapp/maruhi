# スパイク C 検証結果: E2EE ラウンドトリップ + HPKE ライブラリ選定

日付: 2026-08-01。ROADMAP Phase 0 の検証スパイク。CRYPTO_SPEC 未決事項 #1(HPKE ライブラリ選定)の判断材料。
**使い捨てコードは `spikes/spike-c/` にあり、製品コードではない。`packages/crypto` には一切コードを置いていない。**
最終選定は人間が行う(本メモは推奨まで)。

## 検証対象

CRYPTO_SPEC §2 のスイート **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM**(HPKE Base mode)を、2026-08 時点の有力候補 2 ライブラリで検証した。

| 候補 | 構成 | バージョン(厳密ピン) |
|---|---|---|
| **hpke-js**(dajiaji) | `@hpke/core` + `@hpke/dhkem-x25519`(+ 内部依存 `@hpke/common`) | 1.9.0 / 1.8.0 |
| **hpke**(panva) | 単一パッケージ・ゼロ依存 | 1.1.3 |

候補洗い出しの結果(2026-08-01 時点の最新調査):

- **@noble 系に独立した HPKE 実装は存在しない**。@noble/curves・@noble/ciphers はプリミティブのみ。noble ベースの HPKE は `@panva/hpke-noble`(panva hpke の拡張。PQ KEM / SHAKE KDF / ChaCha20Poly1305 用)として存在するが、本スイート(X25519 + AES-256-GCM)には不要。CRYPTO_SPEC 未決事項 #1 の候補表記「@noble 系」は実質 panva hpke に収斂する
- その他の候補(`hpke-wasm` 等)は メンテ状況・普及度で上記 2 つに劣後するため深掘りしなかった
- panva hpke は 2022 年から存在(0.x)、**2025-12 に v1.0 化**された新しめの選択肢。RFC 9180 の Standards Track 再発行(draft-ietf-hpke-hpke)にも追従している

## 検証内容と結果

検証項目(`spikes/spike-c/src/checks.ts`。全環境で同一のチェックを実行):

1. 各ライブラリの自己ラウンドトリップ(Seal → Open)
2. 文脈束縛: info 不一致・aad 改竄で復号失敗すること(CRYPTO_SPEC 設計原則 3 の前提)
3. 相互運用: hpke-js で Seal → panva で Open、およびその逆(RFC 9180 準拠の間接証拠)
4. RFC 9180 公式テストベクター(cfrg/draft-irtf-cfrg-hpke の test-vectors.json から本スイート Base mode を抽出):
   - DeriveKeyPair(ikmR) が (pkRm, skRm) に一致(両ライブラリ)
   - Open 方向のベクター一致(両ライブラリ。受信側は決定論的なので derandomize 不要)
   - Seal 方向のベクター一致(hpke-js のみ。`ekm` パラメータで derandomize 可能)

結果マトリクス(**全環境・全チェック合格**):

| 環境 | 実行方法 | hpke-js | hpke (panva) |
|---|---|---|---|
| Node 22(基準) | vitest プロジェクト `spike-c-node` | PASS | PASS |
| workerd | `@cloudflare/vitest-pool-workers` 0.20.1(userAgent = `Cloudflare-Workers` を確認) | PASS | PASS |
| ブラウザ(Chromium 151 headless) | vitest browser mode + `@vitest/browser-playwright` | PASS | PASS |
| Bun 1.3.14 | `bun run src/run-in-bun.ts`(vitest は Node 上で走るため直接実行) | PASS | PASS |

## 動いたこと

- 両ライブラリとも、本スイートの Seal/Open ラウンドトリップ・info/aad の文脈束縛・相互運用・RFC 9180 ベクター(上記の範囲)が **4 環境すべてで成立**
- WebCrypto X25519(panva が依存)は workerd・Bun 1.3.14・Chromium で実測動作。ブラウザ対応下限は Chrome/Edge 133+、Firefox 130+、Safari 17.0+(caniuse 確認。2026 年時点で実質 Baseline)
- panva hpke: 非抽出(extractable=false)秘密鍵でも **KeyPair(公開鍵込み)を渡せば Open が動く**(Bun / Node で実測)。CRYPTO_SPEC §3 の「ブラウザ: IndexedDB + 非抽出設定」方針と両立する
- hpke-js: `createSenderContext({ ekm })` で Seal 方向も derandomize でき、公式ベクターの enc / ct と完全一致を確認

## 動かなかったこと・ハマったこと

- **panva hpke の Open に秘密鍵単体を渡す場合、extractable=true が必須**(Node / workerd / Bun / Chromium すべて)。エラーは `"privateKey" must be extractable or a Key Pair must be used in this runtime`。内部で秘密鍵から公開鍵を導出するための制約。→ 実装時は「KeyPair を渡す」を標準にすれば非抽出のまま運用できる(上記の通り実測済み)
- panva hpke は単発 Seal に ikmE/skE を注入する手段がなく(意図的な API 設計)、**Seal 方向のベクター一致検証は不可**。Open 方向ベクター + 相互運用で間接的に担保した
- `spikes/` はルート workspaces(`packages/*`, `apps/*`)外のため、`bun install` がルートの workspace として解決してしまい依存が入らない。**ディレクトリ直下に `bunfig.toml` を置くと独立プロジェクトとして解決される**(spike-b / 将来のスパイクでも同じ手が使える)
- 初回のバンドルサイズ計測で生成物(`.bundle-tmp/`)を消し忘れ、ルート oxlint が生成 JS を lint して大量エラー。生成物は即削除する運用にした

## 評価軸ごとの比較

| 評価軸 | hpke-js(dajiaji) | hpke(panva) |
|---|---|---|
| 3 環境での動作 | ✅ 4/4 環境 | ✅ 4/4 環境 |
| 依存数 | `@hpke/common` 1 つ(ただし X25519 は **noble-curves の ed25519 モジュールをベンダリング**。監査系譜が npm の @noble/curves と切れている) | **0**(WebCrypto のみ) |
| バンドルサイズ(bun build --minify、スイート一式) | **566 KB(gzip 169 KB)**。ベンダリングされた ed25519/ristretto コード一式を含む | **16 KB(gzip 5 KB)** |
| 監査状況 | 正式監査なし(README 明記)。**CVE-2025-64767(Critical 9.1、2025-11)**: SenderContext.seal() の並行実行で AEAD nonce 再利用。1.7.5 で修正済み | 正式監査なし。脅威モデル文書と Security Policy あり。既知 CVE なし。作者 Filip Skokan は Node.js TSC メンバー・jose(週数千万 DL)の作者 |
| RFC 9180 ベクター | ✅ 通過(Seal 方向も ekm で直接検証可能。プロジェクト自体も公式ベクター + Wycheproof でテスト) | ✅ 通過(Open 方向 + DeriveKeyPair。Seal 方向は相互運用で間接確認。プロジェクト自体も公式ベクターでテスト) |
| メンテ状況 | 2022 年から継続、@hpke/core 1.9.0(2026-03)、週 257K DL、120 stars | v1.0 は 2025-12(若い)、1.1.3(2026-06 更新)、週 854 DL(まだ少ない)。draft-ietf-hpke-hpke(Standards Track 化)へ追従 |
| 将来の PQ 移行(maruhi/v2) | ML-KEM 系は別パッケージ(@hpke/ml-kem 等) | **MLKEM768-X25519 ハイブリッドが本体 API に定義済み**(WebCrypto 未対応ランタイムは @panva/hpke-noble で補完)。CRYPTO_SPEC の v2 構想と一致 |
| テスト容易性 | ekm derandomize があり公式ベクターを Seal 方向まで直接固定できる | derandomize なし。自前テストベクター(§11)は「固定鍵 + Open 方向」+ ラウンドトリップで書く必要がある |

## 推奨(最終選定は人間)

**第一候補: `hpke`(panva)、退避経路: hpke-js。**

理由:

1. **web ダッシュボードは Trusted Computing Base**(CLAUDE.md)であり、「依存ゼロ・16 KB・WebCrypto 委譲」は「サードパーティ供給網を最小に保つ」原則への適合度が圧倒的に高い。hpke-js の 566 KB は大部分がベンダリングされた曲線実装で、npm の @noble/curves 本体(Cure53 監査 2024)と監査系譜が切れているのが supply chain 上の弱点
2. 暗号実装をランタイム(BoringSSL 等のネイティブ実装)に委譲する構造は、JS 実装の nonce 管理バグ(hpke-js CVE-2025-64767 のような)の面を小さくする
3. maruhi/v2 で構想する X25519+ML-KEM-768 ハイブリッドが本体 API に既にある
4. 懸念(若さ・低 DL 数)は、maruhi 側が単発 Seal/Open しか使わないこと・退避経路の存在で緩和できる。両ライブラリの API 表面は薄いアダプタ 1 枚で吸収できることをスパイクで確認済み(`spikes/spike-c/src/adapters.ts` の `HpkeAdapter`)

採用決定時にやること(人間承認後):

- CRYPTO_SPEC §2 の「候補: hpke-js、@noble 系」を選定結果に改訂し、未決事項 #1 を閉じる
- `packages/crypto` の実装では **KeyPair 渡しの Open** を標準とし(非抽出鍵と両立)、秘密鍵単体+extractable 経路を作らない
- テストベクター(§11)は「Open 方向 + DeriveKeyPair + ラウンドトリップ」構成で定義する(Seal 方向の完全固定は panva では不可)

## 採用判断への示唆・残った疑問

1. **ブラウザ実測は Chromium のみ**。Firefox / Safari(WebKit)は caniuse の対応表(FF 130+ / Safari 17+)で判断した。Phase 1 の CI にブラウザマトリクスを足すか、Safari 実機での一度の手動確認を推奨
2. バンドルサイズは `bun build --minify` の参考値。web 本番は Vite(rolldown)なので、スパイク A / Phase 1 での実測で再確認する
3. panva hpke の低ダウンロード数は「壊れたとき自分が最初の発見者になる」リスク。厳密ピン + 更新は独立 PR(ADR-0011 の運用)でカバーする前提
4. CLI(Bun)の OS キーチェーン保存は生バイト → 都度インポートになる想定。extractable=true でのインポートになるため、panva の extractable 制約は CLI 側では実質問題にならない(メモリ上に生鍵がある時点で等価)
5. 監査はどちらも未実施。「監査済みライブラリのみ」(CRYPTO_SPEC 設計原則 2)を字義通り満たす HPKE ライブラリは 2026-08 時点の JS エコシステムに存在しない。ランタイム内蔵 WebCrypto(監査済みネイティブ実装)への委譲度が最も高い選択肢が panva、という整理になる。**設計原則 2 の文言と実態の突き合わせは人間の判断が必要**

## 本採用時に統合すべきルート変更(このブランチで実施済みのもの含む)

- `.fallowrc.json` の `ignorePatterns` に `spikes/**` を追加(実施済み。使い捨てコードを dead-code 解析から除外)。スパイク完了後に spikes/ ごと削除するならこの行も戻す
- ルート `package.json` / `vitest.config.ts` / `ci.yml` は変更していない。スパイクのテストはルートの `bun run test` に含まれない(意図的。使い捨てコードを CI 対象にしない)
- Phase 1 で crypto の 3 環境 CI(CRYPTO_SPEC §11)を組むときは、本スパイクの vitest 3 プロジェクト構成(node / workerd / browser)+ Bun 直接実行、という形がそのまま雛形になる。ブラウザは `@vitest/browser-playwright` 4.1.10 + `bunx playwright install chromium` で CI 上も再現可能
