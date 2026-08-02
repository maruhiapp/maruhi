# セッション 04 メモ(packages/crypto 実装 — Phase 1 着工)

日付: 2026-08-02。前提: セッション 03 の全 PR(#8〜#11)は main にマージ済み。
スコープ: packages/crypto(E2EE コア)のみ。CRYPTO_SPEC 準拠 + テストベクター全通過。

## 1. やったこと(コミット順 = 層順)

1. **テストベクター補完**(実装より先にコミット): chain-entries.json を seq 5〜9 に延長
   (add_member(reader) → change_role(admin) → grant_server → rotate_epoch(admin 実行)→
   revoke_server)。署名系 negative 4 件 + 認可系 negative(`kind: "authorization"`)7 件 +
   `expected_head_states`(状態導出 API の期待値)を追加。verify_reference.mjs 拡張、全 99 検査 PASS
2. **§2.1 エンコーダ** + 型付きエラー + `internal.package` 境界
3. **§3 鍵**: X25519(panva hpke API 経由)/ Ed25519(WebCrypto)、FP、DEK 生成
4. **§4 変数暗号化**: AES-256-GCM + LP AAD。nonce は内部生成のみ(注入 API なし)
5. **§5 DEK ラップ**: HPKE Base 単発 Seal/Open。Open は KeyPair 渡しのみ
6. **§6 チェーン**: 正規化・署名・検証(role 権限含む)・状態導出(メンバー集合 + 有効 grant + 観測エポック)
7. **§8 リカバリーラップ**: HKDF(salt=空)+ AES-256-GCM
8. **3 環境テスト基盤**: node / workerd / browser の vitest + Bun 直接実行。CI step 11 に独立ステップ追加

全 4 実行環境(Node / workerd / Chromium / Bun 1.3.14)で全 123 チェック PASS。

## 2. 実装判断(PR レビューで特に見てほしい点)

- **エラー設計はデフォルト (b)**(裁定待ち): crypto は Effect 非依存の純粋関数 +
  判別可能 union(`CryptoResult`)。比較は PR 本文参照。裁定が (a) ならマージ前にラップし直す
- **サーバー鍵 FP = `SHA-256(server_enc_pub)[:16]`**(仕様に明文なし): サーバーは enc 鍵のみ(§9)で
  §3 のユーザー FP 定義(enc||sig)を適用できないため。ベクターで固定。**要レビュー** →
  承認されたら CRYPTO_SPEC §9 への明文化を提案
- **grant_server の scope_environments**: 環境 ID リストを LP エンコードし、その hex 小文字文字列を
  payload の 1 フィールドとして外側 LP に載せる(binary_encoding 規約と同型の入れ子 LP)。
  リスト順序は署名対象の一部。**要レビュー** → 同上、§6.2 への明文化を提案
- **同一サーバー鍵への再 grant はスコープ拡大(旧 ⊆ 新)のみ受理**(2026-08-02 所有者裁定。
  当初は置き換えで実装したが、縮小を許すと revoke_server + rotate_epoch(§7 の全環境
  ローテーション義務)を迂回できてしまう穴があるため変更した。縮小は必ず失効経路を通す。
  ベクター `authz-grant-scope-narrowed` で固定、拒否理由コードは `grant-scope-narrowed`)
- **rotate_epoch の new_epoch 単調性は検証しない**(§6.3 に規定なし。同期ロジックと同時に設計)。
  構造検証は「1 以上の安全な整数」のみ
- **エラー判別子は `_tag` でなく `kind`**: oxlint の no-underscore-dangle と衝突するため。
  Effect マッピングは core 側で kind ごとに行う
- **検証順序**: フレーミング → payload 構造 → actor 解決(non-member / FP 不一致)→ 署名 →
  認可 + 意味検証。認可系ベクターの expected_reason はこの順序を前提に固定してある
- **Ed25519 の決定論性をテストに利用**: ベクター全エントリを seed から再署名して signature_hex の
  完全一致を確認している(正規化と署名の同時固定。WebCrypto Ed25519 は RFC 8032 決定論的)
- **秘密鍵は既定 extractable=false**。エクスポートが要る生成時(リカバリーブロブ作成)のみ
  呼び出し側が明示 opt-in。nonce・HKDF salt は API から注入不可(誤用を構造的に排除)

## 3. ハマったこと・環境知見

- **システム Python の cryptography が壊れている**(`_cffi_backend` 欠落)。venv を作って
  `pip install cryptography`(50.0.0)で参照ツールを実行した。ベクター再生成は
  entries 1〜4 のバイト列が既存とビット一致することを diff で確認済み(append-only 延長)
- **ブラウザテストの Chromium リビジョン不一致**: プリインストールは chromium-1194(playwright
  1.56 系)だが、リポジトリの playwright ピンは 1.62.1(revision 1234 要求)。素の
  `bunx playwright install chromium` は**グローバルキャッシュの 1.56.1 に解決されて no-op になる**
  罠がある。`cd apps/web && bun x playwright install chromium` でリポジトリのピンを解決させて
  1234 をダウンロードしたら browser プロジェクトも PASS。CI は bunx がリポジトリの
  node_modules を解決するので問題にならない想定(step 11 に保険の install を入れてある)
- **fallow の複雑度ゲート**(cyclomatic ≥ 10 / 60 行超で error)は暗号検証コードだと簡単に踏む。
  op ごとの apply / shape 関数へ分割して解消した(結果的に見通しは良くなった)
- root の vitest glob(packages/*/vitest.config.ts)は「ファイル名完全一致」なので、
  vitest.workerd.config.ts / vitest.browser.config.ts を同居させても step 7 には载らない

## 4. 次セッションへの申し送り

- **PR マージ後に ROADMAP の「E2EE コア」をチェックオフする**(このセッションでは PR がレビュー待ちのため未実施)
- エラー設計の裁定が (a)(Effect を crypto に入れる)なら、マージ前にラップし直す
- 仕様側の追記提案(裁定後に別 PR で): CRYPTO_SPEC §9 にサーバー鍵 FP 定義、§6.2 に
  scope_environments の正規化、§6.2 に再 grant の意味論
- 未実装(意図的スコープ外): §6.3 の DEK ラップ先一致検査・ヘッドゴシップ(検証 API の
  ChainState を入力とする同期ロジック)、§6.4 サーバー側検証・CAS、§7 ローテーション
  オーケストレーション、リカバリーコードの Base32 表示・master 鍵ブロブの直列化形式(CLI 実装時)
- spikes/ は温存中(spike-c 構成の移植完了。削除判断は所有者)
- 参照ツールの venv 手順は test-vectors/README.md に書いていない(使い捨てツールのため)。
  再生成が必要なら本メモの §3 を参照
