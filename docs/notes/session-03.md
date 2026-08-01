# セッション 03 メモ(実デプロイ検証 + root 統合 + AUDIT_SPEC + テストベクター)

日付: 2026-08-01。前提: セッション 02 の全 PR(#2〜#5)は main にマージ済み。Cloudflare 資格情報(アカウント API トークン)は Cloud Agents > Secrets に登録済み。

## 1. 実デプロイ検証(ADR-0012 の実証)

すべて `DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false` を付けて実行(「言わざる」)。

### 資格情報の確認

- `wrangler whoami`: **アカウント API トークンで認証成功**(account: maruhi)。wrangler の全操作(deploy / delete / API 直叩き)はこのトークンで問題なく動く
- トークン種別の実測: `/accounts/:id/tokens/verify` → active、`/user/tokens/verify` → `Invalid API Token`。つまり**アカウント所有トークン(Account Owned Token)**であり、`/user/*` 系エンドポイントは一切呼べない

### spike-b: wrangler 経路 — ✅ 成立

- `wrangler deploy` 成功(Total Upload 1272 KiB / gzip 264 KiB。Worker Startup Time 25 ms)
- カウンタ API を実 URL で確認: GET 初期値 0 → increment(+3, +2)→ GET 5(**DO SQLite の永続化がエッジ実環境で成立**)。別名カウンタは 0(DO 分離)。不正 payload は 400(Schema バリデーション)
- `wrangler delete --force` 成功。workers 一覧が空であることを API で確認(残骸なし)

ハマったこと:

1. **wrangler が workers.dev サブドメインを自動登録した**: アカウントにサブドメイン未登録の状態で deploy すると、警告を出しつつ worker 名由来の `spike-b` で登録される(削除 API は存在せず、変更のみ可)。API での `maruhi` への変更はセッションの権限制約で実行できなかったため、**サブドメイン `spike-b` がアカウントに残っている**。所有者がダッシュボード(Workers & Pages → 右ペインの workers.dev)で `maruhi` 等へ変更することを推奨(変更すると旧 URL は即無効。現在 worker は 0 個なので今が変え時)
2. **新規サブドメインの TLS 証明書発行に約 10 分かかる**。それまで `*.spike-b.workers.dev` への接続は SSL handshake failure になる(HTTP 応答ではないので、デプロイ直後の疎通確認はリトライループが必要)

### spike-b: Alchemy v2 経路 — ⛔ アカウント API トークン起因でブロック(所有者へ依頼)

- `CI=1` での環境変数認証自体は成立(資格情報は読まれ、`AuthError: No credentials configured` は出ない)
- `alchemy plan` は state store 必須: `Cloudflare State store not found. Run 'alchemy bootstrap cloudflare' ... or pass --yes`
- `alchemy deploy --yes`(state store ブートストラップ込み)は `alchemy-state-store` worker のデプロイ中に **`Unauthorized: Authentication error`(Cloudflare error 10000)で失敗**
- 原因の裏取り(alchemy 2.0.0-beta.67 のソース確認): state store のブートストラップは **edge-preview セッション + `/user/tokens` 系エンドポイント**を使う(`src/Cloudflare/StateStore/State.ts`、`src/Cli/commands/cloudflare.ts` は `/user/tokens/verify` を「source of truth」とコメント)。これらは**ユーザー API トークン前提**で、アカウント所有トークンでは 401 になる。wrangler が同一トークンで全部動くこととも整合
- **→ 指示どおりここで中断。所有者への依頼: `CLOUDFLARE_API_TOKEN` をユーザー API トークン(dash の My Profile → API Tokens で作成。Workers 編集権限)に差し替えてほしい。**差し替え後の別セッションで `alchemy deploy` / `alchemy destroy` を再検証する
- 失敗はデプロイ前に起きたため**リソースの残骸なし**(workers 一覧空を確認)。ローカルの `spikes/spike-b/.alchemy/log/out` が更新されたのみ(git restore 済み)

### apps/web: Workers Static Assets + _headers(CSP)— ✅ 成立

- `bun run build`(vite build + write-headers.ts)→ `wrangler deploy` 成功。アセット 11 ファイルアップロード(`_headers` はアセットとしては配信されず、設定として消費される — 期待どおり)
- **CSP ヘッダの本番反映を確認**: 実 URL のレスポンスに `content-security-policy: default-src 'none'; script-src 'self' 'sha256-…'; …` が付与される(ビルド時計算のインラインブートストラップのハッシュ許可。CLAUDE.md の承認済み例外)。`referrer-policy: no-referrer` / `x-content-type-options: nosniff` も反映
- index.html / CSS / RSC ペイロード(`funstack__/fun__rsc-payload/*.txt`)の配信を確認。**デプロイ直後の数十秒はアセットが 404 になることがある**(伝播遅延。リトライで解消)
- **SPA フォールバックの本番挙動は wrangler dev と異なる**: `not_found_handling: "single-page-application"` は本番では `Sec-Fetch-Mode: navigate` 付きリクエストにのみ index.html を返す(素の curl GET `/about` は 404 text/plain)。ブラウザのナビゲーションは常に navigate を送るので実害はないが、ヘルスチェックや curl 検証はヘッダを付けること
- ブラウザ実測(Playwright での hydration + CSP 違反ゼロ確認)は、このクラウド環境のプロキシが Chromium の外向き CONNECT を通さないため実施不可(curl は OK、Chromium は example.com でも ERR_CONNECTION_RESET)。同一ビルドに対するローカル e2e(wrangler dev + Playwright、CSP 違反ゼロ含む 4 テスト)で担保済み
- 検証後 `wrangler delete` で削除。workers 一覧空を確認

### 環境まわりの知見

- クラウド環境の Playwright は `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` のプリインストール Chromium を使う(`bunx playwright install` は不要・禁止)。apps/web の e2e(localhost 向き)はプロキシ除外リストに localhost が入っているため動く

## 2. root 統合 PR

- ci.yml に独立ステップ 3 つを追加: 8. web ビルド(vite + write-headers)、9. web e2e(`bunx playwright install --with-deps chromium` → wrangler dev + Playwright)、10. `doctor:astryx`。**ルート vitest.config.ts の projects には web e2e を入れていない**(ビルド成果物前提のため。spike-a の推奨どおり)
- e2e のポート固定(8791)を解消: `node:net` の `listen(0)` で OS に空きポートを割り当てさせる方式に変更(並列実行で衝突しない)。CI からの実行用に apps/web に `e2e` スクリプトを追加
- CI 全体の env に `DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false`(「言わざる」をメンテナ CI にも適用。spike-b の知見)
- ROADMAP のチェックオフ: 要決定 3 件・検証スパイク 3 本・npm プレースホルダ + org

## 3. docs/AUDIT_SPEC.md 起草(0.1-draft、人間レビュー待ち)

- イベント一覧(認証系 / org 系 / データ系 = 変数 × 環境 / チェーンミラー / grant_server 経由のサーバーアクセス)、actor モデル(内部 user_id + 鍵 FP + API トークン id のみ)、CRYPTO_SPEC §7 の要ローテーション検出のクエリ要件(Q1〜Q5)からの逆算でスキーマを設計
- 保存先: プロジェクト系イベント = プロジェクト DO 内 append-only(チェーンと同一 DO・同一トランザクション、クエリが DO 内で完結)。org / ユーザー系 = 3 案比較の上で **D1 専用テーブル(案 A)を提案**(認証イベントは sessions / tokens と同一トランザクションで書ける・検出クエリに関与しないため DO 併置の利点がない)
- 判断が要る点(未決 #1〜#5): 閲覧権限モデルの詳細、監査ヘッドのチェーンチェックポイント、プロジェクト削除後の保全、var.read の集約、SIEM エクスポート

## 4. 暗号テストベクター(packages/crypto/test-vectors/。実装より先にコミット)

- RFC 9180 公式ベクター(spike-c 抽出分)を `hpke/` へコピー。maruhi 固有部は `encoding.json` / `variable-encryption.json` / `chain-entries.json` / `recovery-wrap.json` / `dek-wrap.json`(固定鍵・固定 nonce + 改竄系 negative)
- 期待値の算出は独立参照ツール 2 系統: Python 3.11 + pyca/cryptography(`tools/generate_reference.py`)と hpke-js の ekm derandomize(`tools/generate-dek-wrap.mjs`)。さらに第 3 の実装系(Bun WebCrypto + panva hpke の非抽出 KeyPair Open)で全ベクターを突き合わせ検証(`tools/verify_reference.mjs`、全 PASS)
- **チェーン正規化(CRYPTO_SPEC §6.1「実装はテストベクターで固定する」)の実体をここで定義した**: LP エンコーディングの入れ子(payload は op ごとの固定フィールド順)、バイナリ値は hex 小文字文字列、entry_hash = SHA-256(署名込みエントリバイト列)。鍵 FP は素の連結(固定長 32B×2)とした。**要人間レビュー**(test-vectors/README.md の「特に確認すべき点」参照)
- fallow の解析対象から `packages/crypto/test-vectors/tools/**` を除外(spikes/ と同じ使い捨てツール扱い)
- packages/crypto の実装コードは書いていない(仕様承認後・人間レビュー必須)

## 決定・整理の記録(2026-08-01)

- **ホステッド版は Workers for Platforms を使わない**(所有者との整理): 通常のマルチテナント Workers アプリ + プロジェクト DO 分離で提供する。WfP はテナントのコードを実行するための仕組みであり、maruhi のテナント分離はデータレベル(プロジェクト DO の名前空間分離)で足りる。AUDIT_SPEC §5 の保存先設計(D1 共有テーブル + プロジェクト DO)もこの前提に立つ
- **funstack-static まわりの upstream 報告は当面見送り**(所有者判断。実害なしのため)。調査結果の記録: ① preload の `as="stylesheet"`(正しくは `style`)はエミッタを追跡した結果 **@vitejs/plugin-rsc 0.5.32 にベンダリングされた react-server-dom のコード**が発生源で、funstack-static 本体ではない。preload が無効化されコンソール警告が出るだけで、CSS 本体は通常の `<link rel="stylesheet">` で読まれるため実害なし。② インラインブートストラップは funstack-static の設計選択(`bootstrapScriptContent`)であり、承認済みのハッシュ許可方式で運用確定。報告する場合は ① は plugin-rsc / React 側へ(facebook/react 原本との突き合わせ確認の上)、② は `bootstrapScripts`(外部 URL)への切り替えオプションとして funstack-static へ提案するのが筋
- **workers.dev サブドメインを `maruhi` へ変更完了**(所有者がダッシュボードで実施。旧 `spike-b` は無効化。今後のデプロイ URL は `<worker>.maruhi.workers.dev`)
- **`CLOUDFLARE_API_TOKEN` のユーザー API トークンへの差し替え**を所有者が実施(My Profile → API Tokens、「Edit Cloudflare Workers」テンプレート + D1 Edit、maruhi アカウント限定)。Alchemy 経路の再検証は差し替え後の新セッションで行う(シークレットはコンテナ起動時に注入されるため、既存セッションには反映されない)
