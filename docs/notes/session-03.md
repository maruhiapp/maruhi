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
