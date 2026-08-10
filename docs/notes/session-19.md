# セッション 19 メモ(wrangler 一発デプロイの検証 + セルフホスト初回セットアップウィザード)

日付: 2026-08-10。前提: PR #38(セッション 18)マージ済みの main から開始。
スコープ: ROADMAP Phase 1 の残り 2 項目(ドッグフーディング前の最後の実装)。

## 1. wrangler 一発デプロイの検証(ADR-0012 セルフホスト経路)

スパイク B(2026-08-01)で「資格情報がないため未実施」だった実デプロイを、
検証用 CF アカウント(環境変数の `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`)で
最後まで通した。**素の wrangler のみで成立する**(修正は下記の設定明示のみ):

1. `wrangler d1 create maruhi` → database_id を wrangler.jsonc に記入
2. `wrangler d1 migrations apply maruhi --remote` — **drizzle-kit v1 のフォルダ形式
   (`drizzle/<name>/migration.sql`)は `migrations_pattern` でそのまま適用できた**
   (wrangler 4.118+ の正式サポート。ローカル `--local` でも確認)
3. `wrangler secret put GITHUB_CLIENT_SECRET`(検証はダミー値)
4. `wrangler deploy` → `https://maruhi-server.maruhi.workers.dev`
   - バンドル 1754 KiB / gzip 355 KiB(スクリプト上限内)、**Worker Startup Time
     35 ms**(スパイク B の「コールドスタート未計測」に対する実測)
   - cron(セッション掃除)も同時に登録された
5. 疎通: 未知パス 404 / 認証必須 401 JSON / `GET /auth/github/start` が
   リクエスト origin から正しい redirect_uri を導出することを確認

wrangler.jsonc への修正: `workers_dev: true` / `preview_urls: false` を明示
(プレビュー URL は OAuth コールバック origin を増やすだけなので無効化)。
apps/server に `deploy` / `db:migrate` 系スクリプトと wrangler 4.118.0(devDependency)を
追加 — バージョンは vitest-pool-workers の推移的依存と同一ピンで二重コピーなし。
検証時の wrangler 実行は `WRANGLER_SEND_METRICS=false`(「言わざる」)。

**検証デプロイは残置してある**(次フェーズのドッグフーディングの土台):
account `maruhi`(66174a06…)、D1 `maruhi` = `85cb9161-4aa4-4129-adce-d97e14d2ec55`、
URL 上記。コミット済み wrangler.jsonc は配布物としてプレースホルダ ID を保つ方針の
ため、**オーナーの再デプロイ時は database_id をこの実 ID に差し替えてから
`bun run deploy`**(client_id/secret は §3 の残タスク参照)。

**Deploy to Cloudflare ボタンは未検証**: ボタンは公開 Git リポジトリが前提
(リポジトリ公開 = Phase 2)。公開時に、モノレポサブディレクトリ指定と D1 の
自動プロビジョニング(database_id の書き換え)を検証する(ROADMAP Phase 2 に追記)。

## 2. セルフホスト初回セットアップウィザード(設計判断と実装)

ROADMAP の「CLI コマンドかドキュメントか」の設計判断:

- **導入手順の正は `docs/SELF_HOSTING.md`(検証済み runbook)とした**。理由:
  (i) セットアップの全手順(d1 create / migrations / secret put / deploy)が
  CF 資格情報を要する wrangler 操作であり、maruhi CLI に CF 資格情報を持たせる
  べきではない(CLI は秘密のクライアントであって IaC ツールではない)、
  (ii) ADR-0014 裁定 5「セルフホストは上級者経路」— コピー&ペースト可能な
  検証済み手順書が最小かつ十分、(iii) デプロイ → OAuth App 作成(コールバック
  URL にデプロイ URL が要る)→ 再デプロイという 2 段構造は対話ウィザードにしても
  消えない
- **サーバー側のランタイム登録 API(「初回アクセス時の Web 登録フォーム」)は
  不採用**: 未認証の初回登録面は「デプロイ直後に先着した者が自分の OAuth App を
  登録してインスタンスを乗っ取る」経路になる。防ぐにはブートストラップ
  シークレットの別配布が要り、deploy 時に vars/secret で固定する現行の形より
  複雑で弱い。AUTH_SPEC §3 に明文化(仕様先行、マージ = 所有者承認)
- 上記の判断に伴い AUTH_SPEC §3 の「初回アクセス時のセットアップウィザード
  (CLI / サーバーに含める)」の一文を、実際の形(runbook + 下記の機構)へ改訂した

実装した機構(ドキュメントを支える 2 点):

1. **公開設定エンドポイント `GET /auth/config`(AUTH_SPEC §4)**: 未認証で
   `{ githubClientId }` を返す。**セッション 11 の所有者裁定 B(「次の独立 PR で
   公開設定エンドポイント」)の実装**であり、裁定の設計点どおり応答は client_id
   のみ・config の `githubClientId` は上書き手段(GHES・テスト用)として残した。
   CLI login の解決順: `--github-client-id` → config → `/auth/config`。
   これでセルフホスト利用者の CLI 設定は `maruhi config set server <url>` の
   1 項目で足りる
2. **未設定検出**: client_id がプレースホルダ
   (`replace-with-your-github-oauth-app-client-id`)または空のままなら、
   `/auth/config` と `/auth/github/start` が 503 `SetupIncomplete`
   (reason: `github-oauth-unconfigured`)を返す。未設定のまま GitHub へ
   リダイレクトすると GitHub 側のエラーページに飛んで原因に辿り着けないため、
   fail-closed でガイドへ誘導する。プレースホルダ文字列は wrangler.jsonc と
   handlers-auth.ts で同期(双方にコメントで明記)。デプロイ済み検証環境
   (client_id 未設定)で 503 の実挙動も確認済み

`docs/SELF_HOSTING.md` の要点: 手順は全て今回実行したコマンド(検証済み)。
GitHub OAuth App 作成では **"Enable Device Flow" のチェックが必須**(CLI ログインが
device flow。チェック漏れが最頻の詰まりどころとしてトラブルシューティングにも記載)。
client_secret ローテーション・独自ドメイン(コールバック URL の追随)・更新手順も記載。

## 3. テスト・品質

- server(vitest-pool-workers)+4: `/auth/config` 200(未認証)/ プレースホルダ 503
  (`worker.fetch` に env 差し替えで直接渡す形 — SELF は固定 bindings のため)/
  空文字列 503 / `githubStart` の fail-closed 503。テストの `GITHUB_CLIENT_ID` は
  vitest.config の bindings で「設定済みダミー」に上書き(従来はプレースホルダが
  そのまま入っていた)
- cli(Vitest)+4: 自動解決でログイン成立(/auth/config が 1 回呼ばれる)/
  config 値があればサーバーへ問い合わせない(裁定 (iii) の上書き優先)/
  503 はセットアップガイド案内で exit 1 / 自動取得失敗(旧サーバー 404 相当)は
  `config set githubClientId` の逃げ道を案内
- `bun run check` green(920 テスト)

## 4. スコープ外(申し送り)

- **ドッグフーディング開始時の人間タスク**: GitHub OAuth App の作成(SELF_HOSTING.md
  手順 5〜7)と、検証デプロイへの client_id/secret 登録。CLI 側は §1 記載の
  database_id 差し替えのみ
- Deploy to Cloudflare ボタン検証は Phase 2(公開時)へ(§1)
- 監査イベント(auth.* の D1 側)は引き続き D1 監査基盤導入と同時(session-18 §3)
- session-11 §5 の裁定済み後続 PR は、1(公開設定エンドポイント)が本セッションで
  完了。**残りは 3(pull のメタデータのみモード)のみ**(2 はセッション 17-1 で完了済み)
- チェーン追記系コマンド・crypto test/checks の整理候補(session-17 §4)は未着手のまま有効
