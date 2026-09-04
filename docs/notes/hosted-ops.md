# hosted-ops — H3: 運用基盤(監視・アラート / バックアップ / リストア演習)の設計

Status: 2026-09-02 起草(H3 実装 PR #137 に同梱)。**2026-09-03 リストア演習(§5-3 / O7)を実機で実施 — 突合一致で H3 完了**(実施記録は §5-3、実測値は §4-2 / §1、人間タスクの完了日は §7)。hosted-design.md §5(裁定 DC)を「実装できる形」へ落とした
内部文書。**運営側のみ**の段であり、製品のワイヤ・受理面(AUTH_SPEC / AUDIT_SPEC)は無変更。
設計探索(候補・上位互換探索・棄却案・一次情報の確認)の記録は本文書に置く(独立の session ノートは作らない)。

前提(確定事実 — hosted-design.md §5-1 / session-47 裁定 DC):

- テレメトリ禁止(CLAUDE.md「言わざる」)は**クライアント → 外部**の送信の禁止。運営のサーバーが自分の観測を
  運営自身の受け口へ送ることは対象外(DC-1)。ただし送る内容に**リクエスト由来の識別子**(プロジェクト ID = capability
  〔AUTH_SPEC §11-2〕・ユーザー ID・トークン・鍵素材・平文)を含めない — 静的メッセージ + 集計値のみ(DC-2)
- 監査ログ(製品機能)に運用イベントを書かない(DC-3)。運営向け管理 API・管理画面を作らない。専用 health
  エンドポイントを作らない(DC-6 — 外形監視は `GET /auth/config`)。DO 退避のテナント向け API 化は棄却案のまま
- DO の内容は暗号文・チェーン・監査・ラップ済み DEK・メタ・マニフェスト・チェックポイント(`PROJECT_DO_TABLES` の
  全表)で平文の秘密は存在しない(E2EE)。退避先に置いても運営が読める情報は増えない

## 1. 一次情報の確認(2026-09-02 — Cloudflare 公式 docs。起草値と区別する)

| 項目 | 一次情報(2026-09-02 確認) | 本設計での使い方 |
|---|---|---|
| R2: 1 オブジェクト上限 | 単一 PUT 4.995 GiB / multipart 4.995 TiB・パート最小 5 MiB(最終パート除く)・最大 10,000 パート・キー長 1,024 バイト・メタデータ 8 KiB。同一オブジェクトへの同時書き込み 1/秒(超過 429)(r2/platform/limits — 2026-06-08 版) | DO スナップショットは 16 MiB 未満なら単一 `put`、以上は multipart(パート 16 MiB 起草値 → 10 GB でも 640 パート) |
| R2: 料金 / 無料枠 | Standard: $0.015/GB-月・Class A $4.50/百万・Class B $0.36/百万・egress 無料。無料枠 10 GB-月・Class A 100 万/月・Class B 1,000 万/月(r2/pricing)。ライフサイクル規則(削除 / IA 遷移 / 未完了 multipart の中止)は wrangler `r2 bucket lifecycle add --expire-days / --abort-multipart-days`(r2/buckets/object-lifecycles) | 保持は**バケットのライフサイクル規則**で行う(アプリは削除しない — §4-2)。R2 の有効化には運営アカウントで R2 の契約(支払い方法の登録)が要る = 人間タスク(§7)。**実機(wrangler 4.128)**: `lifecycle add` は規則名が必須の位置引数(`lifecycle add <bucket> <name> --expire-days …`)。バケットには既定の "Default Multipart Abort Rule"(7 日)が付いてくる |
| Workers: cron の CPU / 実行時間 | Paid: cron 間隔 ≥ 1 時間なら CPU 15 分 / < 1 時間なら 30 秒、壁時計 15 分。Free: CPU 10 ms。メモリ 128 MB / isolate。サブリクエスト Paid 10,000 / 呼び出し(Free 50)。cron 数 Paid 250 / アカウント(Free 5)(workers/platform/limits) | 退避スイープは**毎時 cron**で走らせるが 1 回の予算は壁時計 10 分(起草値)で打ち切り、カーソルで継続する。Free プランでは退避バインディングが無く no-op(CPU 10 ms 内 — D1 読み 1 本) |
| DO: 上限 | SQLite 10 GB / オブジェクト(Paid)。行 / 文字列 / BLOB 2 MB。文 100 KB・束縛パラメータ 100 / クエリ・列 100 / 表。CPU 30 秒 / リクエスト(`limits.cpu_ms` で 5 分まで)。alarm 壁時計 15 分。Free は SQLite DO のみ・5 GB / アカウント(durable-objects/platform/limits — 2026-06-01 版) | 復元の INSERT は 1 文あたり `floor(100 / 列数)` 行(最大 16 列 → 6 行)。巨大 DO の退避 CPU は `limits.cpu_ms`(hosted 環境のみ 300,000)で緩和 — 上界の議論は §4-2 |
| DO: SQL cursor | `await` を挟んで再開した cursor は「作成後に挿入・更新・削除された行を観測しうる」(storage-api docs)。`.raw()` で列順配列、`.columnNames` で列名 | 退避の行読みは **rowid キーセット + LIMIT で 1 文ずつ同期に `toArray()`** し、cursor を await 越しに持たない(全表が rowid を持つ — `WITHOUT ROWID` なし) |
| Workers RPC | 直列化した RPC メッセージ上限 32 MiB。大きなデータは byte stream で(rpc docs) | DO 退避は DO 自身が R2 へ書き、RPC の戻り値は集計値のみ(§2-D) |
| D1: Time Travel | Paid 30 日 / Free 7 日。`wrangler d1 time-travel info <db> [--timestamp]` でブックマーク、`restore <db> --timestamp|--bookmark` は**その場・破壊的**(上書き。進行中クエリは中断。復元しても以前のブックマークは消えない)。追加費用なし(d1/reference/time-travel) | 誤削除・論理破壊の第一手段。運営 runbook §5-1 |
| D1: export / import | `wrangler d1 export <db> --remote --output=<file> [--table] [--no-schema] [--no-data]`。SQL ダンプ(CREATE + INSERT)。**export 中は他のリクエストをブロック**。仮想表は不可。import は `wrangler d1 execute <db> --remote --file=<sql>`(5 GiB 上限・`BEGIN/COMMIT` は除去)(d1/best-practices/import-export-data) | 定期 export は低トラフィック時刻(02:41 UTC 起草値)に GitHub Actions cron で実行(§4-1)。**実測(2026-09-03・D1 295 KB)**: export ステップ 3 秒(ブロックは 1〜2 秒以内)。import は**ダンプの文順を並べ替えないと失敗する**(export は表ごとに CREATE → INSERT を並べ、`PRAGMA defer_foreign_keys` は import 経路で効かない — `scripts/reorder-d1-dump.ts`、§5-1 (3))。API トークンは **D1: Edit** が要る(Read では export が `Authentication error [10000]`) |
| D1: サイズの観測 | `wrangler d1 info <db> --json`(JSON に **`database_size`** バイト — API の `file_size` を wrangler 4.124 が出力前に改名する。旧版は `file_size`。PR #137 レビューで訂正) | D1 総量トリップワイヤ(5 GB)は export ワークフロー内で判定(§3 行 1) |
| Workers Logs | wrangler `observability.enabled` で有効化。保持 Paid 7 日 / Free 3 日。1 エントリ 256 KB。Paid 月 2,000 万イベント込み・超過 $0.60/百万。`head_sampling_rate` で頭部サンプリング。組み込みのアラート機構は docs に記載なし(workers/observability/logs/workers-logs) | hosted 環境で有効化(`head_sampling_rate` 1)。ただし **`observability.logs.invocation_logs: false` を必須**にする — 既定の Fetch invocation log はリクエスト URL(パス + クエリ)を本文に含み、`/projects/:id`(capability)や `/auth/github/callback?code=…` が保持期間中ログストアに残る(PR #137 Cursor セキュリティレビューで発見。CI 8c が検査)。残るのは console の静的行のみで、per-request 識別子を含まないため全量でも capability の集積にならない。**リクエストログを含む Logpush も有効化しない** — §5-1。**2026-09-03 演習で追加発見**: Effect `HttpRouter.toWebHandler` の既定 HTTP ロガーが console 経路で `"Sent HTTP response" {"http.url":"/projects/<id>"}` を出しており、invocation log を切っても capability がログストアに残っていた。`disableLogger: true` で止めた(index.ts)。修正後は正常経路のログが 0 行になることを Workers Logs の実データで確認 |
| Workers Analytics Engine | binding `analytics_engine_datasets`・`writeDataPoint`(呼び出しあたり 250 点・blob 合計 16 KB)・保持 3 か月・読み出しは SQL API(`/accounts/{id}/analytics_engine/sql` + Account Analytics Read トークン)(analytics-engine/get-started, /limits) | **不採用**(§2-A — 読み出しに API トークンを要し、閾値判定を worker 内で閉じられない) |
| Cloudflare Notifications | Workers / DO / D1 / R2 向けの通知種別は一覧に**無い**(Health Checks は Pro 以上)(notifications/notification-available — 2026-04-24 版) | プラットフォーム通知に依存しない。運営の webhook へ自前送信(§2-B) |
| wrangler: 名前付き環境 | `durable_objects` / `d1_databases` / `r2_buckets` / `ratelimits` / `vars` は**非継承**(環境ごとに再宣言)。`triggers` / `assets` / `migrations` / `limits` / `observability` は継承(wrangler config-schema の記述 + configuration docs)。DO binding の `script_name` で他 Worker 定義の DO 名前空間へ束縛可 | hosted 固有バインディングは `env.hosted` に置く(§2-F)。復元 worker は `script_name` で本番名前空間へ束縛(§2-E) |
| GitHub: token 請求 | 2,000 回/時/App(secondary。残量観測 API なし — session-48 §1) | 自前計数(§3 行 3)。閾値 1,600/時(80%)起草値 |

## 2. 裁定(候補の列挙 → 上位互換 / 銀の弾丸の探索 → 選定)

### 2-A. 計数の出所(GitHub token 請求・ログインフロー行の作成上限到達・サインアップ拒否)

候補:

- (a) Workers Analytics Engine への `writeDataPoint`
- (b) 既存の静的ログ行 + Workers Logs / Logpush 側のクエリ
- (c) D1 の自前カウンタ行(固定窓。前例: `login_failed_windows` / DO の `lease_windows`)
- (d) プラットフォーム標準メトリクス(GraphQL / ダッシュボード)
- (e) 既存の監査行(`auth.login_succeeded` + `auth.login_failed`)からの推定

探索: (a) は書き込み側の規律(識別子を書かない)は守れるが、**読み出しに Account Analytics Read の API トークンを
worker が持つ**ことになり、閾値判定を worker 内で閉じられない(トークン = 新しい秘密 + 外部呼び出し)。(b) も同じ
(Logs のクエリ API)。(d) は token 請求(GitHub 側の枠)を観測できない(§3-4 追記 — 自前計数が唯一の観測手段)。
(e) は `auth.login_failed` が固定窓上限(100/時/バケット)で切り詰められるため洪水時ほど不正確で、抑制マーカーの
10 の冪からの復元は近似にすぎない。**(c) が上位互換**: 書き込み(1 UPSERT)も読み出し(1 SELECT)も D1 内で閉じ、
新しい秘密・外部呼び出し・バインディングを要さず、セルフホストでも無設定で動く。同じ信号を 2 経路に書かない規律から
(a)(b) は併用しない。

**採用 (c)**: D1 表 `ops_counters(metric, window_start, count)` — 1 時間の固定窓、`INSERT … ON CONFLICT DO UPDATE SET
count = count + 1`。書き込み点は 2 つ:

- `github_token_requests`: `GitHubApi.exchangeCode` の**呼び出し点を装飾**(`countingGitHubApi` — index.ts の
  buildServices で 1 か所)。web OAuth callback と CLI ハンドオフの両経路が同じ実装を通るため、ハンドラを触らない。
  成否を問わず 1 計上(GitHub は請求を数える)。**受理面の挙動(拒否・遅延)は変えない** — 計数のみ
- `cli_flow_capacity`: `CliFlowRepo.createOrMatch` が `"capacity"` を返した点(handlers-auth-cli.ts — 一様エラー
  ページの直前)。正規運用で起きない事象の検知(AUTH_SPEC §4-1 (4) (iii))

サインアップ拒否の計数は**新しいカウンタを作らない**: AUDIT_SPEC §3.1 が「H3 のトリップワイヤはこの行を数える」と
規定する `auth.signup_denied` 行(+ `auth.signup_denied_suppressed` マーカー)を D1 `user_audit_events` から窓で数える
(索引 `uae_event(event, seq)`)。同じく `auth.login_failed_suppressed` マーカーを認証面の洪水の信号にする。
これらは既に D1 にある記録の読み取りであり、新しい書き込み経路を増やさない(監査に運用の関心を書かない — DC-3)。

カウンタの増分失敗は握り潰さない: 静的 1 行(`console.warn`)を残して受理処理を続ける(計数は観測であり、
ログイン経路の可用性に優先しない)。

### 2-B. 閾値判定と通知経路

候補:

- (a) worker の `scheduled`(毎時 cron)で判定し、運営の webhook(Workers Secret `OPS_ALERT_WEBHOOK_URL`)へ POST
- (b) GitHub Actions cron が `wrangler d1 execute` で D1 を読み判定(通知 = ワークフロー失敗の GitHub 通知)
- (c) Cloudflare Notifications(プラットフォーム通知)
- (d) Analytics Engine / Logs のダッシュボード(人が見る)

探索: (c) は一次情報で Workers 系の通知種別が無く脱落。(d) は通知にならない。(b) は「D1 export ワークフローが
既に API トークンを持つ」ことを利用でき、worker に秘密を足さない点で魅力 — **銀の弾丸候補**として検討した。しかし
(1) 判定入力の主部(退避の状況・DO 総量の census — §2-C)は worker 内にしか無く、外へ出すには追加の読み出し経路が要る、
(2) GitHub Actions cron の実行は数分〜数十分遅れ・欠落しうる(Actions の既知挙動)、(3) ワークフロー失敗通知は
「失敗」1 種で解消通知を持たない、(4) セルフホスト運営者には使えない。(a) は worker 内で判定が閉じ、通知先が
webhook 1 本(Slack / Discord / PagerDuty / メール中継のいずれも受け口を持つ)で汎用。**採用 (a)**。ただし D1 総量
だけは worker 内から実測できない(`file_size` は wrangler / REST API)ため、export ワークフローが `wrangler d1 info` で
判定する(b の限定適用 — 同じ信号を 2 経路に書かない: worker 側では D1 総量を扱わない)。

通知の形: `OPS_ALERT_WEBHOOK_URL`(未設定 = 送信しない。**既定は無効**)へ JSON を POST。本文は**静的な信号名 +
集計値 + 閾値 + 状態(firing / resolved)**のみ。識別子は載らない。判定状態は D1 `ops_state` に保持し、**遷移時
(inactive → active / active → inactive)に通知**、active が続く間は 24 時間ごとの再通知(起草値)。webhook 未設定でも
active な信号は静的 1 行を Workers Logs に残す(セルフホストの hook)。送信失敗は握り潰さず静的 1 行 + 次回再試行
(状態は更新しない = 次の評価で再送)。

### 2-C. H2 の警告行(storage-guard.ts)を信号に接続する

候補:

- (a) 警告行の発火時に DO から D1 へフラグ行を書く(DO は `env.DB` を持つ)
- (b) Workers Logs をクエリして「出た DO id」を数える
- (c) 退避スイープが各 DO を訪ねるとき、同じ meter(`StorageMeter.databaseSizeBytes`)と同じ純関数
  (`storageGuardDecision`)で判定を返してもらい、**警告域 / 拒否域のプロジェクト数を census として集計**する

探索: (a) は受理経路のホットパスに D1 書き込みを足し、失敗時の意味論(受理を止めるのか)を増やす。「DO インスタンス
生存中 1 回」の規律から件数の意味も弱い(再起動で再発)。(b) は API トークンを要する(§2-A と同じ理由で棄却)。
(c) は**新しい書き込み経路を作らず**、hosted-design §5-2 の信号「警告閾値到達プロジェクト数」をそのまま gauge として
出せる。スイープは毎時走るがプロジェクトごとの訪問間隔は最大 24 時間(§2-D の skip 規則でも size は毎回読む) —
即時性は既存の警告行(Workers Logs で「出たか」)が担い、census が件数を担う。**採用 (c)**。storage-guard.ts の文言・
1 回規律は無変更(接続点は meter と判定関数の共有のみ)。

### 2-D. DO → R2 退避の単位・完全 / 増分・トリガー・命名・保持・所要時間

候補(転送の主体):

- (a) worker が DO から RPC でチャンクを引き R2 へ書く
- (b) **DO 自身が permit 下で自分の SQLite を読み、R2 バインディングへストリーム(multipart)する**
- (c) DO alarm による自己スケジュール退避(各 DO が自分で毎日起きる)

候補(単位): 完全スナップショット / 監査 seq・チェーン seq のウォーターマークによる増分。

探索: (a) は RPC 32 MiB 上限と「チャンク間の一貫性」(permit を RPC 越しに保持できない)で脱落。(c) は D1 の
`projects` 列挙・スイープの予算管理が不要になる**上位互換候補**だったが、(1) 全 DO(非アクティブ含む)が毎日起きて
DO 請求が発生、(2) 退避の成否・census を集約する場所(D1)へ各 DO が書き戻す経路が要る、(3) alarm の設定は DO 生成時
(init)の受理経路に入り「製品の受理面に変更なし」に触れる — で見送り。(b) は permit の中で読み出しと書き込みが
一貫し(同一タスクの直列化 — chain-do.ts 冒頭の不変条件)、データは DO → R2 へ直行する。**採用 (b)**。

増分は**採らない**: 削除(環境削除カスケード・ラップ削除・tombstone)の追跡が要り、復元の正しさの検証面が増える。
代わりに **skip 規則**で費用を抑える — `(auditMaxSeq, chainHeadSeq, attestationMark)` が前回成功時と同じ**かつ**前回成功から
7 日以内なら退避しない(全変更が監査行 / チェーン行を伴う。例外はヘッド申告の upsert — チェーン行も監査行も書かない
〔AUTH_SPEC §16-1〕ため第三成分 `head_attestations` の `MAX(accepted_at)` を加える〔PR #137 レビュー〕。残る例外は
リース窓 / 束縛の可変行で、再生成可能な運用状態 — §4-2 の非可搬項)。7 日で必ず再退避するのは、ライフ
サイクル削除(35 日)により「不変のまま退避物が消える」を防ぐため。

一貫性の対価 = permit 保持時間: 退避中は当該プロジェクトのリクエストが待たされる。所要時間はサイズ比例で、
ベータ規模(KB〜MB)ではミリ秒〜秒。上界(9 GB)は §4-2 のとおり 1 回の cron 内に収まらず、`OPS_BACKUP_MAX_BYTES`
(起草値 2 GB)を超える DO は**退避せず `oversize` として信号に載せる**(黙って落とさない。人間が閾値を上げるか
プラットフォーム耐久性に依拠するかを決める)。

トリガー: 既存の `scheduled` ハンドラ(wrangler.jsonc `triggers.crons`)に**毎時 cron を 1 本追加**し、`controller.cron`
で分岐する。スイープは D1 `projects` を id 昇順で列挙し、`ops_state` のカーソルから再開・壁時計 10 分(起草値)で
打ち切る。

オブジェクト命名: `do/<doIdHex>/<takenAt ISO>.ndjson.gz` — `doIdHex` は `ctx.id.toString()`(`idFromName(projectId)` の像 —
一方向。AUTH_SPEC §12-8 の運営側特定手段と同じ識別子)。**キー・メタデータ・マニフェストにプロジェクト ID を載せない**。
内容(NDJSON gzip): 先頭にヘッダ(format / schemaVersion / takenAt / doIdHex)、表ごとに列名行 + 行、末尾にトレーラ
(表ごとの行数・chainHeadSeq・auditMaxSeq・監査ヘッド hex〔列が最新のときのみ — 実体化の書き込みはしない〕・
databaseSize)。トレーラ欠落 = 途中失敗の退避物として復元側が拒否する。

保持: バケットのライフサイクル規則(`--expire-days 35`〔起草値〕・`--abort-multipart-days 1`)。アプリ側で削除しない
(削除権限を worker に持たせない設計 — R2 binding は put/get のみ使う)。

暗号化: R2 は保存時暗号化を既定で行う。**アプリ層で追加の暗号化(運営鍵で AES-GCM 等)は行わない** — CLAUDE.md
「仕様にない暗号操作を実装しない」(CRYPTO_SPEC が唯一の正)に抵触するため。内容は E2EE 暗号文 + 公開メタで、DO に
置いてある形と同一(運営が読める情報は増えない)。バケットは非公開・専用 API トークンのみ。追加層の要否は §7 O8 —
**2026-09-03 所有者裁定: 不要・恒久**(R2 に到達できる攻撃者は DO 本体にも到達でき、退避物だけを守っても防御線に
ならない)。R2 のアクセス経路が増えるときに再訪する。

### 2-E. 復元経路(運営専用・非 HTTP・非常設)

候補:

- (a) 別クラス名の DO へ復元する専用の worker エントリ(HTTP を持たない)
- (b) `wrangler` からの一回性スクリプト
- (c) 復元専用の環境(別 worker 名)へのデプロイ
- (d) 本番 worker に運営向け復元エンドポイント(認証付き HTTP)

探索: (d) は裁定 DC の棄却案(運営向け管理 API)そのもので除外。(b) は DO へ到達する手段が wrangler に無い(DO に
触れるのは worker の fetch / cron / alarm / RPC のみ)。(a) と (c) は同じ方向で、問題は「HTTP を持たない worker を
どう起動するか」— **cron + R2 のジョブファイル**が解: 復元 worker は毎分の cron で `restore/jobs/` を列挙し、ジョブ
(退避オブジェクトのキーと target)を実行して `restore/results/` に結果を書く。運営は `wrangler r2 object put` でジョブを
置き、`get` で結果を読む。HTTP 面ゼロ・起動は R2 への書き込み権限(= 運営)のみ・復元 worker は作業のときだけ
`wrangler deploy -c wrangler.restore.jsonc` し、終わったら `wrangler delete`(非常設)。**採用 (a)+(c) の合成**。

復元の受け側は本番 DO クラスの RPC `opsRestore(objectKey)`(worker 内部 RPC — HTTP ハンドラから呼ばれない)で、
**空の DO(chain_entries が空)にのみ書く**。既存内容を上書きする経路は存在しない(空でなければ `not-empty` で拒否)。
部分復元(途中クラッシュ)は「chain_entries を最後に書く」規則で検出でき、再実行時は非チェーン表を消してやり直す
(チェーンが無い DO は製品から見て未初期化)。スキーマ版は退避時と一致を要求する(不一致は `schema-mismatch` — 運営が
該当版をデプロイしてから復元する)。

復元 worker は `script_name: maruhi-server-hosted`(wrangler の名前付き環境は `<name>-<env>` の別 Worker を公開する —
`wrangler deploy --env hosted` の実体。CI 8c が env.hosted の実効 name と突合)で本番名前空間へ束縛する(target `production`)ほか、自分の DO クラス
`RestoreDrillDO`(ProjectChainDO を継承、名前空間は復元 worker 側)を持ち、**演習(drill)は本番名前空間に触れず**
drill 名前空間へ復元して検証する(target `drill`)。DO 名は退避物のチェーン genesis(seq 1 の `entry_hash_hex` =
プロジェクト ID)から導出するため、ジョブファイルにもプロジェクト ID を書かない。

検証: 復元 RPC は `{ chainHeadSeq, chainHeadHashHex, auditMaxSeq, auditHeadHashHex, rowCounts }` を返し、結果ファイルに
写す。運営は退避物のトレーラと突合する(自動テストは同じ突合を実 DO で固定する — §6)。

### 2-F. バインディングの optional 化(セルフホスト経路を壊さない)

候補:

- (a) 最上位の wrangler.jsonc に R2 binding を足す(wrangler の自動プロビジョニングに任せる)
- (b) `env.hosted` 名前付き環境に hosted 固有バインディングを置き、`wrangler deploy --env hosted` で運営がデプロイ
- (c) 別ファイル `wrangler.hosted.jsonc`(全複製)
- (d) 生成スクリプトで base + overlay から設定を合成
- (e) バインディング無しで R2 の S3 API を Secret(アクセスキー)で叩く

探索: (a) は R2 の契約(支払い方法の登録)が無いアカウントで `wrangler deploy` 一発が**壊れる**(Deploy ボタン経路も
同じ)ため脱落。(e) は SigV4 署名を worker に実装する = 仕様外の暗号操作に近づき、長期資格情報を worker に持たせる
(binding は資格情報を持たない)。(c) は全複製で drift が起きる。(d) は自前ツール。(b) は wrangler の標準機構で、非継承
キー(`durable_objects` / `d1_databases` / `ratelimits` / `r2_buckets`)の再宣言 = 部分複製が対価。**採用 (b)**。drift は
`scripts/check-hosted-config.ts`(hosted 環境のバインディングが最上位を包含することを検査)を CI 8c(dry-run)と同時に
走らせて塞ぐ。実行時は `env.OPS_BACKUP_BUCKET` / `env.OPS_ALERT_WEBHOOK_URL` の**不在 = 無効**(fail-open ではなく
「機能なし」— 無言にはせず、スイープは静的 1 行で「バインディング無しのため退避しない」を残す〔isolate ごと 1 回〕)。
Alchemy v2 化(gap 10)の際は `env.hosted` の内容がそのまま Alchemy 側の宣言に移る。

### 2-G. D1 定期 export の実行主体・暗号化・保管

候補: (a) GitHub Actions cron + `wrangler d1 export`、(b) 運営端末の手動手順、(c) worker から D1 を読んで R2 へ書く。

探索: (c) は D1 の全表を worker で走査する自前ダンプ(Time Travel と `wrangler d1 export` が既にある機能の再実装)。
(b) は忘れる。(a) は `wrangler` が CI で使える(Deploy dry-run の前例)。**採用 (a)** — `.github/workflows/ops-backup.yml`
(毎日 02:41 UTC 起草値 + 手動起動)。成果物は `age` 公開鍵(GitHub Variables に受信者、秘密鍵は運営端末のみ)で暗号化
し、同じ R2 バケットの `d1/<timestamp>.sql.age` へ `wrangler r2 object put`。GitHub Actions の artifact には**置かない**
(公開後のリポジトリでは artifact が第三者に取得されうる)。ワークフローは `vars.OPS_BACKUP_ENABLED == 'true'` の
ときだけ実行(フォークで無駄に失敗しない)。同ワークフローが `wrangler d1 info --json` の `file_size` を 5 GB と比較して
失敗させる(D1 総量トリップワイヤ — §2-B)。`age` の秘密鍵・API トークン・成果物はリポジトリに置かない。

API トークンの権限(**2026-09-03 実測で訂正** — 起草は「D1 Read + R2 Write」): **D1: Edit** と **Workers R2 Storage: Edit**
(いずれも Account スコープ)。`d1 export` は Read では `Authentication error [10000]`(export ジョブの作成が書き込み扱い)、
`r2 object put` はバケット限定の "Workers R2 Storage Bucket Item: Edit" では 403(wrangler の REST 経路はアカウント
レベルの権限を要求する。バケット限定スコープは S3 互換 API 向け)。運営の CI 用には**ユーザーに紐づかない Account API
token** を使う(発行者の離脱・権限変更に影響されない)。権限変更の反映には数分かかることがある(編集直後の 403 は待つ)。

## 3. 監視信号の一覧(hosted-design §5-2 の実装形)

| # | 対象 | 信号(出所) | 収集経路 | 閾値(起草値) | 通知 | 誤検知と対応(runbook 1 行) |
|---|---|---|---|---|---|---|
| 1 | D1 総量(gap 4) | `wrangler d1 info --json` の `file_size` | ops-backup ワークフロー(毎日) | ≥ 5 GB でジョブ失敗 | GitHub の失敗通知(メール) | 誤検知なし(実測)。対応: `user_audit_events` の支配項を確認 → 監査専用 D1 への分離(§3-3 予約 — スキーマ同型のため機械的。手順: 新 DB 作成 → `D1_AUDIT` binding 追加 → D1AuditRepo の書き込み先切替の PR)|
| 2 | DO 総量ガード | 退避スイープの census(`storageGuardDecision` を各 DO で評価) | 毎時 cron → D1 `ops_backups.storage_level` → 評価 | warn ≥ 1 件 / reject ≥ 1 件 | webhook | 誤検知なし。対応: Workers Logs の警告行の DO id と `ops_backups.do_id_hex` を突合 → テナントへ削除の案内(SELF_HOSTING の説明) |
| 3 | GitHub token 請求 | `ops_counters.github_token_requests`(exchangeCode 呼び出し点) | 毎時評価(直前の完了窓 + 進行中窓) | ≥ 1,600/時(2,000 の 80%) | webhook | サインアップ集中(招待コード配布直後)で正当に上がる。対応: 招待コード発行ペースを落とす(hosted-design §3-4 (1))。スロットリングは gap 9 の領分(本タスク外) |
| 4 | ログインフロー行の作成上限到達 | `ops_counters.cli_flow_capacity`(createOrMatch = capacity) | 同上 | ≥ 1 | webhook | 正規運用で起きない(AUTH_SPEC §4-1 (4) (iii))。対応: `cli_login_flows` の未消費行を D1 で確認 → 異常な併走なら WAF で発信元を絞る |
| 5 | サインアップ拒否 | `user_audit_events` の `auth.signup_denied`(+ `_suppressed`) | 毎時評価 | ≥ 20/時、または suppressed ≥ 1 | webhook | invite 制での善意の無駄打ちで上がる。対応: 拒否理由の分布(reason)を D1 で見る → 案内文言 / 招待配布の見直し |
| 6 | 認証面の洪水 | `auth.login_failed_suppressed` マーカー(AUDIT_SPEC §3.1) | 毎時評価 | ≥ 1 | webhook | 対応: 429 率(ダッシュボード)と併読 → WAF レート制限(SELF_HOSTING 推奨値)を強める |
| 7 | 退避の遅れ | `ops_backups`: 最終成功から **再退避間隔(7 日)+ 1 日** を超えたプロジェクト数・連続失敗 ≥ 3 のプロジェクト数・`oversize` | 毎時評価 | いずれも ≥ 1 | webhook | 遅れの閾値は再退避間隔から導出する(独立に置くと skip され続ける休眠プロジェクトが恒常に遅れに見える — PR #137 レビュー)。連続失敗: Workers Logs の静的行(failure code)を見る。oversize: 閾値引き上げの判断(§4-2) |
| 8 | 可用性 | 外形監視(`GET /auth/config` の 200 — 既存の未認証・状態なし面) | 外部サービス(人間タスク) | 連続 3 回失敗で page | 外部サービスの通知 | 専用 health エンドポイントは作らない(DC-6) |
| 9 | エラー率 | Workers ダッシュボードの 5xx 率・DO エラー(プラットフォーム標準メトリクス) | 人が見る(ベータ規模) | ベースライン逸脱 | — | 自前収集しない(同じ信号を 2 経路に書かない) |

通知は webhook 1 本(§2-B)。すべての信号は「静的な信号名 + 集計値」で、識別子を含まない。

## 4. バックアップ設計

### 4-1. D1

- **Time Travel**(Paid 30 日 PITR — 常時有効・追加費用なし)が第一の復旧手段(誤操作・論理破壊)
- **定期 export**(§2-G): 毎日 1 回、`age` 暗号化、R2 `d1/`、ライフサイクルで 35 日保持(起草値)。export 中は D1 が
  他リクエストをブロックする(一次情報)ため低トラフィック時刻に置く。含まれるのは D1 の内容そのもの(ユーザー・
  セッション / トークンの**ハッシュ**・監査 — 生値秘密は元より無い)
- 鍵の所在: `age` 受信者(公開鍵)= GitHub Variables、秘密鍵 = 運営端末(OS キーチェーン等)。API トークン
  (D1: Edit + Workers R2 Storage: Edit — §2-G の実測訂正)= GitHub Secrets
- 実測(2026-09-03 手動起動 — D1 295 KB・219 行): ジョブ全体 25 秒(依存インストール 10 秒・`age` インストール
  10〜24 秒・**export 3 秒**・暗号化 < 1 秒・R2 upload 2 秒・trip-wire 2 秒)。成果物 16.6 KB。02:41 UTC の起草時刻は
  この規模では意味を持たない(ブロックが観測できない)ため据え置き — ユーザー基盤の時間帯分布が分かったら改める

### 4-2. DO → R2

- 単位 = プロジェクト DO 1 つ = 1 オブジェクト(完全スナップショット。§2-D の skip 規則)
- 対象 = `PROJECT_DO_TABLES` 全表(`schema_meta` は除外し、版はヘッダに写す)
- 読み出し = permit 下・rowid キーセット・1 文ずつ同期(cursor を await 越しに持たない)
- 書き込み = NDJSON → gzip(`CompressionStream`)→ 16 MiB パートの multipart(16 MiB 未満は単一 put)
- 費用見積もり(起草値。R2 料金は §1): プロジェクト 1,000 件・平均 1 MB・毎日変更ありの上界で、書き込み 1,000 Class A/日
  = 3 万/月(無料枠 100 万の 3%)、保存 35 GB(月 $0.5)。skip 規則で実効はこの数分の一
- 所要時間の上界(9 GB DO): JSON 化 + gzip を 50〜100 MB/s(起草の見立て — 実測は演習で)とすると 90〜180 秒の
  CPU、アップロードは 16 MiB × 563 パート。DO の CPU 上限(既定 30 秒 → hosted は `limits.cpu_ms` 300,000)と cron の
  壁時計 15 分の内側だが、permit 保持 = テナント待ちが同じ時間になる。よって `OPS_BACKUP_MAX_BYTES`(起草値 2 GB)を
  超える DO は退避せず `oversize` を信号にする(§3 行 7)
- **演習の実測(2026-09-03 — §5-3)**: ドッグフーディング DO(`databaseSize` 188 KB・17 表 47 行)の退避物 5,293 バイト
  (gzip 後。単一 `put`)。スイープは毎時 `:23` の cron に対し `last_success_at` / カーソル更新が毎回 `:23:56.3〜.9`
  (4 回連続)= **cron の起動遅延 ≈ 56 秒、スイープ本体 < 1 秒**。skip 規則は seq 不変の 2 回(03:23 / 04:23)で退避せず、
  seq が進んだ回(02:23)で再退避したことを R2 のオブジェクト数(2)と `last_attempt_at` ≠ `last_success_at` で確認。
  **9 GB 上界・multipart・DO のサブリクエスト計上はこの規模では観測できない**(§8 (a) の未確認は未確認のまま)。
  `OPS_BACKUP_MAX_BYTES` 2 GB を改める根拠は得られず**据え置き**。改めるべき時: 実テナントで `databaseSize` が数百 MB
  級に達したとき、その DO の退避所要(permit 保持時間)を Workers Logs / `last_attempt_at` 差分で測ってから
- 部分適用の窓: (i) multipart 途中のクラッシュ → 未完了 upload はライフサイクル(1 日)で中止・`ops_backups` は
  失敗として記録(次回再試行)、(ii) 古い退避と新しい退避の混在 → オブジェクトはタイムスタンプ付きで**上書きしない**
  (最新の成功キーは `ops_backups.last_object_key`)、(iii) ロールバックデプロイ → 退避物のヘッダの schemaVersion と
  復元先の版を一致検査(§2-E)、(iv) 退避中の DO 退去(eviction)→ RPC が失敗し失敗として記録
- 非可搬 / 再生成可能な行(復元後にテナント側で自然に回復する): `head_attestations`(次回同期で再提出)、
  `lease_windows` / `lease_bindings`(窓は時間で回復、束縛は期限で失効。復元は**古い束縛を復活させる**が期限内の
  トークン再提示を拒む側〔安全側〕にしか働かない)、`attestation_windows`(同上)。`audit_head_hashes` は導出値だが
  退避に含める(復元後の `ensureHeadCurrent` は列が最新なら読み取りのみ)

### 4-3. 退避と census が消費する共有資源の有界化(歩査 (a))

| 資源 | 有界化 |
|---|---|
| cron の壁時計 / CPU | 1 回 10 分(起草値)で打ち切り・カーソル継続。1 回の訪問プロジェクト数上限 2,000(サブリクエスト 10,000 の内側) |
| DO の permit | 退避 1 回 = 1 permit 保持(サイズ比例)。`OPS_BACKUP_MAX_BYTES` で上界 |
| D1 読み書き | プロジェクトごと `ops_backups` の 1 行 upsert + 列挙 1 ページ 100 行。`ops_counters` はログイン 1 回 1 UPSERT |
| R2 | put / multipart のみ(list / delete 権限を使わない)。保持はライフサイクル |
| GitHub クォータ | 触れない(計数のみ) |

## 5. リストア設計と演習手順(runbook — 実機での実施は人間タスク)

### 5-1. D1

1. 影響範囲の確定(いつから壊れたか)。`wrangler d1 time-travel info maruhi --env hosted --timestamp=<RFC3339>` で
   ブックマークを得る
2. `wrangler d1 time-travel restore maruhi --env hosted --bookmark=<bookmark>`(その場・破壊的。進行中クエリは中断)
3. Time Travel の範囲外(30 日超)/ D1 自体の喪失: 新 DB を `wrangler d1 create`、`age -d -i <keyfile>` で export を
   復号し、**`bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>` で文順を並べ替えてから**
   `wrangler d1 execute <db> --remote --file=<out.sql> -y`(5 GiB 超は分割)。並べ替えが要る理由(2026-09-03 実測):
   export は表ごとに CREATE TABLE → INSERT の塊で並び、外部キーの親表(`users`)より先に子表(`api_tokens` 等)の
   INSERT が来る。先頭の `PRAGMA defer_foreign_keys=TRUE` は import 経路で効かず、そのままだと `no such table:
   main.users`、CREATE を前に出すだけだと `FOREIGN KEY constraint failed` で止まる。スクリプトは CREATE TABLE 全部 →
   INSERT を外部キー依存の親→子順 → CREATE INDEX に並べ、BEGIN/COMMIT を落とす。復号済み SQL は作業後に削除する。
   その後 `env.hosted` の `database_id` を差し替えて再デプロイ。行数の突合は `select count(*)` を表ごとに(D1 の
   compound SELECT は項数上限が小さく、全表を 1 文の UNION ALL にすると `too many terms` で失敗する — 4 表ずつ)

### 5-2. DO

1. 復元対象のプロジェクト ID から `idFromName` の像(hex)を得る(`ops_backups.do_id_hex` — D1)。最新成功キーは
   `ops_backups.last_object_key`
2. 復元 worker をデプロイ: `wrangler deploy -c wrangler.restore.jsonc`(本番名前空間へ `script_name` で束縛)
3. ジョブファイルを置く: `wrangler r2 object put <bucket>/restore/jobs/<name>.json --file job.json --remote`、
   `job.json` = `{ "objectKey": "do/<hex>/<ts>.ndjson.gz", "target": "production" }`(演習は `"drill"`)
4. 1 分以内に cron が拾い(実行前に `restore/running/<name>.json` へ移して claim — 毎分の cron が同じジョブを
   二重実行しない)、`restore/results/<name>.json` に結果(`ok` + 検証値、または failure code)を書いて running/ を消す。
   `wrangler r2 object get <bucket>/restore/results/<name>.json --pipe --remote`。結果が無く `restore/running/` に
   ジョブが残っていれば worker が実行中に落ちた = 対象 DO の状態(空か・チェーンが入ったか)を確かめてから再投入する
5. 検証: 結果の `chainHeadSeq / chainHeadHashHex / auditMaxSeq / auditHeadHashHex / rows` を退避物のトレーラ
   (`wrangler r2 object get … --pipe | gunzip | tail -1`)と突合。トレーラの `auditHeadHashHex` は退避時点で累積
   ハッシュ列が最新のときだけ非 null(退避は実体化の書き込みをしない)。null の場合は復元側が列を伸ばして返した値を
   記録し、テナント側の `GET /audit-head` と突合する。本番復元ではさらにテナント側で `maruhi project verify`
   / `audit verify` を依頼(復元は「公証時点以降」の改竄検出の起点を作り直さない — 退避物にヘッド列を含むため)
6. 片付け: `wrangler delete -c wrangler.restore.jsonc`(復元 worker を残さない)。drill 名前空間の DO は復元 worker の
   削除でクラスごと消える

### 5-3. 演習(招待制ベータ前に 1 回 = H3 の完了条件)

1. hosted 環境で退避スイープが 1 周した(`ops_backups` に全プロジェクトの成功行)ことを確認
2. 運営自身のドッグフーディングプロジェクトを `target: "drill"` で復元し、§5-2 (5) の突合が一致する
3. D1: 直近 export を復号し**別の**新規 D1 へ import(本番に触れない)し、`sqlite3` 相当で行数を本番の
   `wrangler d1 execute --command "select count(*) …"` と突合
4. 所要時間(export のブロック時間・9 GB 上界の見立て)を実測し、本文書の起草値(`OPS_BACKUP_MAX_BYTES`・時刻)を改める
5. hosted-design.md §9 H3 行に実施日と結果を追記

#### 実施記録(2026-09-03 — 運営アカウント `maruhi`・hosted origin `https://my.maruhi.app`)

対象: 運営のドッグフーディングプロジェクト(env `dev`・変数 5 本・値はダミー。DO id の像 `1fe4a507…`)。
演習は Claude(Cursor)が運営端末で wrangler を実行し、所有者がブラウザ操作(GitHub OAuth・CLI 承認)と各種
トークン発行を担当した(伴走セッション)。順序: hosted デプロイ(`signupPolicy` 既定 `open`)→ 運営アカウントの
サインアップ → **`signup_policy` を `invite` へ反転**(SELF_HOSTING.md の UPSERT SQL — `updated_at` 必須)→ CLI ログイン
→ プロジェクト作成。以後 `https://my.maruhi.app` は招待制(`/auth/config` で確認済み)。

| 手順 | 結果 | 所要 / 実測 |
|---|---|---|
| (1) スイープ 1 周 | `ops_backups` 1 行(全プロジェクト)・`storage_level=admit`・失敗 0・カーソル終端。01:23Z(init 直後・1,453 B)と 02:23Z(push 後・5,293 B)の 2 世代、03:23Z / 04:23Z は skip | cron 起動 +56 秒・本体 < 1 秒 |
| (2) DO drill 復元 | `wrangler deploy -c wrangler.restore.jsonc` → `restore/jobs/drill-2026-09-03.json`(`target: "drill"`)→ `restore/results/` に `status: "ok"`。**全 17 表の行数・chainHeadSeq 3・chainHeadHashHex `17274a51…`・auditMaxSeq 17 がトレーラと一致**。トレーラの `auditHeadHashHex` は null(§5-2 (5) のケース)→ 復元側の `5522999b…` を、テナント側で監査行から再計算した h_17 と本番 `GET /audit-head` の申告値と突合し **三者一致**。`running/` 取り残しなし。`wrangler delete` で片付け | ジョブ投入 03:45:13Z → 結果 03:46:14Z 以前(cron 1 分 + 数秒) |
| (3) D1 復元 | `ops-backup` 手動起動の export(`d1/2026-09-03T03-16-06Z.sql.age`・16.6 KB)を `age -d` で復号 → `maruhi-drill` を新規作成 → **素の import は 2 回失敗**(`no such table: main.users` → CREATE 先出しで `FOREIGN KEY constraint failed`)→ `scripts/reorder-d1-dump.ts` で親→子順に並べ替えて成功(90 文・219 行)。**全 21 表の `count(*)` が本番と一致**。`wrangler d1 delete maruhi-drill` で片付け | import 3 秒 |
| (4) 実測値 | §4-1 / §4-2 / §1 に反映。起草値の変更なし(根拠不足 — 9 GB 上界はこの規模で観測不能) | — |
| (5) 記録 | hosted-design.md §9 H3 行・ROADMAP.md H3 行を更新(本 PR) | — |

演習で見つかった欠陥・食い違い(本 PR で修正):

- **Effect HTTP ロガーによる capability のログ残留**(§1 Workers Logs 行)— `disableLogger: true`
- `r2 bucket lifecycle add` に規則名が必須(§1 R2 行・SELF_HOSTING.md)
- Actions 用トークンの権限は D1: Edit + Workers R2 Storage: Edit(§2-G・ops-backup.yml・SELF_HOSTING.md)
- D1 import の文順(§5-1 (3)・SELF_HOSTING.md・新規 `scripts/reorder-d1-dump.ts` — 純関数部 `.lib.ts` を
  `test/reorder-d1-dump.test.ts` で固定)
- PR #139 pullfrog レビューで追加: 単一オリジン不変条件(`workers_dev: false` + `routes`)を CI 8c の検査に、
  capability がログに出ないことの回帰テスト(`test/log-hygiene.test.ts` — Effect ロガーを戻すと落ちる)、
  `disableLogger` で消える失敗系ログの代わりに 500 のときだけ静的 1 行(index.ts)
- `deployment_settings` への直 INSERT は `updated_at` NOT NULL — SELF_HOSTING.md の SQL が正(runbook 化)
- GitHub OAuth App の登録フォームが変更されている(Redirect URIs 複数・"Expire user access tokens")— SELF_HOSTING.md §4

運用上の所見(変更はしない — 提案):

- 正常経路の毎時ジョブは Workers Logs に 1 行も出さない(記録は D1 のみ)。「スイープ 1 周・n 件・skip m 件」の
  静的 1 行があると外形からの健全性確認が楽になる(識別子を含まないので DC-2 に抵触しない)
- `maruhi login` のフロー期限(10 分)は伴走(人が別チャネルで URL を受け取る)には短い — 単独運用では問題ない
- CLI の `key generate` は Cursor 端末を AI エージェント環境と判定し recovery code をスキップした(ADR-0016 決定 7
  の想定どおり)。演習用鍵なので問題ないが、運営の本鍵は人間の端末で作ること

## 6. 実装の写像

| 層 | 変更 |
|---|---|
| D1 スキーマ(drizzle) | `ops_counters(metric, window_start, count)` / `ops_backups(project_id, do_id_hex, last_success_at, last_object_key, last_bytes, last_audit_seq, last_chain_seq, storage_level, last_attempt_at, consecutive_failures, last_failure_code)` / `ops_state(key, value, updated_at)`(スイープカーソル・アラート状態) |
| db.package | `OpsRepo`(カウンタ増分 / 窓集計・退避記録 / 遅れ集計・状態 kv・`auth.*` 行の窓集計・`projects` の全列挙) |
| ops-policy.ts | 閾値・予算の起草値(受理ポリシーではない — セルフホストでの変更は自由) |
| ops-signals.ts | `countingGitHubApi`(exchangeCode の装飾)・`noteCliFlowCapacity` |
| ops-alerts.ts | 毎時評価 + webhook + 状態遷移 |
| do-snapshot.ts | DO 側: 表の列挙・NDJSON gzip ストリーム・multipart・復元パーサ・空判定 |
| chain-do.ts | RPC `opsBackup(input)` / `opsRestore(objectKey)`(permit 下・HTTP から呼ばれない)。`Env` に `OPS_BACKUP_BUCKET?` / `OPS_ALERT_WEBHOOK_URL?` |
| ops-backup.ts | スイープ(列挙・skip 判定・census・記録・予算) |
| index.ts | `scheduled` を cron で分岐(日次 = セッション掃除、毎時 = 評価 + スイープ) |
| restore-worker.ts + wrangler.restore.jsonc | 復元 worker(cron + R2 ジョブ。`RestoreDrillDO`) |
| wrangler.jsonc | 毎時 cron の追加、`env.hosted`(R2 / observability / limits + 非継承キーの再宣言) |
| scripts/check-hosted-config.ts | `env.hosted` の drift 検査(CI 8c) |
| .github/workflows/ops-backup.yml | D1 export + age + R2 + D1 総量判定 |
| docs | SELF_HOSTING.md(英語: Backups / Optional operations bindings)、hosted-design §8 gap 4・5 / §9 H3、ROADMAP |
| テスト | `ops-backup.test.ts`(実 DO: fixture → 退避 → 空 DO へ復元 → ヘッド・監査ヘッド〔`ensureHeadCurrent`〕・行一致・seq 無欠番。skip 規則。census。not-empty 拒否。トレーラ欠落の拒否)、`ops-alerts.test.ts`(カウンタ・評価・遷移・webhook 本文に識別子が無いこと)、`ops-restore.test.ts`(ジョブ処理) |

## 7. 人間タスク(実行しない — 列挙。完了日は 2026-09-03 の伴走セッションで記入)

| # | タスク | 段 | 状態 |
|---|---|---|---|
| O1 | Workers Paid の運用アカウント整備(L6)— cron CPU 15 分・DO 10 GB・Time Travel 30 日は Paid 前提 | H3 デプロイ前 | **済 2026-09-03**(運営アカウント `maruhi`。既存の `maruhi-server`〔2026-08-10 試験デプロイ・D1 0 行・DO 0 件〕はデータ無しと確認し、hosted 名で新規運用) |
| O2 | R2 の有効化(支払い方法の登録)とバケット作成: `wrangler r2 bucket create maruhi-ops-backup`、ライフサイクル `lifecycle add maruhi-ops-backup retain-35d --expire-days 35 --abort-multipart-days 1`(**規則名は必須の位置引数**)。公開アクセスなし(`dev-url get` が disabled・custom domain なし) | 同上 | **済 2026-09-03** |
| O3 | `env.hosted` の `database_id`・バケット名を実値に、`wrangler secret put OPS_ALERT_WEBHOOK_URL --env hosted`(webhook の受け口 = チャット / メール中継の契約)。`wrangler deploy --env hosted`。**注意**: 名前付き環境は `maruhi-server-hosted` という別 Worker(= 別の DO 名前空間)を作る。最上位名 `maruhi-server` で稼働中のプロジェクト DO が運営アカウントにあるなら、hosted への切り替えはデータが付いてこない(退避 → 復元 worker で移すか、最初から hosted 名で運用する)。初回デプロイ前に既存デプロイの有無を確認する(PR #137 レビュー)。**デプロイ直後に 1 回**、Workers Logs で invocation log が実際に止まっていること(ダッシュボードの Logs 設定で Invocation logs が OFF、または数分後のログに `http.url` を含む行が無い)を目視確認する — CI 8c は設定ファイルの値しか見ない。**提供ドメイン**(所有者裁定 2026-09-03): 製品オリジン = `my.maruhi.app`(`routes` + `custom_domain`、hosted では `workers_dev: false`)、apex `maruhi.app` = LP + docs〔`/docs` — L1 改訂 2026-09-03。当初の「`maruhi.dev` = docs」は撤回し `maruhi.dev` は 301〕。ダッシュボードのオリジンは TCB なので LP と分ける。初回ユーザー(運営)のサインアップ後に `deployment_settings.signup_policy` を `invite` へ(SELF_HOSTING.md の SQL) | 同上 | **済 2026-09-03**(Secrets: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / SERVER_ENC_KEY_IKM / OPS_ALERT_WEBHOOK_URL〔Slack〕。運営アカウントのサインアップ〔00:4x UTC・`open` 下〕直後の 00:49 UTC に `signup_policy` を **`invite` へ反転**し `GET /auth/config` の `signupPolicy=invite` で確認〔open だった時間は約 1 時間・作成されたユーザーは運営の 1 件のみ = `users` 1 行〕。Logs 目視で **Effect HTTP ロガーの漏れを発見・修正** — §1) |
| O4 | GitHub: Secrets `CLOUDFLARE_API_TOKEN`(**Account API token — D1: Edit + Workers R2 Storage: Edit**。起草の「D1 Read + R2 Write」は実機で不足 — §2-G)/ `CLOUDFLARE_ACCOUNT_ID`、Variables `OPS_BACKUP_ENABLED=true` / `OPS_BACKUP_BUCKET` / `OPS_BACKUP_AGE_RECIPIENT`。`age-keygen` の秘密鍵は運営端末のキーチェーンへ。`workflow_dispatch` で 1 回手動実行して成功を確認 | 同上 | **済 2026-09-03**(手動実行 3 回目で成功 — 権限不足 2 回の実測が §2-G) |
| O5 | 外形監視サービスの契約(`GET /auth/config` を最短間隔・連続失敗で通知)— Better Stack Uptime を採用。専用 health エンドポイントは作らない | 招待制ベータ前 | **済 2026-09-03**(Better Stack Uptime モニター: `GET https://my.maruhi.app/auth/config`・**30 秒間隔**〔プランの最短。無料枠へ落とすと 180 秒〕・期待 200・確認期間 180 秒〔= 連続失敗約 6 回・runbook の「1 分 × 3 回」と同じ 3 分で通知〕・回復期間 180 秒・4 リージョン〔eu/us/as/au〕・通知はメール。TLS 期限 7 日前・ドメイン期限 14 日前の通知を追加。負荷は ≈ 8 req/分で D1 点読み 1 本・レート制限対象外。Sentry 等の APM は**入れない** — クライアント側は「言わざる」、Worker 側はリクエスト由来識別子が第三者に渡る〔DC-2 違反〕ため。エラー率は Workers ダッシュボード〔§3 行 9〕) |
| O6 | 運用 GitHub OAuth App(L7 — 本番コールバック URL)。「Enable Device Flow」は無効のまま。**2026-09 のフォーム**では Redirect URIs(複数可・wildcard 設定制)と "Expire user access tokens" が追加されている — Redirect URI は 1 本(`https://my.maruhi.app/auth/github/callback`)・wildcard オフ、Expire はオンで可(サーバーは access_token を即時使用して捨て、refresh_token を読まない) | H3 デプロイ前 | **済 2026-09-03**(組織 `maruhiapp` 配下) |
| O7 | リストア演習(§5-3)の実施と実測値の反映。**H3 の完了条件** | 招待制ベータ前 | **済 2026-09-03**(§5-3 実施記録 — DO / D1 とも突合一致) |
| O8 | 退避物へのアプリ層暗号化(運営鍵)の要否の裁定 — 要るなら CRYPTO_SPEC の改訂として提示(§2-D)。**判断材料(2026-09-03 整理)**: (a) 退避物の内容は DO と同一の E2EE 暗号文 + 公開メタで、運営が読める情報は増えない。(b) R2 は保存時暗号化 + 非公開バケット + アカウントレベル権限のみ。(c) 追加層を入れると鍵管理(運営鍵の保管・ローテーション・復元 worker への配布)が増え、CRYPTO_SPEC 外の暗号操作になる。(d) 脅威は「R2 バケットの権限漏洩で暗号文 + チェーン + 監査(メタデータ)が第三者に渡る」— 平文は渡らないがメンバー構成・変数名・操作履歴は渡る。(e) D1 export は `age` で運営鍵暗号化済みなので非対称(D1 は GitHub Actions ランナー = 第三者環境を経由するため。DO 退避は Cloudflare 内で完結)。**所有者裁定 2026-09-03: 不要 — 今後も追加しない**。R2 に到達できる攻撃者は DO 本体にも到達でき、退避物だけを守っても防御線にならない。R2 のアクセス経路が増える(外部連携・別アカウントへの複製等)ときに再訪 | 任意 | **裁定済 2026-09-03(不要・恒久)** |
| O9 | Alchemy v2 化(ADR-0012 / gap 10)— `env.hosted` の内容と apex サイト(O10 の `maruhi-site`)を Alchemy 宣言へ移す独立 PR | DP 系列の後(web-design-pass.md §1-6) | 未 |
| O10 | **apex サイトの初回デプロイ(DP2)**。**順序**: DP2 の PR は `apps/web` のトップ(`my.maruhi.app/`)と README から `https://maruhi.app` へリンクするため、**マージ後・次回の製品 Worker デプロイ(`wrangler deploy --env hosted`)より前**に実施する(それまで製品側のリンク先は未配信 = 404 でなく DNS 未解決。秘匿への影響なし)。手順: リポジトリのルートで `bun install && bun run --filter @maruhi/site deploy`(= `blume build` + `scripts/postbuild.ts` + `wrangler deploy` — `apps/site/wrangler.jsonc`、Worker 名 `maruhi-site`、Static Assets のみ・Worker コードなし)。`routes` の `custom_domain: true` により wrangler が `maruhi.app` の DNS レコードと証明書を自動で作る(ゾーンは運営 CF アカウント。apex に既存の A / AAAA / CNAME があれば先に消す)。デプロイ後の目視: `curl -sI https://maruhi.app/` に `content-security-policy`(`script-src 'self' 'sha256-…'`・`style-src 'self' 'sha256-…'`)と `strict-transport-security` があること、`/docs` が開くこと、`/fonts/OFL-Archivo.txt` が読めること、ブラウザ DevTools の Network で外部オリジンへの要求がゼロであること。preview URL は無効(`workers_dev: false` / `preview_urls: false`)なので、事前確認は `bun run --filter @maruhi/site build && bun run --filter @maruhi/site preview`(ローカル wrangler dev、`http://localhost:8789`)で行う | DP2 マージ後 | 未 |
| O11 | **`maruhi.dev` → `maruhi.app` の 301**(ゾーンのリダイレクトルール — Worker は置かない): `maruhi.dev` ゾーンで Rules → Redirect Rules → Create rule。式 = `(http.host eq "maruhi.dev") or (http.host eq "www.maruhi.dev")`、Type = Dynamic、Expression = `concat("https://maruhi.app", http.request.uri.path)`、Status = 301、Preserve query string = on。リダイレクトルールはプロキシされた DNS レコードを要するため、`maruhi.dev`(apex)と `www` に **プロキシ(オレンジ雲)の A レコード `192.0.2.1`**(ダミー)を置く。確認: `curl -sI https://maruhi.dev/docs` が `301` + `location: https://maruhi.app/docs` | O10 の後 | 未 |
| O12 | **訪問数の集計はサーバー側のみ**(web-design-pass.md §1-5 — スクリプト注入なし): `maruhi.app` ゾーンの Analytics & Logs → Traffic(HTTP リクエスト集計)を使う。Web Analytics を有効化する場合は「Automatic setup」(beacon の自動注入)を **選ばず**、JS スニペットも置かない(`_headers` の CSP `script-src 'self' + ハッシュ` が外部ビーコンを弾く — 弾かれるのが設計どおり)。Workers Static Assets の応答にはビーコンが注入されないため、Web Analytics の数字は増えない = 想定内 | O10 の後(任意) | 未 |

## 8. 実装後の第 2 次ゼロベース探索(歩査 — 収束記録。2026-09-02)

(a) **共有資源**: §4-3 の表。追加で確認・修正した点 —
- `ops_counters` の行は窓ごとに増えるため、評価時に 7 日超の行を削除(有界)。`ops_state` は固定キーのみ。webhook
  送信は評価 1 回あたり 1 POST(信号ごとに送らない)
- R2 multipart は**最終パート以外を同一サイズ**に要求する(一次情報)。圧縮ストリームの出力を「溜まったら送る」形は
  パート長が揺れて complete が失敗するため、ちょうど partBytes ずつ切り出す形に改めた(実 R2 互換の miniflare で
  5 MiB パート 2 個の multipart を固定)
- DO 内の R2 呼び出しが DO のサブリクエスト上限に数えられるかは一次情報に記載がなく**未確認**(10 GB でも 640 パート —
  Workers Paid の 10,000 の内側)。2026-09-03 の演習は 188 KB の DO(単一 put・1 サブリクエスト)で multipart を通らず、
  **未確認のまま**。実テナントの DO が 16 MiB を超えて初めて multipart 経路が実機で走る — その回の
  `ops_backups.last_failure_code`(`upload-failed` / `rpc-failed`)と Workers Logs の静的行で確認する
- Free プランの cron は CPU 10 ms: 毎時ジョブはバインディング無しなら D1 を数本読むだけ(I/O 待ちは CPU に数えない)。
  それでも超過する環境があれば `triggers.crons` の 2 本目を外せばよい(SELF_HOSTING に明記 — 退避と評価は消える)

(b) **成立し続けるべき読み手**: 既存の日次 cron(セッション掃除)は cron 文字列で分岐し従来どおり(既定の cron 文字列
が来ない実行環境 — テストの `createScheduledController()` は cron が空 — では**日次処理**を選ぶ = 既存テストの契約を
維持)。DO の受理経路は permit を共有するだけで判定順・拒否語彙は不変(storage-guard.test.ts が固定)。セルフホストの
deploy は最上位設定が無変更(cron 1 本追加のみ)、CI 8b の dry-run は従来どおり + 8c で hosted / restore の dry-run と
drift 検査。`GitHubApi` の装飾は index.ts の 1 か所で、ハンドラ(web callback / CLI callback)は exchangeCode の呼び出し
形を変えない。

(c) **部分適用の窓**: §4-2。加えて —
- 「復元途中で製品 init が同じ名前に届く」= 同一 genesis を持つ正当な所有者の再初期化で、復元完了前にチェーン 1 行が
  入ると復元は `not-empty` で拒否される(上書きしない側に倒れる — 運営が init 済みの DO を消す手段は無いため、テナントと
  調整して再初期化を待ってもらうか、復元を諦めて再初期化を採る)
- 退避は **at-least-once**: DO の upload 完了後・D1 の記録前に cron が落ちると、次回は記録が無いので再退避する
  (オブジェクトはタイムスタンプ付きで重複しても上書きしないだけ — ライフサイクルが消す)
- 復元は途中失敗で全表を消して空へ戻す。消し損ね(DO 退去)でも chain_entries は最後の表なので「未初期化」側に倒れ、
  再実行が非チェーン表の残骸を消してからやり直す(テストで trailer 欠落・schema 不一致の両方を固定)
- 退避物のトレーラの監査ヘッドは「列が最新のときのみ非 null」。復元後の突合はその前提で行う(§5-2 (5))。当初は
  退避側で列を伸ばす案も考えたが、退避は読み取りのみ(9 GB 級 DO で実体化の書き込みを退避が誘発しない)を優先した

(d) **成長様式ごとの信号の成立**: pull 主体(var.read のみ増える)— 監査 seq が進むため skip されず再退避・census が
size を読む(テストで「pull 後は skip されない」を固定)。失効主体(remove / rotation.recommended)— 同上。サインアップ
主体(D1 のみ増える)— DO は不変で skip、D1 総量はワークフローが見る、拒否計数は `user_audit_events` から(テストで
signup_denied 行の窓集計を固定)。休眠プロジェクト — 7 日ごとに再退避され、ライフサイクル削除(35 日)に先行する。

第 2 周(生成規則を変えて): 「信号が出ない形」を探した — (i) webhook の受け口が落ちている間の遷移は状態を進めない
ため次回再送される(テストで固定)。(ii) 評価は毎時で、firing → resolved が 1 時間の内側で往復した場合は観測されない
(トリップワイヤの粒度として受容 — 短命の洪水は抑制マーカー行が残す)。(iii) スイープが予算切れで終端に達しない日が
続くと後半のプロジェクトが `backup_stale_projects` に現れ、それ自体が「規模に対して予算が足りない」の信号になる。

新規案が出なくなった時点で収束(実装 PR 本文に要約)。

## 9. スコープ外・申し送り

- Alchemy v2 化(O9)・インシデント / ステータスページ(H4 / H5)・SECURITY.md・脅威モデル
- GitHub token 請求のスロットリング(gap 9 のオープンベータ開放条件)
- テナント向けエクスポート(hosted-design §10)— 退避物の形式(NDJSON gzip)はテナント向け輸送の形と**独立**であり、
  再利用を前提にしない(目的も認可も異なる — DC の棄却案)
- 監査専用 D1 の分離(gap 4)は監視閾値到達時の手順として §3 行 1 に予約
- CI の web e2e S9 のフレーク(PR #135)は別 PR
