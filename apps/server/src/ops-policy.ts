// 運用基盤(H3)の起草値 — docs/notes/hosted-ops.md §3 / §4。
//
// これらは**受理ポリシーではない**(製品のワイヤ・受理面に影響しない運営側の
// 閾値・予算)。セルフホストでの変更は自由。値は招待制ベータの実測(リストア演習
// — hosted-ops.md §5-3)後に改める。

/** 運用カウンタの固定窓(1 時間 — GitHub の secondary rate limit と同じ粒度)。 */
export const OPS_COUNTER_WINDOW_MS = 60 * 60 * 1000;

/** カウンタ行の保持(評価時にこれより古い窓を削除 — 有界化)。 */
export const OPS_COUNTER_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

/** hosted-ops §3 行 3: GitHub token 請求 / 時の警告閾値(2,000 の 80%)。 */
export const OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD = 1600;

/** hosted-ops §3 行 5: サインアップ拒否 / 時の警告閾値。 */
export const OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD = 20;

/** hosted-ops §3 行 7: 連続失敗がこの回数以上のプロジェクトを信号にする。 */
export const OPS_BACKUP_CONSECUTIVE_FAILURES_THRESHOLD = 3;

/** hosted-ops §2-B: active が続く信号の再通知間隔。 */
export const OPS_ALERT_RENOTIFY_MS = 24 * 60 * 60 * 1000;

/**
 * hosted-ops §2-D: 内容不変(監査 seq・チェーン seq が前回成功と同じ)でも、前回
 * 成功からこの時間を超えたら再退避する(ライフサイクル削除 35 日に先行する)。
 */
export const OPS_BACKUP_REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * hosted-ops §3 行 7: 最終成功からこの時間を超えたプロジェクトを「退避の遅れ」に数える。
 * 再退避間隔 + 1 日の猶予から**導出**する(独立に起草すると、内容不変で skip され続ける
 * 休眠プロジェクトが再退避間隔の内側で恒常に「遅れ」に見える — PR #137 pullfrog 指摘)。
 * 検知が遅くなる対価(スイープの予算不足は最短でも 8 日で表面化)は §8 (b) 第 2 周 (iii)
 * のとおり受容し、演習(§5-3)の実測で改める。
 */
export const OPS_BACKUP_STALE_MS = OPS_BACKUP_REFRESH_MS + 24 * 60 * 60 * 1000;

/**
 * hosted-ops §4-2: これを超える DO は退避せず `oversize` を信号にする(permit
 * 保持 = テナント待ちと cron の壁時計を有界にする。実測後に改める)。
 */
export const OPS_BACKUP_MAX_BYTES = 2_000_000_000;

/** hosted-ops §4-3: スイープ 1 回の壁時計予算(cron 上限 15 分の内側)。 */
export const OPS_SWEEP_BUDGET_MS = 10 * 60 * 1000;

/** hosted-ops §4-3: スイープ 1 回に訪ねるプロジェクト数の上限(サブリクエスト上限の内側)。 */
export const OPS_SWEEP_MAX_PROJECTS = 2000;

/** スイープの `projects` 列挙ページ(D1 の 1 クエリ)。 */
export const OPS_SWEEP_PAGE_SIZE = 100;

/** hosted-ops §1: R2 multipart のパート長(最小 5 MiB の内側で、10 GB でも 640 パート)。 */
export const OPS_SNAPSHOT_PART_BYTES = 16 * 1024 * 1024;

/** 退避の行読みのページ(rowid キーセット — 1 文ずつ同期に読む)。 */
export const OPS_SNAPSHOT_ROW_PAGE = 500;

/** 復元の 1 トランザクションに入れる行数(DO SQLite の束縛パラメータ 100 / 文は別途分割)。 */
export const OPS_RESTORE_BATCH_ROWS = 1000;

/**
 * 毎時 cron の文字列(wrangler.jsonc の `triggers.crons` と**手動で一致**させること —
 * worker-env.ts の IP_RATE_LIMIT_PERIOD_SECONDS と同じペア注記)。scheduled ハンドラは
 * この文字列で運用ジョブ(退避スイープ + 評価)へ分岐し、他はセッション掃除(日次)。
 */
export const OPS_HOURLY_CRON = "23 * * * *";
