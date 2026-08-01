# スパイク B 検証結果: サーバー基盤の結線(Effect v4 HttpApi + DO + vitest-pool-workers + Alchemy v2)

日付: 2026-08-01。ROADMAP Phase 0 の検証スパイク。
**使い捨てコードは `spikes/spike-b/` にあり、製品コードではない。** `apps/server` は変更していない。

## 検証対象と構成

| 部品 | バージョン(厳密ピン) | 備考 |
|---|---|---|
| effect | 4.0.0-beta.102 | **v4 に stable は存在しない**(latest は 3.22.1)。CLAUDE.md の「Effect v4 系」に従い beta を採用、ADR-0011 の厳密ピンで運用 |
| @cloudflare/vitest-pool-workers | 0.20.1 | セッション 01 と同じ。`cloudflareTest()` プラグイン形式 |
| alchemy | 2.0.0-beta.67 | v2 は npm dist-tag `next`。こちらも stable 未リリース |
| wrangler | (pool-workers の推移的依存) | dry-run 検証に使用 |

作ったもの: カウンタ 1 本のダミー構成。

- `src/api.ts` — HttpApi 定義(GET `/counter/:name`、POST `/counter/:name/increment`)。v4 では @effect/platform が effect 本体に統合され、HttpApi は `effect/unstable/httpapi` にある
- `src/worker.ts` — 素の Workers API(`export default { fetch }` + `DurableObject` サブクラス)のまま、内部を Effect で実装:
  - **DO(ManagedRuntime パターン)**: `CounterDO` のコンストラクタで Layer から `ManagedRuntime.make` を 1 度だけ実行し、RPC メソッド(`getValue` / `increment`)は `runtime.runPromise` で Effect を走らせる。ストレージアクセスは Effect サービス `CounterStore` の背後に隔離(ADR-0006 の縮小版)。DO SQLite は `ctx.storage.sql`(UPSERT + RETURNING)
  - **Worker**: `HttpApiBuilder.group` でハンドラ実装 → `HttpRouter.toWebHandler` を isolate ごとに 1 度だけ構築。`env`(DO バインディング)はリクエストごとに `handler(request, Context.make(WorkerEnv, env))` で注入(リクエスト毎に Layer を再構築・dispose しない)
- `test/counter.test.ts` — vitest-pool-workers(workerd 実環境)。SELF 経由の HttpApi 統合 + `runInDurableObject` による DO SQLite 実データの直接検証
- `wrangler.jsonc` + `alchemy.run.ts` — ADR-0012 両対応の 2 経路(後述)

## 結果: すべて成立

- **テスト 5/5 通過**(workerd 実環境。`navigator.userAgent === "Cloudflare-Workers"` を確認)
  - HttpApi ルーティング → DO RPC → DO SQLite 読み書きのラウンドトリップ
  - Schema バリデーション失敗時のエラー応答
  - `runInDurableObject` で DO 内部の SQLite 行を直接 assert
- Effect v4(beta.102)は **workerd 上で `nodejs_compat` なしにそのまま動く**
- `tsc --noEmit` 通過、ルート品質ゲート 7 ステップ通過
- wrangler 経路: `wrangler deploy --dry-run` でバンドル成功(**Total Upload 1259 KiB / gzip 261 KiB** — Effect ランタイム込みのサイズ感。Workers のスクリプト上限 3 MiB (free) / 10 MiB (paid) gzip 内)
- Alchemy 経路: `alchemy.run.ts` が型チェック通過、CLI(`alchemy plan` ほか)起動確認

## ADR-0012(Alchemy v2 + 素の wrangler 両対応)の検証

**成立する。** 鍵は Alchemy v2 の「**Async Worker**」形式:

- Worker 実装(`src/worker.ts`)は素の Workers API のまま。Alchemy 固有の import を一切含まない
- `alchemy.run.ts` は `Cloudflare.Worker("SpikeB", { main: "./src/worker.ts", env: { COUNTER: Cloudflare.DurableObject<CounterDO>("COUNTER", { className: "CounterDO" }) } })` と「実装 Effect を渡さず main を指すだけ」。この場合 Alchemy はファイルをそのままバンドルし、Effect ランタイムをデプロイ定義側から持ち込まない
- 同一ソースを `wrangler.jsonc`(durable_objects バインディング + `new_sqlite_classes` migration)でもデプロイできる。二重管理は「バインディング宣言 2 か所」だけに縮む
- 注意: Alchemy には Effect ネイティブな Worker/DO 記述(two-phase Effect パターン、スキーマレス RPC ブリッジ)もあるが、**それを使うとソースが Alchemy 依存になり wrangler 経路が壊れる**。maruhi では Async Worker 形式に固定すべき

実デプロイ(`alchemy deploy` / `wrangler deploy`)は **Cloudflare 資格情報がないため未実施**。`alchemy plan` も state 取得に資格情報を要求するため実行できなかった(`AuthError: No credentials configured for 'Cloudflare'`)。dry-run バンドルと型チェックまでで打ち切り。

## ハマったこと(実装時に再遭遇しうる罠)

1. **HttpApiEndpoint の payload に素のフィールド群を渡すと form-urlencoded になる**: `payload: { by: Schema.Number }` は `application/x-www-form-urlencoded` コーデック扱いで、JSON ボディは **415 Unsupported content-type** になる。JSON にするには `payload: Schema.Struct({ by: Schema.Number })` と Schema を明示する(`HttpApiEndpoint.js` の `getPayload` が fields shorthand に `asFormUrlEncoded()` を付ける実装)
2. **`HttpApiBuilder.layer` は型上 `HttpPlatform` / `FileSystem` / `Etag.Generator` / `Path` を要求する**(ファイルレスポンス用。JSON API だけなら実行時には呼ばれない)。workerd には FS がないので `FileSystem.layerNoop({})` + `HttpPlatform.layer` + `Etag.layer` + `Path.layer` で型要求だけ満たした
3. **alchemy CLI は optional peerDependencies を実行時に要求する**: bun 実行では `@effect/platform-node` と `@effect/platform-bun`(4.0.0-beta.102)を追加するまで CLI が起動しない
4. **Alchemy v2 ドキュメントの Async Worker + DO の例は `bindings:` プロパティだが、実際の `WorkerProps` の型は `env:`**(`bindings?` は WorkerVersion 側の別物)。beta ゆえのドキュメント乖離
5. `cloudflare:test` の `env` の型付けは `Cloudflare.Env` の global augmentation で行う(`ProvidedEnv` 拡張はまだ動くが deprecated。`env` 自体も `cloudflare:workers` からの import が推奨に変わっている)
6. テレメトリ: alchemy は CLI テレメトリを送る(`DO_NOT_TRACK=1` か `ALCHEMY_TELEMETRY_DISABLED=1` で無効化、`~/.alchemy/telemetry-disabled` で永続 opt-out)。wrangler も同様(`WRANGLER_SEND_METRICS=false`)。**「言わざる」原則はメンテナ環境の CI にも適用したいので、Phase 1 で CI の環境変数に無効化を入れるべき**

## 採用判断への示唆

- ADR-0005(HttpApi、Hono 不使用)と ADR-0012(両対応)は、このダミー規模では**問題なく成立**。スキーマから型付きハンドラ・バリデーション・エラー応答まで一貫して導出される体験は良好
- HttpApi が `unstable/` 名前空間にある点は認識しておく: v4 stable 化の際に API が動く可能性が明示されている。厳密ピン + 独立 PR 更新(ADR-0011)で吸収する前提
- ManagedRuntime パターンは DO と素直に噛み合う。DO には明示的な破棄フックがないため `runtime.dispose()` は呼んでいない(今回の Layer は リソースレスなので問題なし)。**リソースを持つ Layer(接続・タイマー等)を DO に載せる場合の後始末は実装時の設計課題**
- Effect ランタイム込み gzip 261 KiB は Workers 制限内だが、コールドスタートへの影響は未計測。Phase 1 で実測する

## 残った疑問(Phase 1 で解消すべきもの)

1. **実デプロイ未検証**: Alchemy v2 / wrangler とも Cloudflare 資格情報が必要。Phase 1 着工時に検証用アカウントで `alchemy deploy` と `wrangler deploy`(または Deploy to Cloudflare ボタン)を通すこと。クラウド開発環境で行うなら Cloud Agents > Secrets に CF トークンの登録が必要
2. Drizzle(`drizzle-orm/durable-sqlite`、ADR-0006)は本スパイクのスコープ外。DO 内自己マイグレーション + Effect サービス境界の検証が別途必要(alchemy は drizzle-orm 1.0.0-rc.4 を optional peer に持っており、バージョン整合の確認も)
3. D1(プロジェクト外メタデータ)との結線は未検証(DO SQLite のみ検証した)
4. Effect v4 stable 化のタイミング(ROADMAP のウォッチ項目のまま)
5. alchemy 2.0.0-beta の破壊的変更ペース(beta.47 の changelog でもブリッジ挙動が動いている)。ADR-0011 の厳密ピン運用が必須

## 本採用時に統合すべきルート変更

- `.fallowrc.json` の `ignorePatterns` に `spikes/**`(spike-c ブランチと同一の 1 行。どちらが先にマージされても内容が同じなので衝突しない)
- ルート `package.json` / `vitest.config.ts` / `ci.yml` は変更していない
- Phase 1 で apps/server に組み込む際: effect(v4 beta、厳密ピン)を apps/server の依存に追加し、プレースホルダ worker を HttpApi 構成に置き換える。CI 環境変数にテレメトリ無効化(`DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false`)を追加する
