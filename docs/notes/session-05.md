# セッション 05 メモ(メンバーシップログのサーバー保存 — apps/server 基盤 + CRYPTO_SPEC §6.4)

日付: 2026-08-02。前提: PR #12・#13(packages/crypto = E2EE コア)マージ済み。
スコープ: 仕様追記(§6.4 サイズ上限)+ packages/core + packages/api-schema + apps/server
(プロジェクト DO・チェーン追記 API)+ vitest-pool-workers テスト。

## 1. やったこと(コミット順 = 層順)

1. **spec**: §6.4 にサイズ上限(サーバー受理ポリシー)とプロジェクト ID = genesis
   エントリハッシュを規定(§6.1 の先送り項目の解消)
2. **deps**: effect 4.0.0-beta.102 を core / api-schema / server に完全ピンで追加
3. **core**: `CryptoResult`(kind 判別 union)→ `Data.TaggedError` マッピング
   (`fromCryptoResult` / `cryptoEffect`。セッション 04 裁定 (b) の帰結)+ `ProjectId`
4. **api-schema**: チェーン init / get / append の HttpApi 定義。ChainEntry のワイヤ
   Schema(op 判別 union、crypto の `ChainEntry` と型レベルで一致固定)+ 型付きエラー
   (404 / 409 CAS / 409 genesis 重複 / 413 / 422 検証失敗 / 422 累積上限)
5. **server**: `ProjectChainDO`(DO SQLite append-only 保存、verifyChain 再実行、
   CAS、受理ポリシー、Semaphore(1) 直列化)+ HttpApi worker + 認証サービス境界
6. **テスト**: ベクター正常系 9 + 認可系 negative 14 の API 経由再生、CAS 競合、
   genesis 重複、サイズ / 累積上限、認証境界。全 30(サーバー)/ root 197 PASS

## 2. 裁定事項(重要: 所有者の実時間応答が得られなかった)

セッション中に AskUserQuestion で 4 件の裁定を仰いだが応答が得られなかったため、
**すべて「推奨案で仮進行 + PR レビューで所有者が承認/差し戻し」**とした。4 件とも
不可逆な選択肢(合意規則化 = crypto 変更)を避けた形になっている。マージ = 承認とみなす。

### 裁定 1: エントリ全体サイズ上限(§6.1 の先送り項目)

比較した案: (a) 受理ポリシー 1 MiB【採用】/ (b) op 別上限(64 KiB + grant_server
例外)/ (c) 合意規則化(verifyChain 組み込み)/ (d) 規定しない。

採用理由: §6.1 のフィールド上限(合意規則)が仕様適合エントリの正規化サイズを最大
約 516 KiB(grant_server の最大形 = 1024 B 環境 ID × 256)に**数学的に束縛**するため、
1 MiB の受理ポリシーは仕様適合エントリを拒否し得ない = 実装間差異によるチェーン分裂が
構造的に起きない。(c) は packages/crypto 変更(人間レビュー + ベクター先行)を発動し、
フィールド上限と二重の検査になるだけで暗号学的利得がない。(d) は仕様の
「§6.4 実装時に追加で規定する」への回答にならない。

### 裁定 2: チェーン累積上限(先送り項目とは別の追加論点)

比較した案: (a) 受理ポリシーで導入(10,000 エントリ / 累積 32 MiB)【採用】/
(b) 導入しない / (c) 合意規則化 / (d) エントリ数のみ。

採用理由: 追記は §6.4 により全チェーン再検証(O(n) 署名検証)であり、member 権限の
`rotate_epoch` 連打でチェーンを肥大させる DoS(サーバー CPU + 全クライアントの同期・
検証コスト)が開いている。受理ポリシーなら将来の引き上げが過去チェーンの有効性に
影響しない。「長いチェーン = 無効」は有効性の意味論として不自然なので合意規則化しない。

### 裁定 3: プロジェクト ID と DO 名前解決

比較した案: (a) genesis エントリハッシュ = project_id、DO は idFromName【採用】/
(b) サーバー採番(newUniqueId)/ (c) クライアント生成 ULID / (d) D1 projects テーブル。

採用理由: (a) はチェーンと ID を暗号学的に束縛する — サーバーが同じ ID で別チェーンを
配布する差し替えを、クライアントが genesis ハッシュ再計算だけで機械的に検出できる
(§6.1 にはエントリ↔プロジェクトの束縛がないため、この性質は ID 設計からしか得られない)。
同一 genesis の再投入は構造的に同一 DO へ到達し重複拒否になる。D1 不要なので、org 連携
(AUTH_SPEC §9、認証セッション送り)の先取りもしない。(d) はスコープ外の D1 に踏み込む。

### 裁定 4: 認証スタブの本番混入防止

比較した案: (a) モジュールグラフ分離【採用】/ (b) 環境変数切替 / (c) ビルド時 define +
DCE / (d) 別パッケージ(@maruhi/server-testing)。

採用理由: (a) はスタブを `apps/server/test/support/auth-stub.ts` に置き、wrangler の
バンドルが `src/index.ts` を起点とする以上、スタブが本番ビルドに入る経路が構造的に
存在しない(設定ミスで有効化される (b)・検証コストの高い (c) と違い、保証が bundler の
module graph で機械的)。本番側は「明示の未認証プレースホルダ」(`unauthenticatedRequestAuth`)
のみで、これはスタブではなく現状の正直な表現。

**既知の制約(スタブ期間中)**: クライアントの身元申告は信用しない。追記 API の保護は
現状チェーン署名の検証(§6.4)のみで、リクエスト主体の認証は行われない。認証セッションで
SessionService / TokenService の実装が `RequestAuth` に結線される。

### その他の設計判断(機械的・可逆。推奨案で進行)

- **Drizzle 見送り(DO チェーンテーブル)**: ADR-0006 は「リポジトリ層をサービス境界に
  閉じる」が本旨。単一 append-only テーブル(SELECT 1 本 + INSERT 1 本)にマイグレーション
  生成の利得はなく、drizzle-orm 依存(1.0.0-rc 系)を今入れる理由がない。素の SQL を
  `ChainStore` サービス境界内に閉じた(Drizzle 型どころか SQL も外に出ない)。
  D1 のユーザー / 組織スキーマ導入時(認証セッション)に Drizzle を導入し、その時に
  DO 側も揃えるか再評価する
- **DO 変更操作の直列化は Effect Semaphore(1)**: DO の input gate はストレージ以外の
  await(verifyChain 内の crypto.subtle)中に開くため、ゲート任せでは追記同士が交錯し
  「検証済み → 挿入」の間に別追記が入り得る。Semaphore で直列化し、seq PRIMARY KEY を
  最終防衛とした
- **HTTP 生ボディ上限 4 MiB は実装詳細**: 仕様(§6.4)は正規化バイト列基準(1 MiB)のみを
  規定。生ボディ上限は JSON エスケープ膨張(最悪 ~6 倍)を見込んだ JSON パース前の
  メモリ DoS 防御で、スキーマ外の素の 413 で返す
- **自由文字列の §6.1 上限を api-schema の Schema に重複させない**: 上限超過は常に
  verifyChain の `invalid-payload`(ベクターで固定された理由コード)として報告されるべきで、
  Schema 400 と二重の拒否経路を作らない。固定長 hex のみ Schema で検査(安価・正確)

## 3. ハマったこと・環境知見

- **cloudflareTest プラグイン(0.20.1)にはテスト間ストレージ分離がない**(旧
  defineWorkersConfig の isolatedStorage に相当する機能がソース上存在しない)。DO SQLite は
  ファイル内のテスト間で持ち越されるため、beforeEach で明示リセットした。さらに DO の
  ManagedRuntime layer は最初のメソッド呼び出しまで遅延構築されるので、リセット側で
  CREATE TABLE IF NOT EXISTS してから DELETE する必要がある
- **workers-types と DOM lib の併用**: server の tsconfig は
  `types: ["@cloudflare/workers-types", "@cloudflare/vitest-pool-workers/types"]` +
  `lib: ["ES2023", "DOM"]`。DOM lib がないと @maruhi/crypto のソース(DOM の
  SubtleCrypto オーバーロード前提)が typecheck を通らない(workers-types は
  exportKey の戻り値を union に潰している)。併用しても重複識別子エラーは出なかった
- **workers-types の RPC スタブ型は union 戻り値を分配する**: `Promise<A|B>` を返す DO
  メソッドがスタブ経由だと `Promise<A>&... | Promise<B>&...` になり await 型が壊れる。
  worker 側で `as Promise<T>` に戻すヘルパ(rpcCall)を挟んだ
- **HttpApi ハンドラのエラー型はエンドポイント宣言と厳密一致が必要**: ハンドラの
  エラー union が宣言より 1 型でも広いと `.handle()` の型が崩れ、離れた場所
  (toWebHandler の Context 型が unknown になる等)に誤誘導なエラーが出る。共有写像
  関数はオーバーロードで戻り値 union を絞ること
- **oxlint の no-underscore-dangle は有効**(eslint-js プラグイン経由)。`_tag` への
  直接アクセスや `_` 接頭辞の識別子はテストでも書けない。判定は instanceof で行う
- **fallow の CRAP ゲートは cyclomatic 6 でも踏む**(coverage 推定 0 の関数は
  CRAP = c²+c > 30)。flat な switch 写像でも分割・共通化で 4 以下に抑える。DO の RPC
  メソッドは静的には未参照に見えるため `fallow-ignore-next-line unused-class-member` で
  理由付き抑制した
- Effect v4 beta.102: `Effect.catchAll` は存在しない(catchTag / catchTags / catchCause)。
  Semaphore は `effect` 直下の `Semaphore.makeUnsafe(permits)` + `withPermit`

## 4. 次セッションへの申し送り

- **PR マージ後**: ROADMAP のメンバーシップログ項目の注記を更新(サーバー保存・追記 API
  完了、残りはクライアント同期。完全チェックオフはしない)← 本セッションの PR 作成後の
  イベントで対応予定
- **裁定 1〜4 は PR レビューでの所有者承認が必要**(§2 参照)。差し戻しの場合、
  仕様(CRYPTO_SPEC §6.4 の 2026-08-02 追加 2 項目)と実装(apps/server/src/policy.ts、
  chain-do.ts、auth.ts)を対で変更すること
- **Phase 0 の残項目「監査ログのスキーマ設計」は未着手**(本セッションの optional 項目。
  時間の都合で見送り)。次セッション以降で提案ドキュメントとして作成する
- 未実装(意図的スコープ外): §6.3 クライアント同期(DEK ラップ先一致検査・ヘッド
  ゴシップ)、認証の本実装(AUTH_SPEC。RequestAuth への結線点は用意済み)、監査ログ、
  D1、org 連携(projects.org_id)、実デプロイ検証(spike-b からの継続課題)
- プロジェクト ID = genesis ハッシュの帰結: クライアント同期実装時、`GET chain` の検証に
  「hash(entries[0]) == projectId」の照合を含めること(§6.4 に明記済み)
- 認可(reader の pull 拒否等、§6.2 の「サーバーはデータ操作もチェーン導出 role で認可」)は
  変数値 API の実装時に ChainState 導出(DO 内)を使って行う。今回のチェーン取得 API は
  認証がないため全公開(既知の制約に含む)
