# セッション 43: W2 — 読み取りダッシュボード(S3〜S7)の実装裁定(BM〜)

日付: 2026-08-29。目的: PR-W2(web-dashboard-design.md §7)の実装上の裁定の記録。
規範 = ADR-0018(改訂 1・2)・web-dashboard-design.md(§4 表示規律・§5 可視性
マトリクス)・AUTH_SPEC §5 / §11-4 / §11-5・AUDIT_SPEC §6 / §7。本文書が裁定する
のは仕様・設計文書が実装へ委ねた具体化(配信トポロジ・SPA ルーティング・
エラー分岐・可視性 UX・検査との両立)のみ。各裁定は「複数案 → 上位互換探索 →
3 周比較 → 自律選択」(session-27 §14 の様式。記号は session-41 の BH /
session-42 の BL の続きで BM〜)。

前提資料: web-dashboard-design.md 全節、ADR-0018 改訂 1・2、ADR-0013、
ADR-0017、AUTH_SPEC §3 / §5 / §11-4 / §11-5、AUDIT_SPEC §6 / §7、
session-39(AM〜AT・§10)、session-41(BA〜BH)、session-42(BI〜BL)、
apps/web(W1 現状)、apps/server/wrangler.jsonc。

## 1. 裁定 BM: web と server の配信トポロジ(同一オリジンの成立形)

制約の確認(いずれも実装済みの API / 防御であり、本 PR は挙動を変更できない):

- セッションクッキーは `__Host-maruhi_session`(AUTH_SPEC §5)— `__Host-` は
  ホスト単位で束縛され、別オリジンの Web からは同送されない。SameSite=Lax は
  クロスサイト XHR/fetch へのクッキー付与も遮断する
- OAuth callback は `${origin}/` へ 302(handlers-auth.ts — origin はサーバー
  自身のリクエスト URL 由来)。ログイン完了の着地点はサーバーの origin
- 既存 CSP は `connect-src 'self'`(write-headers.ts)。別オリジン API への
  fetch は CSP 拡張(= 例外面の追加)を要する

つまり「ダッシュボードと API の同一オリジン」は 3 点から独立に要求される。

### 第 1 周

- **案 BM-a: 別オリジンのまま CORS + SameSite=None 化** — 棄却: サーバーの
  クッキー属性・CORS ヘッダーの変更 = API 挙動の変更(本 PR の禁止事項)。
  かつ SameSite=Lax の CSRF 第一層を自ら外す方向で、防御的にも逆行
- **案 BM-b: web Worker にプロキシスクリプトを足して API を中継** — 棄却:
  現行 web は素の静的配信(Worker コードゼロ)であり、配信面に実行コードを
  足すのは ADR-0018「運営の配信面の最小化」と逆向き(session-41 BF-c と
  同じ棄却理由)。認証リクエストが 2 つの Worker を経由する形にもなる
- **案 BM-c: custom domain のゾーンルーティングで 2 Worker を同一オリジンに
  合成**(`example.com/auth/*` → maruhi-server、他 → maruhi-web)— 棄却:
  routes はゾーン(独自ドメイン)前提で、セルフホストの既定 URL =
  workers.dev(apps/server/wrangler.jsonc の `workers_dev: true` /
  SELF_HOSTING.md)では成立しない。既定デプロイで動かない形は採れない
- **案 BM-d: maruhi-server Worker に Workers Static Assets として web の
  ビルド出力を同梱する(単一 Worker)** — wrangler.jsonc の `assets` 設定のみ
  (API 実装・エンドポイントは無変更)。セッション・CSP・callback の 3 制約を
  すべて構成だけで満たす

### 第 2 周(上位互換探索)

- BM-d の詳細形: `assets.directory = ../web/dist/public`(web のビルド出力 +
  write-headers.ts の生成物 `_headers` / `_redirects` をそのまま同梱)。
  `run_worker_first` に API のパス空間(`/auth/*`・`/projects`・`/projects/*` —
  api-schema の全エンドポイントはこの 2 前置に収まる)を列挙し、API リクエスト
  は常に Worker(HttpApi)へ、それ以外はアセット層(SPA フォールバック含む)へ。
  `html_handling` は W1 と同じ明示ピン(session-41 裁定 BH)
- 「wrangler deploy 一発」(CLAUDE.md セルフホスト原則)との整合: 単一 Worker
  形はむしろ 2 Worker 形(web を別デプロイ)より一発性が高い。deploy スクリプト
  (apps/server)に web ビルドを前置する(`bun run db:migrate && web build &&
  wrangler deploy`)。SELF_HOSTING.md の手順は増えない
- apps/web/wrangler.jsonc(maruhi-web)の扱い: **静的配信の検証ハーネスとして
  存置**(e2e は従来どおりこの Worker の wrangler dev に対して走る。アセット層
  の挙動 — `_headers` のデタッチ・`_redirects` の先勝ち — は同一のアセット
  ワーカー実装であり、検証対象の意味は変わらない)。ホステッドの配信面としては
  使わない(ダッシュボードは API なしでは成立しない)

### 第 3 周(再点検)

- W1 の不変条件への影響: `/invite` の per-path CSP・`_redirects` 正規化・
  meta CSP は配信バイト(dist/public)ごと server Worker に載る。
  `run_worker_first` は `/auth`・`/projects` 前置のみで `/invite` に触れない。
  既存検査(write-headers.ts)は全て非退行
- SPA フォールバックと API の共存: `run_worker_first` 列挙内は常に Worker
  (API の 404 意味論 — §11-2 の存在秘匿 — がアセット層に浸食されない)。
  列挙外の未知パスは従来の web Worker と同じ SPA フォールバック
- server テスト(vitest-pool-workers)への影響: wrangler.jsonc を読むため
  assets ディレクトリの実在が要る。テスト設定で `dist/public` を(空で)
  作成して吸収する(空ディレクトリ = アセット照合ゼロ = 全リクエストが
  従来どおり Worker へ。API テストの意味は不変)— 実測で確認
- 新しい失敗モード: web ビルドを忘れた deploy は古いアセットを配る(API とは
  独立に更新が漏れる)。deploy スクリプトへのビルド前置で系統的な発生源を
  閉じる。アセット無しでの deploy は wrangler がディレクトリ欠落で落ちる
  (黙って API 単体になる形はない)

**選択: 案 BM-d(単一 Worker — maruhi-server が web アセットを同梱配信)**。

## 2. 裁定 BN: バンドル語 `hash` 全面禁止検査(session-41 BG)との両立

S5(チェーン取得)・S6(監査)の応答フィールド(`headHashHex`・
`prevHashHex`・`chainHeadHashHex` 等)の消費で BG の検査
(`/\bhash\b/i` の全面禁止)が割れる、が本裁定の出発点だった。

### 第 1 周

- **実測**: `\bhash\b` は**単語境界つき**であり、`headHashHex` /
  `auditHeadHashHex` / `prevMetaSigHashHex` のような複合識別子には一致しない
  (`d`↔`H`・`h`↔`H` はどちらも単語文字同士で境界が立たない)。一致するのは
  裸の語 `hash`(識別子・文字列・UI 文言中の単独語)のみ
- **案 BN-a: 検査を緩和(フィールド名の許可リスト)** — 棄却: 上の実測により
  緩和の必要自体がない。許可リストは「フラグメント非読取」の保証を将来の
  ドリフトに対して弱める(BG が明示的に避けた方向)
- **案 BN-b: 検査を無変更のまま、web 実装側の規約で裸の語を避ける** —
  API フィールドは元々複合名で一致せず、実装側で裸の `hash` を書く必然が
  ない(変数名は `headHashHex` のまま運び、UI 文言は "chain head" /
  "digest" 系の語で表現できる)

### 第 2 周(上位互換探索)

- UI 文言(英語 — ADR-0017)で「ハッシュ」を名指す必要があるか: S5 のヘッド
  表示は "Chain head" + seq + hex 値、S6 の突合誘導は "verify with
  `maruhi audit verify`" で足りる。hex 値そのものがラベルの意味を運ぶため、
  裸の語 `hash` を含む文言は一つも要らない(実装後にビルド検査が裏書きする)
- 新規に import する Astryx コンポーネントのチャンクが語 `hash` を持ち込む
  可能性: これは BG が設計済みの「上流変化で意図的に割れる」型そのもので、
  割れたらその時点の裁定を強制する(先回りの緩和はしない)

### 第 3 周(再点検)

- 検査対象は `dist/public` の全 JS + index.html(BG のまま)。ダッシュボード
  実装後のビルドで 0 件を確認することが本裁定の受入条件
- 効果の再確認: 「招待トークン(フラグメント)を読める字面が配信物のどこにも
  存在しない」は W2 のバンドル拡大後も全パスで検査可能なまま保たれる

**選択: 案 BN-b(検査は無変更・実装規約で裸の語 `hash` を持ち込まない)**。
保証の弱化ゼロ(BG の「割れたら裁定を強制する」型もそのまま)。

## 3. 裁定 BO: SPA ルーティングと `not_found_handling`(session-41 BF の申し送り)

### 第 1 周

- **案 BO-a: `not_found_handling` を SPA のまま維持し、ダッシュボードを
  `/dashboard` 前置のクライアントルートとして実装** — 深リンク
  (`/dashboard/projects/:id`)は SPA フォールバックで成立。API のパス空間
  (`/auth`・`/projects` 前置)と SPA のルート空間を**素で分離**する
- **案 BO-b: ルートごとの静的 HTML を出す(`not_found_handling` 廃止)** —
  棄却: funstack-static はルート単位の静的 HTML を出さず(session-41 BF-b と
  同じ確認)、動的パス(`:projectId`)は列挙不能。マルチエントリ化は
  ビルド複雑性だけ増やす
- **案 BO-c: ダッシュボードのルートも `/projects/...` に置く** — 棄却:
  BM の `run_worker_first` 列挙と衝突し、深リンクの直接ナビゲーションが
  API の JSON(401/404)に落ちる。UI のパス空間と API のパス空間の重畳は
  存在秘匿(§11-2)の応答意味論を UI 導線に混ぜる方向でもある

### 第 2 周(上位互換探索)

- ルート集合: `/dashboard`(S3 ログイン / S4 一覧 — 認証状態で出し分け)、
  `/dashboard/account`(S6 本人軸 = `/auth/audit/events`)、
  `/dashboard/projects/:projectId`(S5 / S6 プロジェクト軸 / S7 — タブ)。
  タブはルート化しない(URL に載せる必然がなく、ルート表面 = near-miss
  クラスの増加を最小に保つ)
- funstack-router の部分ルート定義(`route()` を共有モジュール、`bindRoute()`
  で server 側に結合)により `:projectId` の型付き取得(`useRouteParams`)が
  成立することを確認

### 第 3 周(再点検)

- BF(near-miss 正規化)の対象は `/invite` のみで変更なし。`/dashboard` 系の
  タイポは任意の 404 パスと同じクラス(SPA シェル。BG 検査でフラグメント
  非読取が保証済み)であり、正規化ルールを増やさない
- 未認証で深リンクを踏んだ場合も SPA シェルが出て、各画面の 401 分岐(BP)が
  ログイン導線を出す — `not_found_handling` の意味論に依存する画面はない

**選択: 案 BO-a(SPA フォールバック維持・`/dashboard` 前置のルート)**。

## 4. 裁定 BP: 未ログイン・セッション期限切れ(401)・能力制限(403)の分岐と文言

### 第 1 周

- **案 BP-a: 画面ごとに個別処理** — 棄却: 401/403/404 の分岐は全画面共通で、
  個別処理は文言の漂流(表示規律 §4 違反の混入面)を作る
- **案 BP-b: 薄い fetch 層で HTTP 状態を型付きの結果に写し、分岐を一元化** —
  分類: `ok(T)` / `unauthorized`(401)/ `forbidden`(403 — reason 同梱)/
  `notFound`(404)/ `error`(その他 + ネットワーク)。UI はこの型だけを見る

### 第 2 周(上位互換探索 — 文言。すべて英語 = ADR-0017)

- **401(未ログイン・期限切れの区別なし)**: サーバーは区別を返さず、UI も
  区別を捏造しない。`/dashboard` 直下 = S3 ログインカード("Sign in with
  GitHub")。画面内の再取得での 401(期限切れの典型)= 同じログインカードへ
  差し替え + "Your session has ended. Sign in again to continue."
- **403 `session-not-allowed`**: 本 PR の消費 API は全て
  `SESSION_ALLOWED_ENDPOINTS` 内であり正常系では発生しない(発生 = 新旧不整合
  等の異常)。汎用文言 "This action is not available to browser sessions.
  Use the maruhi CLI." で CLI へ誘導(隠さない — fail-closed の可視化)
- **403 その他(`insufficient-role` 等 — S6 invites の admin 未満が正常系)**:
  "Not available to your role in this project, as reported by the server."
  何が隠れているかの示唆(件数・種別)は載せない(AUDIT_SPEC §7)
- **404(§11-2 の存在秘匿)**: "The server reports no such project for your
  account." — 「存在しない」と「メンバーでない」を区別できない応答である
  ことを UI も区別せずに写す
- **ネットワーク・5xx**: "Could not reach the server." + retry ボタン

### 第 3 周(再点検)

- CSRF: 書き込み系はログアウト(POST `/auth/logout`)のみ。fetch 層が
  mutation に `x-maruhi-csrf: 1` を一律付与する(§11-4)
- 401 分岐がログイン画面を出すとき、元 URL への復帰は担保しない(callback は
  `${origin}/` 固定 — BM の制約)。ログイン後の再導線は S1/S4 の静的リンクで
  足りる(復帰 state をどこかへ持つ形は保存面を増やすだけ)
- 表示規律との整合: エラー文言も「サーバー申告」の言い回しで統一し、
  クライアント側の推測(expired / revoked / not a member 等の断定)を含めない

**選択: 案 BP-b + 上記文言**。

## 5. 裁定 BQ: S6 監査ビューアの可視性クラス表示 UX(設計文書 §8 申し送り)

### 第 1 周

- **案 BQ-a: クラス選択 UI(クラス 1 / クラス 2 の切り替え・高度フィルタ)** —
  棄却: クラスはサーバー認可の内部構造であり、admin 未満の画面に「クラス 2」
  という語を出すこと自体が不可視集合の存在を UI が示唆する形(件数非漏洩の
  精神と逆)。高度な横断検索は CLI(`maruhi audit`)の領分で、W2 の需要は未実測
- **案 BQ-b: 単一の時系列リスト + 役割適応の見出し** — admin 未満:
  "Events visible to your role"(AUDIT_SPEC §7 / 設計文書 §4-4 の規定文言)。
  admin(応答に `seq` が載る場合)のみ seq 列を表示。フィルタは置かず
  `before` カーソルの "Load more" のみ

### 第 2 周(上位互換探索)

- seq 列の出し分けを「役割の事前判定」でなく「**応答に seq があるか**」で行う:
  クライアントが role を推測して出し分ける形は §5 マトリクスの「表は UI の
  出し分けであり防御ではない」を超えて判定ロジックの複製になる。応答適応なら
  サーバー認可が唯一の判定点のまま
- invites タブ(admin 軸): 403 は BQ/BP の役割文言で表示し、タブ自体は隠さない
  (隠すと「自分に invites 監査があるか」を UI が事前判定する形になる。
  表示は BP の "as reported by the server" 文言で統一)
- 完全性主張の排除: 欠番検査・突合は表示せず、フッターに
  "Integrity checks are the CLI's job: `maruhi audit verify`" の静的案内のみ
  (設計文書 §3 S6 の規定)

### 第 3 周(再点検)

- 本人軸(`/auth/audit/events`)も同一のリスト部品を使う(seq は D1 経路で
  常に欠落 — AUDIT_SPEC §7 — なので seq 列は自然に出ない)
- イベント行の表示フィールド: event 名・serverTs・actor(userId + FP)・
  target・environment/variable ID・payload(JSON 折りたたみ)。すべて
  記録どおり = サーバー申告の生値。表示名の解決(検証済みステートメント経由)
  は行わない — 検証を持たない Web での名前解決はステートメント検証なしの
  名前信用になる(§12-2 の「検証を通らない名前を信用しない」に反する)ため、
  識別子のみ表示が表示規律上の正解

**選択: 案 BQ-b(単一リスト + 応答適応の seq 列 + 規定文言 + フィルタなし)**。

## 6. 裁定 BR: API 消費の実装形(型・クライアント層)

### 第 1 周

- **案 BR-a: Effect HttpApiClient(api-schema からの導出クライアント)** —
  棄却: Effect ランタイム + Schema デコーダ一式が Web バンドル(= TCB)に
  入る。CLAUDE.md「フロントの供給網を小さく保つ」と ADR-0018 決定 1 の
  バンドル検査単純性に逆行。CLI と違い Web の消費面は GET 中心の 9 面で、
  導出の利得が薄い
- **案 BR-b: 素の `fetch` + 手書き型** — 棄却: api-schema との型乖離が
  コンパイルで検出されない(監査応答のような広い構造で漂流リスク)
- **案 BR-c: 素の `fetch` + api-schema からの type-only import** —
  `import type`(erasable)のみなら実行コードはバンドルに一切入らず、
  型は単一定義(`typeof XSchema.Type`)に束縛される。web の devDependencies に
  `@maruhi/api-schema`(workspace)を追加するだけ

### 第 2 周(上位互換探索)

- ランタイム検証(Schema デコード)を持たない残余: 表示専用・値なしの読み取り
  であり、形の崩れは表示の崩れにしかならない(認可・秘匿はサーバー側)。
  クライアント側での applicative な防御(optional チェーン)で足りる。
  むしろ「Web バンドルに Schema 検証を積まない」は表示規律(検証を実装
  しない)と同じ側に立つ
- type-only 徹底の強制: `import type` のみを使い、oxlint / tsc
  (`verbatimModuleSyntax` 相当の設定があれば)で担保。バンドルへの混入は
  BG 検査(api-schema の実行コードは `hash` 語を含む)でも二次検出される

### 第 3 周(再点検)

- fetch 層は `credentials: "same-origin"`(既定)+ mutation の CSRF ヘッダー
  (BP)+ `accept: application/json`。API ベース URL は相対(同一オリジン —
  BM で構成保証)
- ページングの consume(`nextAfter` / `before`)もこの層に置かず画面状態で
  持つ(層はステートレスに保つ)

**選択: 案 BR-c(素の fetch + type-only import)**。

## 7. 裁定 BS: e2e の認証画面テストの形(モック / フィクスチャ)

### 第 1 周

- **案 BS-a: 実サーバー(vitest-pool-workers の SELF)と結合した e2e** —
  棄却: web e2e は wrangler dev(静的配信)+ Playwright の既存ハーネス
  (session-41 BD)であり、そこへ server の D1/DO 起動・OAuth フェイクを
  持ち込むとテストが配信検証から統合検証へ肥大する。GitHub OAuth は
  実フローをそもそも e2e できない
- **案 BS-b: Playwright の `page.route` で同一オリジンの API パスを
  インターセプトし、フィクスチャ JSON を返す** — 配信・描画・CSP は実物
  (wrangler dev + 実ブラウザ)のまま、API 応答だけ差し替える。フィクスチャは
  api-schema の型に適合するリテラル(tsc が型で拘束)

### 第 2 周(上位互換探索)

- CSP との関係: `page.route` はネットワーク層の差し替えであり、ページから見た
  リクエスト先は同一オリジンのまま — `connect-src 'self'` の検証を弱めない
  (violation ゼロのアサーションが全ダッシュボード画面で維持できる)
- 網羅する分岐: 未ログイン(401 → S3)、ログイン済み(S4 一覧 + ページング
  ボタンの有無)、プロジェクト画面(S5 チェーン/環境、S6 監査 + 役割文言、
  S7 フラグ + dismiss 静的案内)、403(invites の admin 未満文言)。
  ログアウトは POST への CSRF ヘッダー付与をルートハンドラ内で検証

### 第 3 周(再点検)

- モックの漂流リスク: フィクスチャが実サーバーの応答と乖離する面は残る
  (e2e は描画とゲーティングの検証であり、ワイヤ互換の真実源は api-schema の
  型 + サーバー側テスト)。型付きフィクスチャで乖離の大半はコンパイル検出
- 既存 e2e(CSP・/invite・SPA ナビゲーション)は無変更で残し、非退行を担保

**選択: 案 BS-b(page.route + 型付きフィクスチャ)**。

## 8. 実施記録

- **配信構成(BM)**: `apps/server/wrangler.jsonc` に `assets`
  (`../web/dist/public`・`run_worker_first: ["/auth/*", "/projects",
  "/projects/*"]`・SPA フォールバック・html_handling 明示ピン)。
  `apps/server/package.json` の deploy / deploy:dry-run に web ビルドを前置。
  server テスト(vitest-pool-workers)は assets ディレクトリ不在でも全通過を
  実測(504 件 — pool はアセット設定を要求しない)
- **画面**: `apps/web/src/dashboard/` — `api.ts`(fetch 層 = BP/BR)・
  `types.ts`(type-only import = BR)・`routes.ts`(/dashboard 前置 = BO)・
  `shared.tsx`(失敗表示の文言一元化 = BP)・`chain-view.ts`(S5 の表示用
  畳み込み — 検証なし)・`DashboardScreen.tsx`(S3 + S4)・
  `ProjectScreen.tsx`(S5 + S6 + S7)・`AccountAuditScreen.tsx`(S6 本人軸)・
  `AuditEventList.tsx`(BQ)。`App.tsx` に bindRoute で結合、S1 に
  ダッシュボード導線を追加
- **複雑度規律への追随**: fallow の変更ファイル監査(CRAP 閾値)が新規 14 関数を
  検出 → 全て分解(op ハンドラ表・ガード分離・サブコンポーネント化)で解消。
  リポジトリの全高複雑度関数が本 PR 分だった(110k LOC 中 14 件)ことから、
  「関数 cyclomatic ≤ 4」が事実上の規律と判断し、抑制コメント・baseline 追加は
  使わなかった
- **テスト**: e2e 4 本追加(BS — page.route + 型付きフィクスチャ。S3 401 分岐・
  S4 ページング + CSRF 付きログアウト・S5〜S7 タブ + invites 403 文言 +
  seq 応答適応・本人軸の seq 非表示)+ web ユニットテスト新設
  (`vitest.unit.config.ts` = root vitest 統合、`test/unit/` — chain-view の
  畳み込み・api 層の分類と CSRF ヘッダー)。既存 7 本は無変更で通過
- **BG 検査の実測(BN)**: Astryx Table / TabList / SegmentedControl 等を含む
  拡大後バンドルでも語 `hash` は 0 件のまま = 検査は無変更で通過
- スコープ外の確認: server 実装・api-schema・CLI・packages/crypto に変更なし
  (server は wrangler.jsonc / package.json の配信構成のみ)。仕様の文言変更
  なし(設計文書 §3 S4・§7・§8 の追随のみ)

## 9. 実装後の再点検(上位互換の一巡再探索 — タスク手順 7)

- **BM 再点検**: `run_worker_first: true` + Worker 内アセットバインディング
  fetch(配信をコードで制御)を再検討し棄却 — 配信面に実行コードを足す方向
  (BF-c / BM-b と同じ理由)で、_headers / _redirects のアセット層意味論も
  自前再実装になる。宣言のみの BM-d が上位互換のまま
- **欠陥修正(BM — 実測で発見)**: `run_worker_first` の初版列挙
  (`/auth/*`・`/projects`・`/projects/*`)は **`POST /invites/accept`
  (§15-2 — CLI の招待受諾)を取りこぼしていた**。api-schema の全エンドポイント
  目録との突合で発見し、実測で確認 — 列挙外のためリクエストがアセット層に
  渡り、`_redirects` の小文字総取り `/invite*`(session-41 BF)が **POST ごと
  301 → `/invite` で飲む**(受諾 API の破壊)。`/invites`・`/invites/*` を
  列挙に追加して解消(実測: POST /invites/accept = Worker 401、`/invite` 静的
  200・`/Invite` 301 は不変)。教訓は session-39 §10-1 と同型 —
  「前置に収まっているはず」の列挙は全エンドポイント目録と機械的に突合する
- **付随観察(BM)**: run_worker_first 経由の Worker 応答にも `_headers` の
  `/*` から STS・nosniff が付与される(実測)。API 応答へのセキュリティ
  ヘッダーの追加は加法であり、エンドポイントの挙動・契約は不変
- **BM の実測(wrangler dev — combined 構成)**: `/` と `/dashboard` = SPA
  シェル 200、`/auth/config` = Worker(503 SetupIncomplete — 未設定サーバーの
  正しい応答)、`/projects` = Worker 401、`/invite` = 静的ページ +
  per-path CSP `script-src 'none'`、`/Invite` = 301 → `/invite`、`/` の CSP =
  ブートストラップハッシュ許可付き。W1 の全不変条件と API のパス分離が
  combined 形でも成立することを実測確認
- **残余(BM)**: pool-workers がアセット設定を無視するため、combined 形の
  配信挙動(run_worker_first の実効)は CI の自動テスト外(上の実測は手元の
  wrangler dev)。`deploy:dry-run` が設定の妥当性検査を担い、実効の確認は
  初回デプロイ後の実応答確認(W1 の BC/BE 推奨と同じ非荷重の推奨)に置く
- **BN 再点検**: 実測で裏書き(§8)。緩和・精緻化の必要は発生しなかった
- **BP 強化(採用)**: 画面内の 401 バナー(セッション期限切れ)にサインイン
  導線(`/dashboard` への Go to sign-in)を追加 — 文言だけで導線がない形は
  期限切れ時に行き止まりだった
- **ログイン後の着地の再検討(棄却)**: OAuth callback は `${origin}/`(S1)へ
  固定(API 挙動 — 本 PR で不変)。S1 で `/auth/me` を自動照会して
  ダッシュボードへ自動遷移する案は棄却 — P1(未認証の訪問者)の静的
  ランディングに API 呼び出しを持ち込み、サインイン済みで S1 を見たい人の
  導線も奪う。S1 の静的リンク(open the dashboard)で足りる
- **S5 の FP 列の再検討(棄却)**: メンバー表への鍵 FP 列の追加は、add_member
  エントリが target の FP を運ばず(公開鍵のみ)、クライアントでの FP 計算は
  暗号導出(検証コードの同梱に半歩入る)ため置かない。FP はチェーンヘッド・
  監査行・grant_server(エントリが FP を運ぶ)の表示に限る — 表示規律 §4 の
  「FP は参照値」とも整合
- **レビュー反映(PR #107 Bugbot — 2 件とも正当なバグとして修正)**:
  (1) **stale fetch 競合** — `useApiResource` / `AuditEventList` は in-flight
  応答の後着が新しい画面状態を上書きできた(projectId・監査軸の切り替え)。
  effect クリーンアップの stale マーク / 世代カウンタで旧応答を破棄する形に
  修正。(2) **空ページ + nextAfter の終端誤断(S4)** — §11-5 の候補ページは
  ghost 除外・確認失敗の省略で `{ projects: [], nextAfter }` になりうるが、
  初版 UI は 0 行 = 終端と誤断して残り membership を隠した。行が増えるか
  nextAfter が尽きるまでカーソルを自動追跡する形に修正(深さは候補ページ数で
  有界 — 全滅時のコストは CLI の全ページ列挙と同水準)。e2e に空ページ跨ぎの
  ページングを追加
- **レビュー反映(PR #107 pullfrog)**: (1) **run_worker_first の被覆スイープの
  検査化** — 列挙は api-schema パス空間の手書き複製でドリフトが無音
  (navigation リクエストは SPA シェル 200 に飲まれる)という指摘を受け、
  session-capability.ts と同じ型のスイープテスト
  (apps/server/test/serving-topology.test.ts — 登録済み全エンドポイントの
  被覆 + `/invite` 非被覆の回帰ガード。wrangler.jsonc の実値は
  vitest.config.ts が unstable_readConfig で注入)を追加。§9 の欠陥修正を
  一回性の突合から常設の fail-loud へ格上げ。(2) **CI に deploy:dry-run**
  (step 8b — credential 不要の設定妥当性検査)を追加し、combined 構成の
  設定検証を人間儀式から CI へ移した(配信挙動そのものの自動テスト外は残余の
  まま)。(3) **CSP ヘッダーの実在 assertion** — violation ゼロ検査はヘッダー
  欠落でも通る(空虚)ため、/dashboard 系 3 パスのヘッダー実在を e2e で直接
  固定。(4) **プロトタイプ鎖ルックアップの自衛** — `ENTRY_FOLDERS[entry.op]` /
  `ROLE_TOKEN_COLOR[role]` は敵対的サーバーの op/role(`__proto__` 等)で
  プロトタイプ鎖の値に当たりうる(帰結は描画破壊のみ)— Object.hasOwn ガード +
  回帰ユニットテスト。(5) RoleToken を shared.tsx へ移動(置き場の指摘)。
  stale fetch の指摘は Bugbot 対応(40bd7b1)で修正済み(pullfrog は旧
  コミットのレビュー)。(6) incremental review の passing note(前進しない
  nextAfter を返す壊れた・敵対的サーバーでの無限追跡)も、カーソル非前進 =
  終端扱いの 1 条件で塞いだ(サーバー不信の姿勢の均一化)。**サインイン後の着地(`${origin}/`)の scope 質問**は
  本裁定(BP 第 3 周)どおり W2 では受容 — callback への return path 追加は
  API 挙動の変更であり、需要が出た時点の別 PR(AUTH_SPEC §3 の改訂)に送る
- **S6 ページ終端判定の再検討(維持)**: 「ページが limit 未満なら終端」は
  サーバーの既定 limit(50)への依存を足すため、「空ページで終端」の現行形を
  維持(1 回余分な取得と引き換えに応答形への仮定を持たない)

## 10. 第 2 次上位互換探索(オーナー依頼 — 2026-08-29)

オーナーの依頼「銀の弾丸・上位互換となる新しい案の模索」による追加の一巡。
標的は §9 までに**残余として記録した点**(= 現裁定の最弱部)。3 件を採用し、
4 件を検討の上で棄却した。

### 裁定 BT: e2e の配信系を combined 構成(デプロイされる実構成)へ移す(採用)

- **標的**: BM の最大残余 —「combined 形の配信挙動(run_worker_first の実効・
  SPA フォールバック・per-path ヘッダー)は CI の自動テスト外」。pullfrog の
  approve 済みレビューも "the residual" として名指ししていた。e2e は
  apps/web/wrangler.jsonc(**デプロイされない**静的専用ハーネス)に対して
  走っており、検証対象と配信物が別物だった
- **発見**: ダッシュボード e2e は API を page.route でモックする(裁定 BS)ため、
  **配信系をどちらの Worker にしても API 側の準備が不要**。ならば e2e の
  wrangler dev を apps/server(assets 同梱の本番構成)で起動すれば、既存の
  全アサーション(/invite の per-path CSP・near-miss 301・SPA フォールバック・
  CSP ヘッダー)がそのまま**デプロイされる構成の検査**になる — 変更は spawn の
  cwd 1 箇所 + 追加アサーションのみ
- **追加の利得**: 未設定ローカルサーバーの素の応答(503 / 401 JSON)が
  「Worker に届いた」ことの証拠になるため、**API パス到達の回帰テスト**を
  e2e に置けるようになった — §9 で実測発見した欠陥
  (`POST /invites/accept` が `_redirects` の総取りに 301 で飲まれる)を
  そのまま再現するテストを固定(スイープテストの静的検査 + 実配信の動的検査の
  二層になる)
- **棄却しなかった懸念の確認**: wrangler dev(server)は D1 / DO をローカルで
  自動生成し、OAuth secret なしでも起動する(§9 の BM 実測 4 回で確認済み)。
  D1 マイグレーション・secret はモック e2e の経路では不要
- apps/web/wrangler.jsonc は preview 用ハーネスとして存置(e2e の正は本裁定で
  server 構成へ移動 — 検証対象と配信物の一致が上位互換の本体)

### 裁定 BU: サインイン後の /dashboard 復帰(採用 — BP 残余の解消)

- **標的**: BP 第 3 周の受容残余「callback は `${origin}/` 固定のため、
  サインイン後にランディングへ着地し、もう 1 クリック要る」
- **採用形**: Sign in クリック時に sessionStorage へ**ワンショットのマーカー**を
  置き、S1 がマーカーを**消費したときだけ** `/auth/me` を 1 回確認して
  /dashboard へ戻す(`resume.ts` + S1 の不可視クライアント島)。マーカーなしの
  S1(P1 訪問者)は従来どおり API 呼び出しゼロ — BP 第 3 周が棄却した
  「S1 での常時 /auth/me 照会」を避けたまま余分なホップだけが消える。
  セッション未成立(OAuth 中断)はマーカーだけ消えてランディングに留まる。
  storage 不可(プライベートモード等)は型付きの「マーカーなし」へ劣化
- **棄却案**: (a) callback のリダイレクト先を /dashboard に変更 — API 挙動の
  変更で本 PR の禁止事項(需要が残れば AUTH_SPEC §3 の改訂として別 PR へ
  申し送り。本裁定の採用でその需要自体が概ね消える)。(b) document.referrer で
  GitHub 帰りを検出 — 受信 referrer は GitHub 側の Referrer-Policy に依存し
  非決定的。(c) `_redirects` による復帰 — 静的層はセッション状態を知り得ず、
  P1 のランディングを壊す

### 裁定 BV: e2e フィクスチャの Schema 実検証(採用 — BS 残余の縮小)

- **標的**: BS 第 3 周の残余「フィクスチャが実サーバー応答と乖離する面は残る
  (型付きで大半はコンパイル検出)」— 型適合は hex 長・パターン等の実行時
  制約を見ないため、fixture の座標値(row_id 長・projectId 形式)は目視だった
- **採用形**: e2e に「全フィクスチャを api-schema の実 Schema で
  `decodeUnknownSync` する」テストを追加。Schema 実行コードは**テスト
  プロセス内のみ**で動く(バンドル非投入 — 裁定 BR の「Web バンドルに
  Schema を積まない」と両立。web の devDependencies に効きは既存ピン
  `effect@4.0.0-rc.111` を明示追加 — 供給網の増分ゼロ)
- これで「モックとワイヤ契約の漂流」はコンパイル(型)+ 実行時(Schema)の
  二層で機械検査になる。残余は「サーバー実装が Schema より狭い応答を返す」
  クラスのみ(それは server 側テストの領分)

### 検討の上で棄却(第 2 次)

- **compat flag(`assets_navigation_has_no_effect`)で navigation 吸収自体を
  無効化し run_worker_first を不要化** — 棄却: API 到達性が Sec-Fetch-Mode の
  意味論に依存する形になり、明示列挙 + スイープ(検査可能・fail-loud)より
  推論が長くなる。フラグの将来変更にも晒される
- **apps/web/wrangler.jsonc の削除**(ハーネス二重化の解消)— 棄却:
  `bun run preview`(静的のみの軽量プレビュー)の価値が残る。e2e の正が
  server 構成へ移った(BT)ことで「検証対象の取り違え」の害は既に消えている
- **referrer / callback 変更による復帰**(BU の棄却案として上に記載)
- **フィクスチャの自動生成(Schema の Arbitrary 由来)** — 棄却: 画面の
  アサーションは具体値(名前・ID)に結びついており、生成値では検証が
  非決定的になる。実検証(BV)が同じ漂流検出をより単純に与える

## 11. 第 3 次上位互換探索(オーナー依頼 — 2026-08-29)

第 2 次(§10)後にまだ**手検証・規約どまり**で残っていた点を標的にした一巡。
2 件を採用、4 件を検討の上で棄却。

### 裁定 BW: ダッシュボード消費面の単一目録 + クライアント側スイープ(採用)

- **標的**: 「画面が呼ぶ全エンドポイントが `SESSION_ALLOWED_ENDPOINTS` の
  列挙内」という W2 の中核不変条件が**手検証**だった(pullfrog の初回レビューも
  人手で突合していた)。パス文字列も各画面に手書きで散在し、api-schema の
  リネーム・タイポは実行時 404 / 403 まで沈黙する
- **採用形**: `src/dashboard/endpoints.ts` — 全パスビルダー + 各ビルダーを
  api-schema の (group, endpoint) 識別子へ束縛する目録
  (`DASHBOARD_ENDPOINTS`)。画面はビルダー経由でのみ fetch する。ユニット
  テスト(test/unit/endpoints.test.ts)が目録を登録済み HttpApi と突合し、
  (1) **パス整合**(ビルダー生成パス = テンプレートのサンプル置換 — 未知
  パラメータは置換されず fail-loud)、(2) **セッション許可**
  (`isSessionAllowedEndpoint` — 新画面が列挙外 API を呼ぶ形は実行時 403 で
  なくテストで割れる)、(3) 目録の重複なし、を固定する
- **効果**: serving-topology スイープ(サーバー側 — run_worker_first 被覆)と
  対になり、**api-schema を中心に消費の両方向が機械検査**になる。あわせて
  serving-topology 側に負方向(`/invite`・`/dashboard` 系が worker-first に
  飲まれない)の検査を拡張
- 逆方向(「セッション許可の全読み取り面をダッシュボードが消費しているか」)は
  不変条件ではないため課さない(recoveryStatus・invites.list/revoke は許可
  済みだが W2 の画面外 — W3b の領分)

### 裁定 BX: wrangler 設定の単一真実源化 — apps/web/wrangler.jsonc の削除(採用)

- **標的**: §10 で「preview 用に存置」とした apps/web/wrangler.jsonc。
  BT(e2e の combined 移行)後、消費者は preview スクリプト 1 つになり、
  html_handling ピン等の**構成の二重管理**(ドリフト面)だけが残っていた
- **発見**: `wrangler dev --config ../server/wrangler.jsonc` は apps/web の
  cwd からでも成立する(パス解決は設定ファイル基準 — 実測: root 200 /
  /projects 401 / /invite 200)。preview をこれに差し替えると
  apps/web/wrangler.jsonc の消費者がゼロになる → 削除
- **効果**: 配信構成が apps/server/wrangler.jsonc の 1 本に集約され、
  デプロイ・e2e・preview の全経路が同一構成を読む。§10 の存置判断は
  前提(preview が旧構成を使う)が消えたため本裁定が上書きする

### 検討の上で棄却(第 3 次)

- **コンテンツハッシュ付きアセットへの `Cache-Control: immutable` 付与** —
  棄却: 性能改善であって残余(セキュリティ・正しさ)の解消ではなく、
  approve 後の PR に検査対象(write-headers の新ブロック)を増やす対価が
  釣り合わない。需要が出た時点の独立 PR へ
- **SRI(subresource integrity)** — 棄却: 全アセット自己配信 + 厳格 CSP の
  下で SRI が足す保証はない(配信者 = 検証者の構図は ADR-0018 Context の
  とおり SRI では壊せない)
- **`/*` CSP の form-action 'self' → 'none' 強化** — 棄却: ダッシュボードに
  フォームは無いが、'self' が既に同一オリジンへ拘束しており閉じる脅威が
  ない。W1 で固定した `/*` CSP 文字列の不変(非退行検査の前提)を崩す
  対価だけが残る
- **復帰マーカー鍵の export 共有(e2e との重複リテラル解消)** — 解消
  (下のレビュー反映で positive 側のテストがマーカー注入自体をやめたため、
  重複リテラルは negative テスト 1 箇所のみ。鍵名ドリフトはそのテストの
  期待〔ランディング残留〕を変えないため無害)
- **レビュー反映(pullfrog — BU の被覆指摘)**: 初版の resume テストは
  マーカーを addInitScript で注入しており、(1) consume ガードを消して
  「S1 で常時 /auth/me」に退行しても、(2) Link が onClick を運ばなくなり
  マーカーが書かれなくなっても、テストが割れなかった。positive テストを
  **実導線駆動**(/dashboard のログインカードを実クリック →
  /auth/github/start への実ナビゲーションを 302 → `/` で差し替え → 実装が
  書いたマーカーで復帰)に置き換え、**マーカーなしランディングの API
  呼び出しゼロ**をリクエスト収集で固定するテストを追加 — BU の 2 不変条件が
  どちらも fail-loud になった

## 12. 第 4 次上位互換探索(オーナー依頼 — 2026-08-29・最終回)

依頼: 「最後にもう一回だけ更なる上位互換のアイディアがないかを模索してください」。
第 3 次で導入した 2 つのスイープ(BW / serving-topology)自身を候補集合に含め、
「検査の穴」と「残った手書き重複」を標的に 3 周比較した。

### 裁定 BY: 消費面目録の完全化(採用)

BW の目録には検査の穴が 3 つ残っていた:

1. **ナビゲーション消費面の目録外** — ログインカードの
   `/auth/github/start` は fetch でなく Link だったため目録に載らず、
   パス整合もセッション面分類も未検査だった。`apiPaths.githubStart()` を
   追加し、目録へ `access: "session" | "unauthenticated"` 判別子を導入。
   スイープを access 対応にし、session 面は従来どおり
   `isSessionAllowedEndpoint`、unauthenticated 面は
   `UNAUTHENTICATED_ENDPOINTS`(AUTH_SPEC §5)への所属を要求する
   (認証必須面をナビゲーション導線として消費する形もテストで割れる)
2. **カーソルクエリ組み立ての 3 重複** — projects の `?after=` と
   audit×2 の `?before=` が画面ごとに手書きだった。`withCursor(path,
   name, value)` に一本化(唯一のクエリ付与点。encodeURIComponent 込み)
3. **ビルダー迂回の無検査** — 目録の網羅性は「画面はビルダー経由でのみ
   fetch する」規律に依存するが、その規律自体が手検証だった。ソース
   トリップワイヤ(src/ 配下・endpoints.ts 除外で
   `["']/(auth|projects|invites)` を走査)をユニットテストに追加。
   バッククォート文字列は対象外(コメント内のパス例と衝突するため)—
   word-hash トリップワイヤ(session-41 BG)と同じ「善意のドリフト検出」の
   位置づけで、意図的な迂回の防止は目的にしない

### 裁定 BZ: SPA ルート空間の非交差スイープ(採用)

- **標的**: BO の分離「SPA は /dashboard 前置、API は /auth・/projects・
  /invites 前置」のうち、逆方向 —「SPA のルートが run_worker_first に
  飲まれない」— の検査が serving-topology.test.ts 内の**手書きパス列挙**
  (4 パス)だった。ルート追加時に列挙の追随を忘れると検査が黙って狭まる
- **採用形**: routes.ts に homeRoute / aboutRoute を移し、全ルートの単一
  目録 `SPA_ROUTES` を export(App.tsx は bindRoute で結合するのみ)。
  web-unit テスト(test/unit/spa-topology.test.ts)が実ルート定義と
  実配信設定(`unstable_readConfig` で apps/server/wrangler.jsonc を読む —
  BT/BX と同じ「実物を読む」姿勢)を突合し、全 SPA ルートの具体化パスが
  どの run_worker_first ルールにも被覆されないことを検査する。ルール
  意味論(完全一致 / 前置 `*` のみ・それ以外は保守的に throw)は
  serving-topology 側と同一
- serving-topology 側の手書き 4 パス検査は**残す**(workerd 実環境での
  検査 + `/invite` は SPA ルートでないため BZ の目録外)。両者は重複でなく
  「サーバー側は代表点・クライアント側は全ルート導出」の相補

### 検討の上で棄却(第 4 次)

- **loader フックへの取得統合(funstack-router の loader でデータ取得)** —
  棄却: 画面の useApiResource / 手動ページングを全面改造する churn に対し、
  得られるのは取得タイミングの前倒しのみ。読み取り専用ダッシュボードの
  規模では上位互換でなく横移動
- **パラメータのブランド型(ProjectId 等の branded type)** — 棄却:
  ビルダー引数の取り違えを型で防ぐ案だが、W2 の消費面では projectId /
  environmentId の 2 種しかなく、ルートパラメータ由来の値は結局 string。
  儀式が増えるだけで実バグ面が現状ない
- **run_worker_first を api-schema から自動生成(コード生成)** — 棄却:
  生成器 + 生成物検査という新しい機構を持ち込む対価に対し、双方向スイープ
  (被覆 + 非交差)が既に同じドリフトを fail-loud にしている。設定は
  「読める素の JSONC」のままが自己ホスト配布物として優る

## 13. 第 5 次上位互換探索(オーナー依頼 — 2026-08-29)

依頼: 「まだ見つかるんですね。それは困るので、一回更なる上位互換のアイディアが
ないかを模索してください」。生成規則を明示して探索した: 第 3〜4 次の発見は
すべて「機械可読な正(api-schema / wrangler.jsonc / ルート定義)の手書き複製が
残っている場所」だった。そこで src/ 全域を対象に「手書き複製」を機械的に
grep 棚卸しし、残余 2 つを塞いだ。

### 裁定 CA: SPA パスビルダー(spaPaths)— BY の双対(採用)

- **標的**: 内部ナビゲーションのパスリテラルが src/ に 9 箇所散在していた
  (`/dashboard` 系 6 + `/` `/about` 3)。routes.ts のパス改名はリンク切れに
  なるが、SPA フォールバックが 200 でシェルを返すため**無音**(API 側で
  BY が塞いだのと同型のドリフト面が SPA 側に丸ごと残っていた)
- **採用形**: routes.ts 内のパス定数を単一の置き場にし、route() 定義と
  `spaPaths` ビルダー(home / about / dashboard / account / project)が同じ
  定数を読む。画面の href / navigateTo は全てビルダー経由。トリップワイヤ
  (裁定 BY)の前置集合に `dashboard` を加え、除外をビルダー置き場 2 つ
  (endpoints.ts・routes.ts)に拡張。spa-topology テストにビルダー ↔
  SPA_ROUTES の束縛検査(置換完全性 + 全ビルダーが宣言ルートに対応)を追加
- 同一モジュール内の定数共有なので、apiPaths ↔ api-schema のような
  突合テストは原理的に不要(複製自体が存在しない)— BY より強い形

### 裁定 CB: カーソルクエリ名のスキーマ突合(採用)

- **標的**: withCursor が付ける `after` / `before` は手書き文字列で、
  api-schema 側のクエリ宣言(membership.list の `after`、audit 系の
  `before`)とは無結合だった。パラメータ名のリネームはサーバーが未知
  クエリを無視するため「ページングが黙って 1 ページ目を返し続ける」形で
  無音に壊れる
- **採用形**: 目録に `cursor?: "after" | "before"` を追加(4 面が宣言)。
  スイープが登録エンドポイントのクエリ Schema の AST
  (`query.ast.propertySignatures`)にその名前の宣言があることを検査する

### 検討の上で棄却(第 5 次)

- **ruleCovers の共有化(serving-topology / spa-topology の重複解消)** —
  棄却: 実行環境が異なり(workerd / node)、共有には新しい置き場
  (テスト支援パッケージ等)が要る。15 行の意味論はどちらも保守的
  throw 付きで消費側に併置されており、共有の機構代のほうが高い
- **RoleToken の色マップを role 列挙と突合** — 棄却: api-schema に role の
  閉じた列挙が存在しない(チェーン導出)上、未知 role は Object.hasOwn
  ガードで中立 Token に**可視**に劣化する — 無音破壊でないため裁定の
  対象基準(silent drift)を満たさない
- **e2e 期待値のビルダー化** — 棄却: テストの期待リテラルをビルダーに
  すると同語反復(builder == builder)になり検査力が落ちる。ユニット
  スイープがビルダー ↔ 正を、e2e がレンダリング ↔ リテラルを固定する
  現行の 2 段が正しい形

### 収束の見立て

第 3〜5 次の全発見は単一の生成規則「機械可読な正の手書き複製を探す」から
出ている。CA/CB 後、src/ のパス・クエリ・ルートに残る手書き複製はゼロ
(grep 棚卸しで確認)で、残るリテラルは (a) ビルダー置き場の定義そのもの、
(b) テストの期待値(意図的 — 上記棄却)、のみ。この規則からの発見は
尽きたと判断する。次に上位互換が出るとすれば別の生成規則(例: W3 の
書き込み系で新しい正が増える時)からで、W2 の読み取り面では閉じた。
