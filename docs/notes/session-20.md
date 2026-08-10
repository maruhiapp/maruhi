# セッション 20 メモ(pull のメタデータのみモード — session-11 裁定済み後続 PR の最後の 1 本)

日付: 2026-08-10。前提: PR #39(セッション 19)マージ済みの main から開始。
スコープ: session-11 §5 の裁定済み後続 PR 3 本のうち残っていた 3
(pull のメタデータのみモード。1 = 公開設定エンドポイントはセッション 19、
2 = テスト支援フィクスチャ共有はセッション 17-1 で完了済み)。
**これで裁定済み後続 PR 3 本はすべて完了。**

## 1. 仕様(仕様先行 — マージをもって所有者承認)

- **AUTH_SPEC §12-7**: 一括 pull と同じ環境単位で**値(暗号文)と DEK を返さない**
  独立エンドポイントを明文化。応答 = 環境の最新ステートメント + 現エポック +
  全アクティブ変数の最新 `VariableMetaStatement` + 削除済みの deleted ステート
  メント。検証材料の同梱・クライアント検証の義務(§6.3)は一括 pull と同一、
  認可も同水準(§12-3 の同一行 = read × reader)
- **var.read の意味論(AUTH_SPEC §12-7 / AUDIT_SPEC §3.3)**: 記録条件は
  **暗号文の配布**である。メタデータのみモードは記録しない —
  「読んでいないものを読んだと記録しない」。理由は要ローテーション検出
  (AUDIT_SPEC §4)の「確実に取得した」ランクの入力純度: 値を読んでいない
  解決操作が var.read に混入すると「取得した」を過大申告する。逆方向の規律
  (読んだものは必ず記録)は一括 pull 側の「返した変数ごとに 1 行」が担う

## 2. 設計判断

- **ワイヤ形 = 独立エンドポイント** `GET …/pull/metadata`(クエリパラメータの
  モード切替でなく): 成功 Schema が別形(値・DEK フィールドが存在しない)で、
  union 応答よりも型が単純・自己記述的
- **既存変数への push は引き続き値付き pull を使う**: 裁定 3 の起草時
  (session-11)は値が無署名だったが、その後の真正性シリーズ(PR #30)で
  prev 連鎖(§4.1 = 検証済み最新値の signed-bytes ハッシュへの連鎖署名)が
  入ったため、**暗号文なしに prev を自計算できない**。よって
  - 新規作成: メタデータ解決のみ → create(**var.read ゼロ** — 意味論どおり)
  - 既存更新: メタデータ解決 → 値付き pull(この var.read は実際に読んだ記録
    として正しい)→ push
- **DEK 二重取得の解消(裁定 3 の後段)**: create 経路 = listMine 1 回のみ。
  既存経路 = 値付き pull の同梱 DEK を検証・開封し **listMine を呼ばない**。
  どちらも取得はちょうど 1 回。競合リトライの再解決では既知エポックの手持ちを
  優先し、エポックが進んだ時のみ listMine(従来の refreshEpochState のまま)
- **床(§6.3)との接続**: メタデータのみ pull には**メタ水準の床検査**を適用
  (checkEnvironmentMetadataPull = 環境・変数メタの後退 / 同一 metaVersion の
  signed bytes 相違 / 検証済み変数の欠落 / 削除の無断取り消し / tombstone
  差し替え)。値水準の検査と規則 (c) は値を運ばない形からは検査できない
  (検査済みと偽らない)。**床のコミットも行わない** — 変数床レコードは値の
  ダイジェストを要し、メタだけから捏造しない。帰結として create だけの push は
  床を確立しない(確立は次の値付き pull / run まで一周遅れる。床は SHOULD で
  誤検出なし)。攻撃面の含意: 解決応答から既存変数を隠して重複 create を誘導する
  攻撃は、床が確立済みなら欠落(variable-omitted)として検出される
- **`maruhi pull` コマンドは値付きのまま**: 既定表示(バイト長)と床の確立が
  値を要するため。メタデータのみモードの CLI 消費者は push の解決経路のみ

## 3. 実装

- api-schema: `EnvironmentMetadataPullSchema` + `pullMetadata` エンドポイント
- server: `activeVariableStatements` クエリ(deleted 側の active 版)、
  `pullEnvironmentMetadataProgram`(認可 reader・監査記録なし)、DO RPC、
  ハンドラ。値付き pull との共通前段は `requirePullContext` へ抽出
- cli: `pullVerifiedEnvironmentMetadata`(values.ts — 検証骨格は
  `verifyAllCommon` として値付きと共有)、`checkEnvironmentMetadataPull`
  (floor-check.ts — `checkFloorCommon` として共有)、push の resolveTarget /
  initialState の切り替え

## 4. テスト・品質

- server +2: 応答形(値の断片が JSON 全体に現れない・配布ステートメントが
  §6.3 クライアント検証を通る)/ 認可と存在秘匿(read スコープ 200・非メンバー
  404・スコープ外 404・削除済み環境 404)。監査ライフサイクルテストへ
  「pull/metadata を挟んでも期待イベント列が変わらない」を織り込み
- cli: 新フロー追随(解決 = メタデータ、既存 = 値付き 1 回)+ ワイヤレベルの
  退行防止 2 点(**create が値付き pull を呼ばない** / **既存 push が listMine を
  呼ばない**)+ deleted ステートメントのアクティブ一覧混入の拒否 + 床の欠落
  検出が push のメタデータ解決でも発火すること(floor-detection)
- fallow: 新規重複 5 群はベースラインへ逃がさず共通化(verifyAllCommon /
  checkFloorCommon / requirePullContext)で解消。checkEnvironmentPull の複雑度
  超過も同リファクタで閾値内へ
- `bun run check` green(924 テスト)

## 5. ハマったこと・環境知見

- **テストの deviceToken 再発行は同一ユーザーの既存トークンを置き換える**:
  fixture のトークンを後続リクエストで使うと 401 になる(data.test の認可
  テストで実測)。再発行後はそのトークンを使い続けること
- **vitest-pool-workers の既定 testTimeout 5s は負荷時にフレークする**:
  1 テスト 13 往復の既存テストが、スイート追加でスケジューリングが変わると
  5s を超えた(単体では 290ms)。server の vitest.config に testTimeout 15s を
  明示(ハング検出の有界性は維持)

## 6. スコープ外(申し送り — session-19 から継続)

- ドッグフーディング開始時の人間タスク: GitHub OAuth App 作成 +
  検証デプロイへの client_id/secret 登録(SELF_HOSTING.md 手順 5〜7)
- 監査イベント(auth.* の D1 側)は D1 監査基盤導入と同時(session-18 §3)
- チェーン追記系コマンド・crypto test/checks の整理候補(session-17 §4)
- Deploy to Cloudflare ボタン検証は Phase 2(公開時)
- 将来 Web ダッシュボードが名前一覧を出すときはメタデータのみモードを使う
  (var.read を汚さない一覧が既にワイヤにある)
