# セッション 13 メモ(DEK 真正性の実装 — セッション 12 仕様の実装 PR-1)

日付: 2026-08-04。前提: PR #27(CRYPTO_SPEC 0.4-draft = 値・DEK・変数メタデータの
真正性仕様)マージ済みを確認して開始(merge commit `5d0f576`。マージをもって仕様 —
session-12.md §10 の要裁定の推奨案込み — は所有者承認済みとして扱う)。
スコープ: session-12.md §9 の **PR-1 = DEK 真正性(案 B)**。ベクター先行 →
crypto → api-schema → server → CLI の層順でコミット。

## 1. やったこと

1. **テストベクター先行**(実装より先にコミット。人間レビュー対象):
   - `tools/generate_reference.py` を拡張: 新 op `create_environment`(payload 順
     `[environment_id, dek_commitment_hex]`)、`rotate_epoch` の 4 フィールド化
     (末尾に `dek_commitment_hex`)、§5.2 コミットメントの参照計算(LP + SHA-256)
   - `chain-entries.json` の**再生成**(session-12 §8-4 の影響一覧どおり):
     全 rotate に create が先行する 12 エントリの正規チェーン、
     `expected_head_states` の環境集合への意味論拡張(現エポック・作成 seq・
     エポック開始 seq・エポックごとのコミットメント —「未観測 = 1」廃止)、
     authz negative 追加(`authz-create-env-duplicate` /
     `authz-rotate-unknown-environment` / `authz-create-env-reader` / 検査順序
     3 件 / コミットメント形式違反 4 件 = payload 構造検査段 / コミットメント
     改竄の署名系 2 件)、`valid_appends` に環境ライフサイクルの許容境界 2 件、
     `environment_deks` セクション(ダミー DEK と実計算コミットメント —
     実装テストが §5.2 照合まで検査できる)
   - `dek-commitment.json` 新規(session-12 §8-3): 正例(dek-wrap.json basic と
     同一 DEK・座標 + epoch 1)+ `dek-mismatch` / 座標移植 3 種 / `wrong-domain` /
     `uppercase-hex` + `rewrap_invariance`(backfill・修復再登録の不変)
   - 差分確認: 既存 6 ベクターファイル(encoding / variable-encryption /
     recovery-wrap / dek-wrap / dek-wrap-signature / hpke)は byte-identical
     (oxfmt 適用後の git diff で機械的に確認)。verify_reference.mjs 全 191 検査
     PASS を確認してからコミット
2. **crypto**: `create_environment` の検証(role member 以上・
   `duplicate-environment` = 履歴全体一意)、`rotate_epoch` の
   `unknown-environment`(create 先行必須 — 既定値フォールバック廃止)、
   状態導出の拡張(`ChainState.environmentEpochs` → `environments` =
   現エポック・作成 seq・エポック開始 seq・コミットメント)、
   `dek-commitment.ts`(computeDekCommitment / verifyDekCommitment)、
   `ChainInvalidReason` + `DekCommitmentMismatch`。core の Effect マッピング追随
3. **api-schema**: op union へ create_environment、環境作成の複合形への置換
   (parentHeadHashHex + entry + name + deks)、rotate 複合エンドポイント新設
   (従来の 2 往復を廃止)、`EnvironmentConflict` の `exists` / `retired` 廃止
   (合意規則へ吸収。`duplicate-name` のみ残置)、`CompositeRequired`(422)、
   エラー契約の複合エンドポイントへの移動
4. **server**: 複合受理(composite-programs.ts — 原子性・複合内整合検査・
   同梱エントリ適用後状態でのラップ判定・行数/リクエスト上限の全経路適用)、
   汎用 append の 2 op 拒否、削除済み環境への rotate 404、
   `chain.environment_created` + rotate ミラーへの dek_commitment payload、
   `currentEpochOf` の新意味論(未観測 = defect)
5. **CLI**: env create の複合化(CLI 初の genesis 以外のチェーン追記。
   ChainHeadConflict の再同期 → 再署名リトライ、ラップ集合はメンバー集合変化時
   のみ再構築)、unwrap 後・DEK 使用前の §5.2 コミットメント照合、
   エポック導出の環境集合ベース化(ファントム環境の拒否)
6. **テスト**: crypto 4 実行環境(node / workerd / browser / bun)のベクター駆動 +
   server 173 / CLI 98 の受理系(session-12 §8-5 の PR-1 分)。フィクスチャは
   create_environment 先行へ全面改修
7. **docs**: 本メモ

## 2. 段階裁定(タスク指定の確認)

**`EnvironmentMetaStatement` は PR-1 に同梱しない**(タスク指定の裁定どおり):
複合環境作成は従来どおり裸の `name` を運ぶ。ステートメントの同梱・検証・保存、
§12-4 の「CAS 再試行での両方再署名」のステートメント側、AUDIT_SPEC §3.3
`env.created` の author 鍵 FP は PR-3 で追加する。公開前ワイヤの意図的な中間状態
であり、session-12.md §9 の「中間状態でも保証が単調に増える」ことは PR-1 単独でも
成立する(コミットメントだけで §1-i/ii = 偽 DEK 注入・偽 DEK での暗号化誘導が
閉じる)。別案(env-meta-sig の最小核の前倒し)は採らなかった — PR-3 の検証機構
(宣言ヘッド・認可時点・prev 連鎖)を部分実装すると PR-2 の値署名と共有すべき
機構が二重に生まれ、レビュー粒度の利点(§9 の分割理由)を失うため。

## 3. 裁定の細部(複数案比較 → 推奨で仮進行。確定条件 = PR レビュー承認)

### 3-1. ChainState の環境状態の形 = 環境ごとの構造体(environmentEpochs の置換)

| 案 | 評価 |
|---|---|
| **`environments: Map<envId, {currentEpoch, createdAtSeq, epochStartSeqs, dekCommitments}>`(採用)** | §6.3 の「各エポックの有効区間(開始 seq)」と §5.2 のコミットメントは同じ導出ループで得られ、環境の存在・エポック・コミットメントが 1 つの真実源に揃う。PR-2 の値検証(エポック整合・宣言ヘッド時点の現エポック)の入力がそのまま出来上がる |
| environmentEpochs を残し別マップ追加 | 「環境が存在するか」「現エポックはいくつか」の 2 つの照会が別マップに割れ、既定値 1 の残骸(`?? 1`)が生き残る温床になる。置換により全呼び出し箇所がコンパイルエラーで洗い出され、「未観測 = 1」の廃止漏れを構造的に防げた |

### 3-2. コミットメント API = DEK は Uint8Array で受ける

`computeDekCommitment({context, dek: Uint8Array})` は内部で `encodeHex`(小文字)
してから原像に載せる。hex 文字列で受ける案は呼び出し側の大文字 hex がそのまま
別原像になる事故(ベクター negative `uppercase-hex` の実装版)を許すため却下。
`verifyDekCommitment` の期待値(チェーン掲載値)は hex 小文字 64 文字のみ受理
(照合の正規形を 1 つに固定 — §5.1 実装の「大文字 hex を許すと正規形が複数生まれる」
と同じ理由)。

### 3-3. 複合エンドポイントの検査順序(サーバー)

`role(member)→ [rotate のみ: URL/エントリの environment_id 一致 →
アクティブ環境(404)] → 親ヘッド CAS → エントリサイズ・容量 → verifyChain
(合意規則)→ 複合内整合(全ラップ epoch = 確立エポック)→ ラップ受理
(§12-6 + §12-8)→ 原子書き込み`。論点:

- **rotate の 404 を CAS より先に置いた**: 削除済み環境への rotate は親ヘッドが
  何であれ受理されない定的な拒否であり、404 を CAS の後に置くと「リトライで
  解決しない 409」をクライアントに何周も回させる
- **未作成環境への rotate 複合はサーバーでは 404**(`unknown-environment` の
  422 ではなく): 環境のデータ行は複合受理でチェーンエントリと原子的に作られる
  ため、「行がないのにチェーンに create がある」は不変条件違反で、「行がなく
  チェーンにもない」= 未作成は行検査(404)が先に立つ。合意規則
  `unknown-environment` そのものは crypto 層の 4 環境ベクターテストが固定する
  (サーバー受理面の期待は membership.test.ts の対応表が明文化)
- **ラップの完全一致(recipient-missing)は個別検査(受信者・重複・署名)の後**:
  旧・環境作成プログラムの判定順を維持(理由コードの互換)

### 3-4. 複合の worker / DO の分担

actor = 認証主体の一致(§11-1 相当)は worker(ハンドラ)で先行検査し、DO は
callerUserId を信頼する — 汎用 append の既存分担と同一。DO 側は role・CAS・
verifyChain・整合・ラップ検査を permit 下で行う。genesis ハッシュ(project_id
座標)は DO 自身のチェーンから取る(session-09 §3 の不変条件を踏襲)。

### 3-5. CLI の CAS リトライ = 上限 5 回・ラップ再構築は差分時のみ

push の MAX_ATTEMPTS と同じ上限。再同期後に現メンバー集合(user_id → enc 鍵)が
不変ならラップ集合を再利用する(§12-4 の「ラップ集合は現メンバー集合が変わった
場合のみ作り直す」。HPKE Seal はランダムなので不要な再ラップは差分比較を壊す
だけでなく無駄)。DEK・コミットメントはリトライを跨いで不変(エントリの再署名
だけが変わる)。

### 3-6. fallow dupes ベースライン

session-11 で裁定済みのテスト支援クローン群(cli / server の buildChain・
op ビルダー等)は、本セッションの改修でフィンガープリントが変わりベースラインと
不一致になった(警告のみ・ゲートは通過)。共有抽出は session-11 §5 の裁定済み
独立 PR の領分なので本 PR では手を入れず、抽出 PR 側でベースラインごと解消する。

## 4. ハマったこと・環境知見

- **チェーンベクターの負例は「旧意味論なら受理された値」を選ぶと強くなる**:
  `authz-rotate-unknown-environment` の new_epoch は 2(旧「未観測 = 1 + 1」で
  受理された値)にした。既定値フォールバックを残した実装はこの 1 本で落ちる
- **複合エンドポイント化はテストの前提を広く壊す**: 汎用 append の拒否
  (CompositeRequired)が入ると、membership テストの「ベクター再生」「CAS」
  「サイズ上限」「write/admin スコープ判別」など rotate をダシに使っていた
  テストが全部影響を受ける。rotate/create を使わない op(remove_member)への
  差し替えと、複合経由の再生ヘルパ(op を追いながらメンバー集合を導出して
  ラップ完全集合を作る)で吸収した
- **サーバー受理面では合意規則の理由コードがそのまま出ないケースがある**:
  role 不足は DO の requireRole(403)が verifyChain(422)より先、未作成環境は
  データ行の 404 が先、コミットメント形式違反は api-schema の hex Schema
  (400)が先。membership.test.ts に「ベクター名 → サーバー期待(status +
  理由)」の対応表を置いて、この写像自体をテストとして固定した
- **テストフィクスチャのコミットメントは実計算が必須**: CLI の pull テストは
  §5.2 照合まで走るため、チェーンに載せるコミットメントはフィクスチャの実 DEK
  から計算しないと全テストが毒ラップ扱いで落ちる。コミットメント原像は
  project_id(= genesis ハッシュ)を含むため、buildChain に「genesis 確定後に
  payload を作る」遅延 op(LazyChainOperation)を導入した
- **`bun run check` の oxfmt は生成 JSON も対象**: 生成ツールの出力に oxfmt を
  かけると既存ベクターは byte-identical(session-10 §3 の知見の再確認)

## 5. 既知の制約・v1 許容

- ローテーションの CLI コマンドは未実装(スコープ外 — チェーン追記系コマンド
  一式と同時に将来実装)。rotate 複合はサーバー実装 + テストで検証済み
- `EnvironmentMetaStatement` 不在の中間状態(§2)。環境の表示名の真正性は PR-3 まで
  従来どおり非認証
- 非 NFC 名の 422(§8-5)は PR-3(ステートメント受理と同時)
- CLI のローカル床(§6.3 SHOULD)は PR-4(要裁定 §10-4)のまま未実装 —
  コミットメント照合は「提示されたチェーンビュー内」で完結する保証(§14.2-1)
  であり、ビュー自体の巻き戻しは引き続き床・ゴシップの領分
- server の複合受理で「データ行はあるがチェーンに環境がない」状態は不変条件
  違反として defect(currentEpochOf の throw)。旧 API で作られた行は存在しない
  (公開前・適用済み環境なし)前提

## 6. 申し送り

- **PR-2(値署名)**: value-signature.json は再生成後の正規チェーン(12 エントリ)
  を参照して作る。`ChainState.environments` の epochStartSeqs が §6.3-4
  (エポック整合・create 前ヘッドの拒否)の入力になる。既存
  dek-wrap-signature.json の description の signer_user_id 欠落もそのとき直す
  (session-12 §13)
- **PR-3(メタデータステートメント)**: 複合作成への EnvironmentMetaStatement
  同梱(CAS 再試行の両方再署名)、`env.created` への author FP、非 NFC 422、
  環境一覧の name → ステートメント置換(EnvironmentSummary 改訂)
- **テスト支援の共有抽出(session-11 §5 の裁定済み独立 PR)**: 本セッションで
  クローン群がさらに近づいた(commitmentOf / createEnvironmentOp 系も両側に
  生えた)。抽出時に fallow dupes ベースラインの不一致警告(§3-6)も解消する
- session-11 §5 の残り(公開設定エンドポイント / pull メタデータのみモード)・
  チェーン追記系コマンド + remove_member の全環境 rotate(session-12 §10-7 の
  複合化検討込み)は未着手のまま有効

## 7. レビュー→修正ループ(PR #28 内。3 観点の並行レビュー → 修正)

### ループ 1 の指摘と対応

3 観点(セキュリティ・暗号 / 正しさ・並行性 / テスト・ベクター・ワイヤ契約)を
並行実行。**[高] 1(契約)= [中](正しさ)の同根**:

1. **複合 create のエントリ内 environment_id から §12-1 の受理ポリシー形式が
   消えた(契約 [高]・正しさ [中] が独立検出)**: 旧 create ペイロードの
   `EnvironmentIdSchema` が、複合化で ID の運搬がチェーンエントリ内へ移った際に
   `Schema.String` へ落ちていた(URL 座標も持たない)。write スコープの
   メンバーが `"my env/💥"` のような ID の環境を原子コミットでき、URL param を
   持つ後続エンドポイント(rotate / rename / **remove** / pull)から到達不能 =
   **ローテーション不能(§7 の全環境義務と衝突)・削除不能・quota 恒久消費・
   ID 永久焼却**の環境が作れた。→ `CreateEnvironmentEntrySchema` /
   `RotateEpochEntrySchema` の environmentId を `EnvironmentIdSchema` に(ワイヤ
   受理ポリシー層で拒否。合意規則 = §6.1 bounded string には昇格させない —
   project.ts の線引きを維持)。不正形式 3 種の複合 create 400 negative を追加。
   既存チェーンへの波及なし(2 op の受理点は複合のみ + 公開前・適用済み
   チェーンなし。悪意サーバーが非適合 ID を配布した場合は CLI の decode が
   fail-closed になる — 修正前より厳密に良い)
2. **汎用 append の 2 op 拒否が worker 単層(セキュリティ [低]・正しさ [低] が
   同根を検出)**: DO の `appendProgram` は合意規則上有効な create / rotate を
   受理でき、将来の呼び出し経路追加で「チェーンに環境はあるがラップ・環境行が
   ない」中間状態が作れた。→ DO 側にも同じガード(`composite-required`
   outcome → `CompositeRequiredError` 写像)を追加(多層防御)。リクエスト
   内容のみに依存する判定のため §11-2 の存在秘匿とも両立(§12-3 1a と同型)
3. **テスト [中]〜[低]**: 監査ミラーの dek_commitment が形式(64 hex)しか
   固定されていなかった → フィクスチャの実 DEK からの §5.2 実計算値と
   `toEqual` で完全一致に強化 / kind なし negative の検査が名前ハードコードで
   ベクター再生成の追加分を黙って落とす → 網羅ガード(未検査 name で fail)を
   追加 / CLI の CAS リトライの「メンバー集合不変ならラップ集合を再利用」の
   再利用側が未検査(常時再構築の実装が通った)→ deks 完全一致 + prev 更新の
   テストを追加
4. **[情報] 群**: 古いコメント(seq 1〜9 等)の更新、README への
   invalid-payload 系 negative の kind 運搬注記、ファントム環境エラーの文言
   (良性レースの再実行案内)、env-create 最終試行の設計コメント
   (push.ts と同じ判断の明記)

### ループ 2(修正の再検証)

3 観点とも**ループ 1 指摘への修正は十分・新規ブロッキング指摘ゼロ**を確認:

- セキュリティ = チェーンエントリの挿入点(`insertSync` 呼び出し元)の全数
  確認で 2 op の迂回経路が worker・DO 両層で不能なこと、`EnvironmentIdSchema`
  強制が snapshot 配布・CLI decode と矛盾しない(非適合 ID がチェーンに載る
  経路が構造的にない)ことまで検証
- 正しさ = 不正 ID 3 種の再現スクリプトで修正後スキーマの拒否を再実行確認。
  DO ガードの判定順(op のみ依存 = 存在情報を運ばない)の整理を妥当と判定
- テスト = 新テスト 3 本の変異検出力(`Schema.String` 退行 / 定数写し /
  常時再ラップがそれぞれ確実に落ちる)をトレースで確認
- 新規 [情報] 1 件(negative の kind 語彙に第三の値が導入されると両ふるいから
  漏れる)→ kind 語彙(undefined | "authorization")の固定チェックを追加して対応

### ループ 3(最終確認)

ループ 2 の 3 観点がそれぞれ「修正十分・新規指摘ゼロ」を明言し、残余はすべて
[情報](非定時間ハッシュ比較 = 公開値のみ / ワイヤ形式が合意規則より狭い
非対称 = コメントで文書化済み / チェーンビュー巻き戻し残余 = PR-4 の床・
§14.2-1 の保証範囲どおり)。品質ゲート: `bun run check` 540 tests green +
crypto 4 実行環境(node 243 / workerd / browser / bun)green。
経過: ループ 1 = 高 1(2 観点同根)・中 2・低 3・情報多数 → ループ 2 =
情報 1 → 指摘ゼロ(ブロッキング)。
