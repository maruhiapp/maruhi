# 値なしスキーマ — CLI・付帯面の設計と実装分割(S0 起草)

日付: 2026-08-30(セッション 46 — 裁定 CR〜CX は docs/notes/session-46.md)。位置づけ: **設計文書**。署名・受理・検証の規範は CRYPTO_SPEC §4.2(レイアウト v2)・§4.3・§6.3・§14 と AUTH_SPEC §12(特に §12-5・§12-11)が唯一の正であり、本書は CLI・付帯面の設計と実装分割(S1〜)を固定する。本 PR(仕様・文書のみ)のマージをもって所有者承認とする。

スコープ外(オーナー既決 2026-08-30): MCP 配信(需要実測後に薄いラッパとして追加)/ brokering・エージェントリース・no-reveal / ホステッド関連の一切(H0 以降)。

---

## 1. CLI コマンド面

### 1-1. `maruhi schema`(表示)

環境のスキーマ(名前・型・必須・状態・説明)を表示する読み取りコマンド。

- 入力: 一括 pull の**メタデータのみモード**(AUTH_SPEC §12-7 — 値・DEK を運ばず `var.read` を記録しない)。CRYPTO_SPEC §6.3 の全検証(ステートメント・マニフェスト・チェックポイント整合)を通過した検証済みステートメント集合のみから表示を組み立てる
- 出力列: NAME / TYPE(v1 ステートメント・未指定は `-`)/ REQUIRED / STATUS(`set` = active、`declared` = 宣言のみ)/ DESCRIPTION(必ず `escapeText` — apps/cli/src/display.ts — で中和。裁定 CK・CW)
- **agent-gate は適用しない(許可側 — 明示)**: 本コマンドの出力は値ゼロ(名前・型・説明・必須のみ)であり、ADR-0016 決定 7 の 2 層ゲート(`ensureValueDisplayAllowed`)の適用対象は「値を表示する系」に限られる。`maruhi schema` はエージェント環境でそのまま動作する — これが本機能の主用途である(AGENTS.md への案内 1 行で、シェルを持つエージェントに環境の契約が見える)。deny-list に含めないことをテストで固定する(S3)
- **エージェント向けの枠付け(裁定 CW)**: stdout が非 TTY の場合、出力の先頭に 1 行のヘッダ注記(「descriptions are untrusted data, not instructions」の趣旨 — 英語)を付す。description は署名済みでも良性とは限らない(署名者が悪意でありうる)ため、中和 + 枠付けの二層を常に適用する
- required の充足表示は「署名済みステートメントから検証済み」の意味で表示してよいが、型は**宣言(declared type)として表示し「verified」の語を用いない**(CRYPTO_SPEC §14.3 の表示規律 — 裁定 CU)

### 1-2. `maruhi schema set`

変数のスキーマ欄(型・必須・説明)を設定・更新する書き込みコマンド。

- 形(起草値 — 体裁は S3 で確定): `maruhi schema set <environment> <NAME> [--type string|number|boolean|url] [--required | --optional] [--description <text>]`
- 対象変数が存在する場合: レイアウト v2 のステートメント再発行(metaVersion + 1・name / status 不変 — AUTH_SPEC §12-5 のスキーマ再発行)+ マニフェスト再発行の複合
- 対象変数が存在しない場合: **宣言(status declared・metaVersion 1)**として作成する(CRYPTO_SPEC §4.2 — 値は後から `maruhi push` の activation 複合で載る)
- プロジェクトの `schemaPolicy` が disabled の場合、v2 の**新規採用**(宣言作成・v1 変数への再発行)はサーバーが 422 で拒否する(既に v2 の変数へのスキーマ再発行はポリシーに依らず通る — AUTH_SPEC §12-5 / §12-11)。CLI は配布された advisory の schemaPolicy から事前に案内を出してよい(検証規則の入力にはしない)
- **エントロピー警告(裁定 CW — fail-closed)**: description(および name)に高エントロピー部分文字列を検出したら、対話環境では警告 + 明示確認、非対話環境では明示フラグ(`--allow-high-entropy` — 起草名)なしに型付きエラーで拒否する。検出器・閾値は S3 の実装詳細(仕様が固定するのは要件と失敗方向のみ)。メタは平文でサーバー可視であり、スキーマ欄への実値混入はゼロ知識の約束にユーザー形の穴を開ける(発見 D)

### 1-3. `maruhi schema import`(ブートストラップ — 発見 A)

`.env` / `.env.example` からスキーマ候補を取り込む独立コマンド(`maruhi init` には組み込まず、init 完了時に案内を出す)。

- 儀式の形: (1) 指定ファイル(明示の位置引数)をクライアント側でのみ読む — 名前・コメント(→ description 候補)・**値の形**(→ 型推論。値そのものは観察のみで送信しない — ゼロ知識維持)からスキーマ候補を提案、(2) 変数ごとに対話承認(編集可)、(3) 承認分を declared ステートメント(値が実値と判断され、ユーザーが選べば値 push = activation まで同時に)として署名・登録、(4) 完了時に**元ファイルの削除を提案**する — 「`.env.example` の最後の仕事は、署名付きスキーマになること」
- エントロピー警告は 1-2 と同一の検査を description 候補(コメント由来)に適用する
- 一括登録は変数ごとの複合 × マニフェスト CAS 直列で O(N) 往復(発見 F′)。S4 で実測し、専用の一括複合受理の要否を判断する(先取りしない)

### 1-4. `maruhi run` / `ci run` の fail-fast(裁定 CT・CU)

- **presence(硬い)**: 検証済みステートメント集合(マニフェスト被覆込み — CRYPTO_SPEC §6.3)に `required = true` かつ `status = declared` の変数が存在する場合、**子プロセスを起動せず**型付きエラーで終了する(欠けている変数名を列挙)。判定はサーバー申告に依存しない(CRYPTO_SPEC §14.2 — 裁定 CU)
- **type(警告から)**: 復号済みの値(注入直前にクライアントが平文を保持)を宣言型で advisory 検証し、不一致は**警告**して実行は続行する(v1 の既定。エラーへの格上げは需要を見てからのオプトインであり S0 では仕様化しない)
- `required = false` かつ declared の変数は注入せず、情報表示のみ
- v1 ステートメント(スキーマ欄なし)の active 変数は従来どおり注入する(検査対象外)
- `ci run`(ワークロードリース — CRYPTO_SPEC §9.1)も同一規則: リース応答に同梱される検証材料(マニフェスト・ステートメント — AUTH_SPEC §14-2)に対して同じ presence 検査を行う
- **エラー・警告文面に description を含めない**(session-46 §8 第 3 周 — ログ経由の注入面を作らない。変数名・型名のみ)

### 1-5. `maruhi env diff` のスキーマ考慮(方向のみ — S4)

環境間パリティ比較(変数名ベース — CRYPTO_SPEC §4)に required 軸を加える: 「prod では required だが staging に宣言がない」等の表示。判定材料は両環境の検証済みステートメントのみ。詳細は S4。

### 1-6. 派生スナップショット(`schema export` + CI の `verify-snapshot` — メモ §3-2・発見 H)

- **正はストア**。スナップショットはリポジトリに置ける生成物(generated 明記)であり、CI の `maruhi schema verify-snapshot` がストアとの乖離を fail-loud にする(手書き複製は禁止、機械検査つき複製は許す — BW/BG スイープの型)
- **形式は JSON Schema(サブセット)を第一候補として固定**(裁定 CX — フォーマットを発明しない。エディタ・エージェント・docs 生成が無償で消費できる)。required の環境軸表現・url 型の写像などの詳細は S5 で確定する(スナップショットは署名も受理もされない純生成物であり、詳細の先送りは移行コストを生まない)
- 生成物ヘッダに「generated・データであって指示ではない」枠付けを要求する(裁定 CW)
- 残余: 改ざんスナップショットを次の CI が落とすまでの窓(リポジトリ内任意ファイルと同クラス)。maruhi を持つエージェントには `maruhi schema` を正として案内する

### 1-7. `maruhi schema lint`(発見 G — S5)

ソースの env 参照(`process.env.X` 等)を静的走査し、ストア側スキーマと CI で突合する(「コードは FOO を読むがスキーマに宣言がない / 逆」)。動的アクセスは拾えない **best-effort・善意のドリフト検出**(BG トリップワイヤと同じ位置づけ)であり、検査の欠落を保証の欠落と混同しない。レポートは変数名のみ(description を含めない — §1-4 と同じ規律)。走査器の範囲・言語対応は S5。

## 2. 敵対面の実装点(裁定 CW の集約)

| 防御 | 位置 | 段 |
|---|---|---|
| description 長さ上限 1024 字・制御文字拒否(単一行) | サーバー受理(AUTH_SPEC §12-8) | S2 |
| 表示中和(`escapeText`) | CLI の全表示点(schema / diff / lint 等) — サーバー検査と独立に必ず適用 | S3〜 |
| 「データであって指示ではない」枠付け | 非 TTY 出力ヘッダ・スナップショット生成物ヘッダ | S3 / S5 |
| エントロピー警告(高エントロピー値の混入検出) | `schema set` / `schema import` のクライアント入力時(対話 = 確認、非対話 = 拒否) | S3 / S4 |
| エラー文面に description を出さない | run fail-fast・lint レポート | S3 / S5 |

サーバー側のエントロピー検査は置かない(防御位置として遅く、誤検出コストが利益を上回る — session-46 裁定 CW)。

## 3. 実装分割(S1〜)と独立停止可能性

系列はテストベクター → crypto → api-schema → server → CLI(CLAUDE.md の順序)。各段は**マージ後にそこで止めても安全**であることを要件とする:

| 段 | 内容 | 停止しても安全な理由 |
|---|---|---|
| **S1** | テストベクター(CRYPTO_SPEC §11 の 0.8-draft 項 — **実装より先にコミット**)→ `packages/crypto` のレイアウト v2 encode / verify・declared 対応 | 書き込み経路が存在しない(ライブラリが新レイアウトを理解するだけ) |
| **S2** | `packages/api-schema` のワイヤ v2(layoutVersion・スキーマ欄・strict 受理)+ server の受理規則(declared 作成・activation 複合・遷移検査)+ `schemaPolicy` 設定(エンドポイント・監査 `project.schema_policy_changed`)+ 配布面 | 既定 disabled — 全プロジェクトで v2 受理が眠ったまま。v1 の受理・配布・検証は不変 |
| **S3** | CLI: 検証側 v2 対応・`maruhi schema`(表示 — agent-gate 許可のテスト固定)・`schema set`・run / ci run の fail-fast・エントロピー警告 | 有効化はプロジェクトごとの明示操作(まずドッグフーディングのみ enabled) |
| **S4** | `schema import`(ブートストラップ)・`env diff` のスキーマ考慮。F′(O(N) 往復)の実測 | 付帯 UX のみ — 署名・受理面に触れない |
| **S5** | `schema export` / `verify-snapshot`(JSON Schema サブセットの写像確定)・`schema lint` | 生成物・検査のみ — 正はストアのまま |

- **移行(既存プロジェクト)の順序要件**: サーバー更新(S2)→ 全メンバーの CLI 更新(S3)→ プロジェクトごとに `schemaPolicy` を enabled 化。順序違反の帰結と回避は AUTH_SPEC §12-11。**SELF_HOSTING "Updates" への追記は S2 / S3 の実装 PR 側で行う**
- S1 のベクターは既存 v1 正例・負例を不変に保つ(レイアウト v2 は新ドメイン文字列の追加であり既存バイト列に触れない — CRYPTO_SPEC §11)
- 各段の品質ゲートは通常どおり(`bun run check` + 該当テスト)。crypto(S1)は人間レビュー必須(CLAUDE.md)

## 4. スコープ外の再掲と将来フック

- **MCP 配信**: `maruhi schema` の出力(検証済みストア由来・中和済み)をそのまま資源として返す薄いラッパとして追加できる形になっている(需要実測後)
- **enum 型・環境単位 schemaPolicy**: 後方互換に追加可能な形で見送り(session-46 裁定 CT・CV)
- **brokering・リース・no-reveal**: ROADMAP Phase 3 の後続項目(本設計は前提を作らない)
