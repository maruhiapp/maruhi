# セッション 35 メモ(PR-M2 実装 — standalone checkpoint 受理 / 監査ヘッド累積ハッシュ / CLI 周期発行)

日付: 2026-08-28。対象: session-27 §14 の PR-M2(= M2 本体)。前提: PR-F1(#87)・
F2(#88)・F3(#96 / #97)・F4(#98)は main へマージ済み。standalone checkpoint は
これまで CompositeRequired で fail-closed、境界 checkpoint の非空 audit_head_hash は
F-3 の暫定 fail-closed(payload-mismatch: checkpointAuditHead)だった。本 PR は
(1) 監査ヘッド累積ハッシュ(AUDIT_SPEC §5.1)+ `GET /projects/:projectId/audit-head`、
(2) standalone checkpoint の受理(AUTH_SPEC §16-2 / CRYPTO_SPEC §6.4)、(3) 境界
checkpoint の非空監査ヘッドの §16-2 化、(4) CLI の周期発行(契機 (i)(ii)(iii) +
session-25 §8 のアンカー更新提案)、(5) テストを実装する。裁定プロセスは goal の
指示どおり「複数案 → 上位互換探索 → 3 周の比較 → 自律選択」で行い、各周の棄却
理由を記録する。

## 1. 裁定 J: row_digest / h_n の正規実装をどこに置くか

### 第 1 周

- **案 J-a: apps/server 内に閉じる** — 利点: 監査ログは DO にしかなく、消費者は
  1 つ。欠点: M4(ヘッド公証の検証・gossip)と AUDIT_SPEC §6 の admin 照合
  CLI は同じ計算をクライアント側で再実装することが既定路線(§5.1 は「独立
  実装間で同一の h_n」を要件にする)。サーバー私有だと将来の CLI 実装が
  「サーバーのコードを読む」以外の固定物を持たない
- **案 J-b: packages/crypto に置き、テストベクターで固定** — LP / SHA-256 /
  タグ付きバイト列という既存プリミティブの合成のみ(独自プリミティブなし)。
  ベクター先行(先行コミット)+ 4 実行環境ハーネスという既存の検証規律に
  そのまま乗る
- **案 J-c: @maruhi/core に置く** — 棄却: core はドメイン型・Schema の置き場で
  暗号計算の検証規律(ベクター・4 環境)がない。§5.1 の計算は暗号仕様の一部

### 第 2 周(上位互換探索)

- **案 J-d: crypto に置き、さらに監査行の写像(SQL 行 → AuditHeadRow)まで
  共有化する** — 棄却: 列名・NULL 表現は DO SQLite の保存形で、crypto が
  ストレージ形を知る形は境界違反(Drizzle 型をサービス外に出さない規律と同種)。
  crypto の入力はドメイン形(AuditHeadRow)まで

### 第 3 周(再点検)

- ベクターの表現力を再点検: h_{n-1} と row_digest を LP に入れる際の表現
  (hex 文字列 or 生バイト)が §5.1 の記述だけでは一意でないことを確認 →
  ベクター(audit-head.json)が固定する値を作り、§5.1 に表現を明記する最小
  追記を行う(裁定 K の (1))。チェーンハッシュ(§6.2 の entry hash)が同じく
  lower_hex 文字列を LP フィールドとして連結する先例に合わせた
- 非 ASCII payload(㊙)・全 NULL 行・非 NULL 空文字列(0x01 + 空)対 NULL
  (0x00)の判別ケースをベクターに含め、タグ付きバイト列の要点を固定した

**選択: 案 J-b**。`packages/crypto/src/internal.package/audit-head.ts`
(`computeAuditRowDigest` / `computeAuditHeadHash`)+ `test-vectors/audit-head.json`
(加法のみ・先行コミット 4a73515)+ 4 実行環境ハーネス。

## 2. 裁定 K: h_n の維持形(同一トランザクション要件と async SHA-256 の衝突)

AUDIT_SPEC §5.1 は「監査行の追記と同一トランザクションで h_n を前進」と書くが、
WebCrypto の SHA-256 は async であり、DO の書き込み規律(単一同期ブロック =
同一タスクの原子コミット。チェーン挿入・ミラー追記・受理副作用がここで書かれる)
とは合成できない — ミラーイベントは同期ブロックの**中で**生成されるため、
その h_n を事前計算しておくこともできない。

### 第 1 周

- **案 K-a: 全書き込み経路を「先に行を確定 → await で h_n → 第 2 タスクで
  ヘッド書き込み」に再構成** — 棄却: 受理経路すべて(チェーン受理・データ
  プレーン・lease)の書き込みフェーズを 2 タスクに割る大改造で、第 1 と第 2 の
  間のクラッシュで「行はあるがヘッドがない」中間状態は結局生じる(= 遅延拡張と
  同じ回復を要する)。原子性の利得がない
- **案 K-b: node:crypto の同期 SHA-256(nodejs_compat)** — 棄却: 新 compat
  フラグの導入(セルフホスト配布物の wrangler.jsonc に波及)+ 「暗号
  プリミティブは WebCrypto と選定済み HPKE のみ」規則のグレー面。遅延拡張で
  足りるのに規則の例外を作る理由がない
- **案 K-c: 遅延実体化** — `audit_head_hashes(seq PK, head_hash_hex)` 派生列を
  持ち、**読む経路(GET /audit-head・checkpoint 受理)が読む前に必ず MAX(seq)
  まで伸ばす**。行本体は不変(append-only)なので h_n は seq の純関数であり、
  いつ計算しても同じ値になる — 観測等価

### 第 2 周(上位互換探索)

- **案 K-d: 追記ごとに eager に第 2 タスクで伸ばす(読み経路の拡張は保険)** —
  棄却: var.read などの読み取りミラーは高頻度パスで、毎読み取りに SHA-256
  連鎖の追い付きを課す。読む者(checkpoint 発行・監査照合)が稀なのに書く者
  全員が払う形は逆向き。遅延形はコストを受益者に置く

### 第 3 周(再点検)

- 部分失敗の不変条件を確認: チャンク(50 行)は seq 順に確定コミットされる
  ため、途中失敗しても列は**接頭辞連続**のまま — 次回の拡張が続きから再開する。
  seq の欠番は append-only ストレージの破損なので defect(500)にする
- 初期化マイグレーションが別物として不要になることを確認: 既存行に対する
  「最初の拡張」がそのまま初期化になる(空テーブル + 既存 N 行 → 全再計算)。
  SELF_HOSTING.md に初回アクセスの一括計算コストを明記
- 仕様との整合: §5.1 の「同一トランザクション」を「同一トランザクション
  **または**観測等価な遅延実体化(読む経路が先に伸ばす・部分失敗で接頭辞連続)」
  に改める最小追記を実施(goal が仕様の最小追加を事前承認、承認は PR レビュー)。
  併せて h_{n-1} / row_digest の LP 表現(lowercase-hex 文字列)を明記(裁定 J
  第 3 周)

**選択: 案 K-c**。`apps/server/src/audit-store.ts` の `ensureHeadCurrent`(permit
下・読む前拡張)+ do-schema.ts の派生テーブル。

## 3. 裁定 L: CLI の「実効権限 admin の事前判定」(403 を踏まない)

§16-2: 非空 audit_head_hash は実効権限 admin = min(トークンスコープ, チェーン role)。
CLI はチェーン role を検証済みビューから知れるが、スコープ半分を知る API がない。

### 第 1 周

- **案 L-a: 試しに送って 403 なら空で再送** — 棄却: goal が明示的に禁じる形
  (403 を踏まない)。監査ログ・レート制限に無駄な拒否を残す
- **案 L-b: GET /audit-head の応答可否で判定** — 棄却: audit-head 取得は CAS 親
  確定**後**に行う規律(先に取ると stale を自招する)なので、判定材料としては
  取得順が逆。また read 系 403 で書き込み権限を推定する間接性が脆い
- **案 L-c: /auth/me に tokenScopes を加法追加** — トークン主体は自分の
  スコープを応答で受け取る。セッション主体はフィールド不在 = 全権。判定は
  「チェーン role admin+ かつ scopePermissionFor === "admin"」の純関数

### 第 2 周(上位互換探索)

- **案 L-d: 専用 endpoint(GET /auth/effective-permission?project=)** — 棄却:
  実効権限の半分(チェーン role)はサーバーの申告を信じない領分(クライアントは
  検証済みチェーンから導く — §6.3)。サーバーが「実効権限」を答える API は
  検証境界を曖昧にする。スコープ半分だけを返す /auth/me 加法で足りる

### 第 3 周(再点検)

- 旧サーバー互換: tokenScopes 不在(旧サーバー応答)をどう読むか。不在 =
  「スコープ情報なし」であり全権と区別できないが、旧サーバーは standalone
  checkpoint 自体を受けない(CompositeRequired)ため、この曖昧さが観測される
  組み合わせはない。SELF_HOSTING.md にサーバー先行の更新順で明記
- optionalKey(欠落可能)での加法追加は既存クライアントの Schema 検査を壊さない
  ことを確認(api-schema の MeSchema)

**選択: 案 L-c**。

## 4. 裁定 M: 境界 checkpoint(rotate / create 同梱)で CLI は監査ヘッドを公証するか

### 第 1 周

- **案 M-a: 実効 admin なら境界分にも公証を載せる** — 利点: 公証済み接頭辞が
  rotate のたびに前進。欠点: 境界 checkpoint は複合の CAS リトライで再署名され、
  監査ヘッドは取得後にミラー追記等で進みうる — 公証が rotate 本体の受理を
  audit-head-stale / unknown で巻き込み、失効操作(rotate)の生存性を監査
  ヘッドの競合に結合する
- **案 M-b: 境界分は公証なし(空文字列)。公証は契機 (i) の周期分が担う** —
  rotate 完了後の周期 checkpoint(standalone)が同じ節目で公証を供給するため、
  公証済み接頭辞の前進頻度は M-a と同等。rotate の生存性は監査ヘッド競合から
  独立

### 第 2 周(上位互換探索)

- **案 M-c: 境界分に公証を載せ、422 時は空で再署名するフォールバック** — 棄却:
  複合の再試行ループに「公証あり→なし」の分岐を持ち込み、失敗時の再署名が
  2 種類になる。得られるものは M-b と同じ(最終的に公証は周期分が担う)のに
  複雑さだけ増える

### 第 3 周(再点検)

- サーバー側は仕様どおり非空を受理する(§16-2 は経路を区別しない)ことを確認 —
  受理規則は checkpoint-accept.ts の共有実装(ensureCheckpointAuditHead)で
  standalone と同一。CLI の方針(空)とサーバーの受理能力(非空も可)は独立で、
  他クライアントが非空を送る自由は保たれる。データ fixture 側は非空境界
  checkpoint を組めるよう署名ヘルパーに引数を加法追加し、受理経路をテストで固定

**選択: 案 M-b**。

## 5. 裁定 N: 契機 (i)(rotate + 再暗号化完了後)の周期 checkpoint のカバー範囲

### 第 1 周

- **案 N-a: 全環境カバー(§6.3 の SHOULD そのまま)** — 棄却: rotate は 1 環境の
  操作なのに、全環境の values_digest 構築のため**読んでいない環境の値取得**を
  強制する。§12-4 の境界 checkpoint が「当該環境 1 タプル」に限定したのと同じ
  監査規律(読み取りを増やさない)の論法。§7 の全環境 sweep では O(n²) の
  pull にもなる
- **案 N-b: 当該環境 1 タプル** — rotate が読んだもの(当該環境の全値)だけで
  構築できる。全環境カバーの SHOULD は契機 (ii)(明示コマンド)と (iii)
  (提案)が担う

### 第 2 周(上位互換探索)

- **案 N-c: 「検証済みビューに既にある環境」だけ広げてカバー** — 棄却: rotate
  時点のビューに他環境の値は通常なく(pull は環境単位)、実質 N-b と同じ集合に
  縮退する。「あるときだけ広い」非決定的なカバーはテストも運用予測も悪くする

### 第 3 周(再点検)

- 発行タイミングを「再暗号化の完全完了時のみ」(remaining === 0 かつ failure
  なし)に限ることを確認: 部分完了時は「完了後のデータ状態」が存在せず、公証
  すべき節目がない。SHOULD なので発行失敗は rotate の成功を覆さず警告で開示

**選択: 案 N-b**。

## 6. 裁定 O: checkpoint 発行への 3-F 意図規律(journal-before-send)の適用

rotate は「送信前に意図をジャーナル」(3-F)で中断復旧するが、checkpoint 発行に
同じ規律を課すか。

### 第 1 周

- **案 O-a: 意図ジャーナルを導入** — 棄却: checkpoint はローカル状態を前進させず
  (床更新もアンカー更新も別操作)、送信が「着地したか失われたか」のどちらでも
  無害(着地 = 公証が 1 本増える、喪失 = 何も変わらない。再実行は常に安全)。
  ジャーナルが守るべき「中断で失われる進行中状態」が存在しない。チェーン自体が
  永続記録
- **案 O-b: ジャーナルなし + §12-10(3) の受理後確認のみ** — 変異の効果は検証
  可能な配布(再同期チェーンに自分のエントリがあること)でのみ確認する。輸送
  失敗時は rotate 型のプローブではなく「着地したかどうか不明・再実行は安全」の
  正直なメッセージ

### 第 2 周(上位互換探索)

- **案 O-c: 送信後プローブ(rotate の appendRotation と同型)で着地確認まで
  自動化** — 棄却: rotate のプローブは「エポックが進んだのに再暗号化しない」
  中間状態を防ぐためにある。checkpoint に中間状態はなく、プローブ失敗時の分岐
  (再送するか)が equivocation でない二重発行(無害だが無駄)を生むだけ

### 第 3 周(再点検)

- §12-10(3) の確認は resync → `history.entryHashAt(seq) === computeChainEntryHash`
  で行い、サーバーの 2xx を信じない形をテストで固定(嘘つきサーバー → exit 1)

**選択: 案 O-b**。

## 7. 裁定 P: session-25 §8 のアンカー更新提案の接続点

### 第 1 周

- **案 P-a: 専用の検出ロジック(アンカー鮮度の独立判定)** — 棄却: アンカーの
  「古さ」の一次驱動はエポック前進(rotate)で、時刻ベースの独立判定は (iii) の
  checkpoint 提案と二重の鮮度概念を作る
- **案 P-b: rotate 成功後は無条件に案内、push 成功後は (iii) の staleness に
  連動** — rotate はエポック床を必ず無効化する(案内は常に正当)。push は
  データ状態だけを進めるので、7 日 staleness((iii))と同じ節目で束ねる

### 第 2 周(上位互換探索)

- **案 P-c: rotate 側も (iii) に統合し、提案を 1 経路にする** — 棄却: rotate
  直後はアンカーが**確実に**古い(エポックが進んだ)のに、7 日条件を待つ形に
  なる。確実性の異なる 2 つの契機を同じ閾値に押し込むと、確実な方の案内が遅れる

### 第 3 周(再点検)

- ノイズ面を確認: sweep(全環境 rotate)では環境ごとでなく 1 回だけ案内する
  (reportSweepOutcome で集約)。提案はすべて非失敗(案内のみ)で、コマンドの
  終了コードに影響しない

**選択: 案 P-b**。契機 (iii) の接続点は push / pull コマンドの成功後のみ
(`run` / `ci run` は値の注入が本分で、対話的案内を差し込まない)。admin の
staleness 基準は「最新の**公証あり**checkpoint」、それ以外は「最新の checkpoint」
(分けないと member の発行が admin の契機を潰し、公証済み接頭辞が前進しない)。

## 8. 裁定 Q: PR 分割

### 第 1 周〜第 3 周(要約)

- **案 Q-a: crypto 先行 PR + サーバー PR + CLI PR のスタック** — 棄却: 本
  セッションの開発ブランチは 1 本のみが指定されており(goal の絶対制約)、
  スタックの中間ブランチを push できない。crypto の「先行コミット」要件は
  同一 PR 内のコミット順(ベクター → 実装)で満たせる
- **案 Q-b: 単一 PR、レイヤー順のコミット列** — ベクター(4a73515)→ crypto
  実装 → api-schema / server → CLI → テスト・docs の順でレビュー可能性を保つ

**選択: 案 Q-b**。

## 9. 実装内容の要約

- **crypto**(人間レビュー必須): `audit-head.json` ベクター(加法のみ・先行
  コミット)+ `internal.package/audit-head.ts`(`AuditHeadRow` /
  `computeAuditRowDigest` / `computeAuditHeadHash`)+ 4 実行環境ハーネス
  チェック(checks/audit-head.ts)
- **api-schema**: `CheckpointMismatchReasonSchema`(5 値)、CompositeRequired の
  op を create_environment / rotate_epoch に縮小、`auditHead` endpoint、
  `MeSchema.tokenScopes`(optionalKey 加法)、membership append のエラー列に
  CheckpointStateMismatchError
- **server**: `audit_head_hashes` 派生テーブル(do-schema)+ 遅延拡張
  (audit-store `ensureHeadCurrent`)。`checkpoint-accept.ts` に standalone 受理
  (CAS → verifyChain → タプル別 受理時点突合 → 監査ヘッド存在・位置検査 →
  同期ブロックでスナップショット保存と原子コミット)。境界経路は
  `ensureCheckpointAuditHead` を共有し F-3 暫定 fail-closed を置換。
  `requiredPermissionForEntry`(checkpoint: 空 = write / 非空 = admin)で
  スコープ半分を worker 検査、role 半分は DO の requireRole(403)
- **audit-head-stale の床**: 直前 checkpoint の chain.checkpointed ミラー行の
  seq(公証有無を問わない)。最初の checkpoint では空虚に真 — AUDIT_SPEC §6 の
  admin 照合と同じ述語・基底
- **CLI**: `maruhi project checkpoint`(契機 (ii))/ rotate 完了後の契機 (i) /
  push・pull 成功後の (iii) 提案 + アンカー案内。監査ヘッドは CAS 親確定後に
  取得、422 は全再 pull で有界再試行(3 回)、枯渇後は直近 2 回の構築で不変の
  部分集合で 1 回だけ発行。ヘッド CAS 競合は再同期 + 再署名(5 回)。受理後は
  §12-10(3) の検証可能配布で確認
- **docs**: AUDIT_SPEC §5.1 の最小追記(hex 文字列 LP 表現・遅延実体化の許容 —
  承認は PR レビュー)、SELF_HOSTING.md にサーバー先行の更新順と初回遅延拡張の
  一括計算コスト

## 10. テストの固定点(要約)

- サーバー(vitest-pool-workers): 権限マトリクス (a)(b)(c)(d)(session-27
  §13-5)、5 種の 422 理由、**存在しない未来 manifest_version の公証拒否 +
  原子性**(session-33 §5 の負例 — ヘッド不変・ミラー不増・後続の正当な
  checkpoint 成功)、部分集合再発行でスナップショットの経路同一性(B 環境の
  行が byte 同一)、境界 checkpoint の非空公証(owner 200 / member 403)
- CLI(vitest + ローカル HTTP モック): タプル構築の検証済みビュー由来
  (サーバー申告値を署名しない)、公証の事前判定(member 0 回 / write スコープ
  0 回)、422 再試行と部分集合退避、契機 (i) の rotate 統合、(iii) 提案の
  admin / member 基準差、嘘つきサーバー(2xx だが未着地)で exit 1
