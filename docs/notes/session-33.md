# セッション 33 メモ(PR-F3 実装 — 2-G′ 境界チェックポイントの前倒し)

日付: 2026-08-27。対象: session-31 §6 の PR-F3(M1-A6 / M1-B1 / M1-T2 の
PR-F3 割当分)。裁定 2 は所有者承認済みの案 2-G′(session-32 §5-1)で、
仕様改訂(CRYPTO_SPEC §4.3 / §6.2〜§6.4、AUTH_SPEC §12-4 / §16-2)は
PR #83 系でマージ済み = 承認済み。本ノートは実装 PR(F3a / F3b)の
実装裁定の記録。裁定プロセスは goal の指示どおり「複数案 → 上位互換探索 →
3 周の比較 → 自律選択」で行い、各周の棄却理由を記録する。

分割(session-32 §5-1 の有界化をそのまま採用):

- **F3a** = `checkpoint` op の合意規則(CRYPTO_SPEC §6.2)の実装 +
  `packages/crypto` のテストベクター(chain-entries.json への加法のみ)+
  env values digest の正規形実装。純粋な M2 前倒しで、既存動作の変更なし
- **F3b** = create / rotate 複合への境界 checkpoint 原子同梱(AUTH_SPEC
  §12-4)、チェックポイント束縛によるマニフェスト検証(CRYPTO_SPEC §4.3
  検証規則 (2) — 旧 H+1 例外の廃止)、§6.4 受理検証(内容突合・スナップ
  ショット原子保存)、M1-B1 の修正、SELF_HOSTING.md の更新順序追記。
  F3a のブランチを base にした stacked PR

スコープ境界(goal / session-32 §5-1): checkpoint の受理・スナップショット
保存まで。スナップショットの配布とクライアント側の整合規則 2 の検証は
M2 本体に残す。

## 1. 裁定 A: チェックポイント束縛の照合材料をどこで引くか(F3a の API 形状)

CRYPTO_SPEC §4.3 検証規則 (2) は「検証済みチェーン上に当該 (environment_id,
manifest_version) のタプルを含む `checkpoint` エントリが存在する場合、その
(epoch, manifest_sig_hash) と完全一致しなければならない(strict は代替経路に
ならない)」。この「存在する場合」の判定を誰が行うか。

### 第 1 周

- **案 A-1: 明示入力(2-D の anchor と同型)** — `verifyDistributedEnvManifest`
  が省略可能な `checkpoint?: { epoch, manifestSigHashHex }` を受け取り、
  呼び出し側が検証済みチェーンから引いて渡す。利点: crypto コアの API が
  小さいまま、既存ベクターへの影響が最小。欠点: **呼び出し側が引き忘れると
  strict へフォールバックする** — 正当な複合マニフェストには fail-closed
  (可用性バグとして即顕在化)だが、**攻撃ケースでは fail-open**: タプルが
  チェーン上に存在するのに引かずに検証すると、同一 (env, mv) の別内容
  マニフェストが strict 経路で通り、session-32 §4-2 が選言形を潰した理由
  (「anchor が存在しても strict 経路が生きたままなら equivocation 優位が
  消える」)を呼び出し規約のバグとして再現する
- **案 A-2: 履歴索引の内部照会** — `ChainHistoryIndex` に
  (environment_id, manifest_version) → タプルの照会を追加し、検証器が常に
  参照する。MUST 形が構造的に強制され、呼び出し側の規約に依存しない。
  欠点: 既存の複合 positive ベクター(manifest-v1-create / manifest-rotate)は
  checkpoint を含まない正規チェーンに対して検証していたため、検証対象
  チェーンの差し替え(チェックポイントを含む派生チェーン)が要る

### 第 2 周(上位互換探索)

- **案 A-3: 両方(内部照会 + 明示入力の照合)** — 検証器が内部照会し、
  呼び出し側も期待タプルを渡して二重照合する。棄却: 明示入力側に独立の
  意味がなく(内部照会が常に勝つ)、API 面だけが太る過剰工学
- **案 A-4: ChainState 側の導出値(環境ごとの最新チェックポイント)だけで
  賄う** — 規則 (2) は「当該 manifest_version のタプル」であり最新とは
  限らない(境界 checkpoint 後に周期 checkpoint が同一 mv を再公証する形、
  古い正当マニフェストの再検証)。最新だけでは (env, mv) 照合が
  表現できず棄却

### 第 3 周(再点検)

- A-2 の欠点(ベクター差し替え)はベクターの**再生成ではない**ことを確認:
  既存ベクターの署名バイト列・署名・ハッシュは一切変えず、検証の前提
  チェーンをチェックポイントを含む派生チェーン(chain-entries.json の
  extended_chains へ**追加**)に差し替えるのはテストハーネス(コード)の
  変更で、session-32 §4-2 の「加法のみ」制約(人間レビューが追加分だけを
  レビューできる)と両立する
- A-1 の fail-open は「既定が strict = 安全側」に見えるが、安全側なのは
  可用性方向だけで、完全一致 MUST の眼目(equivocation の遮断)が呼び出し
  規約に依存する点は消えない。PR-F1 裁定(1-E)が「協調的でなく構造的に」を
  原則化した流れとも整合しない

**選択: 案 A-2**(履歴索引の内部照会)。`ChainHistoryIndex` に
`checkpointTupleFor(environmentId, manifestVersion)` を追加し、検証器が
常に照会する。引き忘れという失敗モード自体を型から消す。

## 2. 裁定 B: 同一 (environment_id, manifest_version) タプルの equivocation 判定の同一性基準

§4.3 (2) は「同一 (environment_id, manifest_version) に**異なる
manifest_sig_hash** のタプルが併存する場合はマニフェスト equivocation の
硬い証拠として拒否・警告」。タプルは (epoch, manifest_sig_hash,
values_digest) を運ぶ — どのフィールドの相違を equivocation とするか。

### 第 1 周

- **案 B-1: manifest_sig_hash の相違のみ**(仕様文言の最小読み)
- **案 B-2: (epoch, manifest_sig_hash) の相違** — epoch はマニフェストの
  署名バイト列に焼き込まれているため、hash 一致 × epoch 相違のタプル対は
  「どちらかの checkpoint がマニフェスト内容と矛盾する epoch を公証した」
  ことの証拠であり、hash 相違と同じクラス
- **案 B-3: 全フィールド(values_digest 含む)の相違**

### 第 2 周(上位互換探索)

案 B-3 は**正当なフローを equivocation と誤判定する**ことが判明し棄却:
rotate 境界 checkpoint(mv N、未再暗号化 = 旧エポック相当の現在値の
values_digest)の後、再暗号化完了後の周期 checkpoint が同じ mv N
(値 push はマニフェスト版を進めない — §4.3 発行契機)を新しい
values_digest で公証するのは仕様が想定する正規の連なり(§6.3 発行
SHOULD (i))。values_digest は同一 (env, mv) でも正当に変わる。

### 第 3 周(再点検)

- B-1 と B-2 の差が出るのは「hash 同一・epoch 相違」の対のみ。これは
  チェーン合意規則(checkpoint のエポック厳密一致)を通った 2 エントリで
  ありうる(mv 非後退は等号を許すため、rotate を挟んだ同一 mv の再公証
  — ただしその場合マニフェスト再発行が挟まるので正当なフローでは mv も
  進む)。正当なフローでは発生せず、発生したら不整合の証拠。B-1 を採ると
  この対では「どちらのタプルと完全一致すべきか」が非決定になる
- 完全一致検査は (epoch, manifest_sig_hash) の両方に対して行う(仕様の
  「(epoch, manifest_sig_hash_hex) と完全一致」)ので、照合の一意性の
  ためにも B-2 が一貫する

**選択: 案 B-2**。照会は (env, mv) → 一意な (epoch, manifest_sig_hash) か、
相違する対を観測した時点で「conflicting」を返し、検証器は conflicting を
`checkpoint-equivocation` として拒否する。values_digest は equivocation
判定に含めない(値側の基準は最新チェックポイント + サーバー保存
スナップショット — M2 の規則 2 の領分)。

## 3. 裁定 C: checkpoint 合意規則の複数環境エントリ間の理由コード優先順

§6.2 の検査順序「role → 監査 admin → unknown-environment →
checkpoint-epoch-mismatch → checkpoint-regression」は単一環境エントリでは
一意だが、複数エントリが別種の違反を持つ場合(例: エントリ 1 が epoch
不一致・エントリ 2 が未知環境)の優先が未固定。

- **案 C-1: リスト順に per-entry で全検査**(エントリ 1 の epoch-mismatch が
  先に出る)
- **案 C-2: 検査段ごとに全エントリを走査(stage-wise)**(unknown-environment
  が先に出る)
- 第 2 周: 上位互換として「reason に environment_id を添える」を検討 —
  ChainInvalid の形(seq + reason)を変える改訂で、既存エラー面の拡張に
  なるため PR-F3 では採らない(将来の DX 改善として独立提案可)
- 第 3 周: 仕様の検査順序の文言は「認可段の検査順序」としてコード種別の
  順を並べており、C-2 が文言の自然な読み(rotate の
  unknown-precedes-epoch と同じ「理由コード種別の順」)。C-1 は実装順の
  偶然をベクター化することになり、他実装(サーバー / 将来の別言語実装)が
  同じループ構造を強制される割に得るものがない

**選択: 案 C-2**(stage-wise)。ベクター
`authz-checkpoint-unknown-precedes-epoch`(エントリ順と逆の優先)で固定する。

## 4. F3a の実装内容(要約)

- `packages/crypto`: `checkpoint` op の型・正規化(payload =
  `LP(environments_lp_hex, audit_head_hash_hex)`、環境エントリ =
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
  values_digest_hex)` の入れ子 LP)・合意規則(§6.2 — 構造検査に重複
  environment_id 拒否を含む / role member+ / 非空監査ヘッドは admin /
  unknown-environment / エントリ時点(自エントリ適用前)エポック厳密一致 /
  同一環境の先行 checkpoint に対する manifest_version 非後退)・導出状態
  (環境ごとの最新チェックポイント)・履歴索引の (env, mv) タプル照会
  (裁定 A / B)・`computeEnvValuesDigest`(§6.2 の values_digest 正規形)
- 新しい理由コード: `checkpoint-audit-role-insufficient` /
  `checkpoint-epoch-mismatch` / `checkpoint-regression`(重複 environment_id
  は仕様どおり payload 構造検査 = `invalid-payload`)
- chain-entries.json: **追加のみ**(canonicalization への checkpoint
  記述・valid_appends 2 件・extended_chains `checkpoint-baseline`・
  negative 15 件・values_digests セクション)。既存 12 エントリ・
  expected_head_states・既存 negative は 1 バイトも変えない(git diff で
  確認)。生成は既存の独立参照生成器(generate_reference.py)の拡張で行い、
  既存出力のバイト一致再現を前提に追加分だけを diff に出す
- `checkpoint-baseline` 派生チェーンの manifest_sig_hash はダミー値
  (チェーン合意規則は内容を検証しない — §6.2 の「形式は合意規則、内容は
  照合側」)。実マニフェストハッシュと結線した境界チェックポイントの
  派生チェーンは F3b(マニフェスト検証規則の consumer と同じ PR)で追加する

## 4-1. F3a の波及(crypto 外に触れた最小面)

`ChainOp` / `ChainState` / `ChainInvalidReason` の拡張はリポジトリ全体の
型検査で次の追随を強制した(いずれも F3a の合意規則実装の直接の帰結で、
新しい挙動は「fail-closed の拒否」のみ):

- `packages/api-schema`: エラー語彙(`CHAIN_INVALID_REASONS`)への 3 理由
  追加(逆方向静的検査 `AllReasonsListed` が強制)。ワイヤの
  `ChainEntrySchema` union へ `checkpoint` を追加(チェーン配布応答の型が
  crypto の `ChainEntry` を運ぶため、union に無いと配布ハンドラが
  型エラーになる)。`CompositeRequiredError` の op リテラルへ `checkpoint`
  を追加
- `apps/server`: 汎用 append(worker + DO の多層)で `checkpoint` op を
  `CompositeRequired` で拒否する。**§16-2 の受理検証(受理時点状態との
  内容突合 + スナップショット原子保存)なしで standalone checkpoint を
  受理すると、偽タプルの持ち込みで §4.3 (2) のチェックポイント束縛を
  汚染できる fail-open になる**ため、受理経路が実装されるまで(境界分 =
  F3b の複合同梱、standalone = M2)は構造的に閉じる
- `packages/core`: チェーンミラー(AUDIT_SPEC §3.4)の網羅 Record へ
  `chain.checkpointed` を追加(公証ダイジェストを payload に写す。
  監査 seq は写さない — 仕様どおり)
- fallow の複雑度指摘への追随として、op ディスパッチ 3 箇所
  (applyOperation / recordHistory / テストの toOperation)を既存イディオム
  (PAYLOAD_SHAPES / mirrorTails と同じ網羅 Record 表引き)へ揃え、
  §4.3 variables_digest と §6.2 values_digest の共通骨格を
  `sorted-digest.ts` に 1 実装化した(正規形はベクターが固定 — 挙動不変)

## 5. F3b の実装裁定

(F3b 作業時に追記)
