# セッション 36 メモ(PR-M3 実装 — 値スナップショット配布・検証 = チェックポイント整合のクライアント規則 2)

日付: 2026-08-28。対象: session-27 §14 の PR-M3。前提: PR-M1・PR-F1〜F4・
PR-M2(#99)はマージ済み。M2 により、サーバーは checkpoint 受理時(standalone /
境界の両経路)に「受理時点の値スナップショット列挙 + 対応 checkpoint seq / hash」を
環境ごとの最新包含 checkpoint として原子保存済み(data-store.ts の
upsertCheckpointSnapshot / checkpointValueEntries)。本 PR は (1) api-schema の
応答同梱(加法)、(2) サーバーの保存済み列挙の配布(値付き pull §12-7 / lease
§14-2)、(3) クライアント規則 2(CRYPTO_SPEC §6.3 チェックポイント整合 2 — 値の
非後退)の検証(一括 pull と lease の両経路)、(4) テスト、を実装する。裁定
プロセスは goal の指示どおり「複数案 → 上位互換探索 → 3 周の比較 → 自律選択」。
裁定記号は session-35(J〜Q)の続番(R〜W)。

## 1. 裁定 R: 規則 2 検証の実装の置き場

### 第 1 周

- **案 R-a: packages/crypto の共有検証関数**(manifest-verify.ts の規則 1 =
  checkpoint-regressed の先例に倣う)— 利点: 「検証機構を二重実装しない」原則の
  形式的な継続。欠点: 規則 2 にはサーバー側の消費者が存在しない(受理時の
  values_digest 突合 — checkpoint-accept.ts — は別規則・別入力で実装済み。規則 2 は
  配布**受信**側の検査)。規則 1 が crypto にあるのは、マニフェスト検証という
  サーバー / CLI 共有の関数に**付随**するからであり、独立規則の置き場の先例では
  ない。また crypto 変更はベクター先行 + 4 実行環境ハーネス + 人間レビューを要する
  が、規則 2 の本体(基準との比較群)はベクターで固定できる正規形を含まない
  (session-27 §13-5 が「スナップショット同梱検証」を実装テストに分類済み。
  正規形 = values_digest の LP は computeEnvValuesDigest として固定済み)
- **案 R-b: CLI 層の合成(新モジュール、values.ts の共通検証骨格へ接続)** —
  一括 pull と lease は既に同一の検証骨格(values.ts の verifyAll —
  verifyLeaseDistribution も同関数)を通るため、CLI 層 1 実装で「両経路に同一
  規則」(§6.3)が構造的に満たされる。床規則 (a)(b)(c) が floor-check.ts に
  ある先例(クライアント専用の検証規則は CLI 層)と整合。digest の正規計算は
  crypto の公開 API(computeEnvValuesDigest — ベクター固定済み)を呼ぶだけで、
  新しい暗号操作は発生しない

### 第 2 周(上位互換探索)

- **案 R-c: crypto に「比較のみ」の純関数を置き、CLI が材料を渡す** — 棄却:
  入力(検証済み配布値・検証済み tombstone)は CLI 層の型であり、crypto に
  渡すには域型の写しを作ることになる(dead な二重型)。ベクターの裏付けがない
  ロジックを人間レビュー必須パッケージへ足す割に、得るものは「置き場のラベル」
  だけ。Web ダッシュボードの値付き pull が実装される時点で共有の必要が実在化
  したら、その PR で crypto へ昇格させればよい(再検討トリガーとして記録)

### 第 3 周(再点検)

- lease 経路の非対称(future head = 即時拒否・床なし)が共通実装と両立するかを
  再点検: 規則 2 の判定は「future(自チェーンが古いだけの可能性)/ rejected」の
  既存 2 分類(裁定 S)に乗り、lease 側は verifyLeaseDistribution が future を
  既に拒否へ写像している — 分岐の追加なしに両経路の意味論(pull = 有界再同期、
  lease = 自己矛盾として拒否)が出る
- 検査順序を固定: 環境ステートメント → 値 / ステートメント → tombstone → 名前 →
  マニフェスト(規則 1 込み)→ **規則 2**。規則 2 の「tombstone で説明される
  消失」判定はマニフェスト整合済みの tombstone 集合(ダイジェスト再計算が
  tombstone 隠しを拒否済み)を前提にするため、マニフェスト段より後に置く
  (§6.3 の「検証済み tombstone(マニフェスト整合込み)」の実装形)

**選択: 案 R-b**。`apps/cli/src/checkpoint-integrity.ts`(単一実装)を values.ts の
verifyAll(値付き経路のみ — metadata-only は §12-7 のとおり対象外)へ接続する。

## 2. 裁定 S: ワイヤへの対応 checkpoint seq / hash の同梱

§12-7 の文言は「列挙(variable_id / version / value_signed_bytes ハッシュ)」のみ、
保存規律(§16-2 / §6.4)は「列挙 + 対応 checkpoint seq / hash」。ワイヤに座標を
載せるかは M3 の裁定事項(goal 明記)。

### 第 1 周

- **案 S-a: 列挙のみ(仕様文言の字義)** — 欠点: 良性の競合(クライアントの
  チェーン同期と pull 取得の間に他メンバーの checkpoint が着地し、応答の列挙が
  自ビューの基準より新しい checkpoint に対応する)と攻撃(列挙の改竄)が
  区別できない。ダイジェスト不一致を一律に「1 回再同期してから再判定」する
  盲目再同期になり、§6.3-2 のヘッド束縛が確立した 2 分類((a) 自ヘッド以下の
  不一致 = 即時の硬い証拠 / (b) 自ヘッドより先 = 再同期 → 解決)と非対称になる
- **案 S-b: 列挙 + 対応 checkpoint seq / entry hash(advisory locator)** —
  §6.3-2 と同型の 2 分類が可能になる: 申告 seq > 自ヘッド = 自チェーンが古い
  だけの可能性(pull は有界再同期 1 回、lease はチェーン同梱ゆえ自己矛盾 =
  即時拒否)、申告 seq ≤ 自ヘッド = 検証済みチェーン上で基準は確定しており、
  基準 checkpoint と不一致な列挙は硬い証拠として即時拒否。検証の基準自体は
  常にチェーン導出(history.latestCheckpointFor)であり、ワイヤ座標は再同期の
  ルーティングと診断にのみ使う — CRYPTO_SPEC §1 原則 6(署名対象外の運搬
  フィールドは advisory。検証の分岐を弱める入力にしない)と両立: 座標を偽って
  も fail-closed(大きく偽る → 再同期後に基準不一致で拒否 / 小さく偽る → 即時
  基準不一致)

### 第 2 周(上位互換探索)

- **案 S-c: 列挙 + 保存タプル全部(epoch / manifest 参照 / values_digest も)** —
  棄却: epoch・digest はチェーン導出値の写しであり、ワイヤに載せると「申告値で
  検証する」誤用面(原則 6 違反の入口)だけが増える。列挙(唯一チェーンから
  再構成できない配布物)と位置(locator)以外は運ばない

### 第 3 周(再点検)

- locator の hash 側の使途を確定: 自ヘッド以下の申告 seq に対して
  entryHashAt(seq) と照合し、不一致は分岐配布の証拠として拒否(seq 単独より
  誤診断が減る)。基準側の一致判定は seq = 基準 checkpoint の seq(チェーン
  導出)との一致で行い、hash 照合はその前提検査
- 旧クライアント互換: 応答フィールドは加法(optionalKey)。旧 CLI のデコードは
  未知キーを無視するため壊れない。逆方向(新 CLI × 旧サーバー = 列挙なし)は
  規則 2 の MUST(基準あり + 列挙なし = 拒否)どおり fail-closed —
  SELF_HOSTING.md にサーバー先行の更新順として明記(§8)

**選択: 案 S-b**。応答フィールド `checkpointSnapshot = { chainSeq, entryHashHex,
values[] }`。

## 3. 裁定 T: checkpoint-digest.json ベクター(session-27 §13-4)の要否

### 第 1 周〜第 3 周(要約)

- §13-4 の列挙(variables_digest / values_digest / audit-head の LP 正規形)は
  既存ベクターが全て固定済みであることを確認した: variables_digest =
  env-manifest.json(PR-M1)、values_digest = chain-entries.json の
  values_digests セクション(PR-F3a/M2 — values-digest.ts のモジュールコメントが
  参照)、audit-head = audit-head.json(PR-M2 裁定 J)。M3 は新しい正規形
  (バイト列形式)を 1 つも導入しない(規則 2 の比較群は §13-5 の実装テスト分類)
- **独立ファイルへの再掲(案 T-a)は棄却**: 同一正規形の二重ベクターは「片方だけ
  更新される」乖離面を作る(ベクターは加法のみ・再生成禁止の規律とも相性が悪い)

**選択: ベクター追加なし**(§13-4 は既存 3 ファイルで充足済みと判定)。crypto に
一切触れないため、ベクター先行コミット・4 環境ハーネス・人間レビュー必須条件は
本 PR では対象外(適用対象が存在しない)。

## 4. 裁定 U: 規則 2 検証成功の床(検証済み観測の単調 join)への記録

### 第 1 周

- **案 U-a: スナップショット列挙を値床へ join する** — 棄却: 床の記録規則は
  「値床は値を実際に検証した場合のみ記録する(捏造しない)」(§6.3)。列挙の
  エントリはダイジェスト経由でチェーン基準と照合されるが、クライアントが
  その version の値署名を検証したわけではない — join は記録規則違反。また列挙は
  checkpoint 時点の状態であり、同じ応答で §6.3 検証を通過した配布値(≥ 列挙の
  version)の床記録に常に支配される(join しても格子上の増分がない)
- **案 U-b: 「規則 2 を checkpoint seq S に対して検証済み」の新レコード種** —
  棄却: この事実を消費する検出規則が存在しない(基準はチェーン導出であり、
  次回の検証は次回のチェーンから基準を引き直す)。チェーンから再導出可能な
  状態を床に写すのは二重真実源(床は「チェーンに載らない検証済み観測」の
  置き場 — チェーンヘッド床が既にチェーン自体をピンしている)
- **案 U-c: 新レコードなし** — 規則 2 成功後の既存 commitPull(検証済み配布値 +
  チェーンヘッドの原子コミット)がそのまま「検証に成功した事実の join」を充足
  する(journal-before-release の順序も既存実装のまま: 床コミット → 復号・使用)

### 第 2 周(上位互換探索)

- **案 U-d: 環境水準エポック観測(座標 (ii))へ基準 epoch を join する** — 棄却:
  基準 epoch はチェーン導出値で、チェーンヘッド床 + 再導出で常に復元できる。
  observedEpoch の join は「チェーンに載らない観測」(マニフェストの焼き込み等)
  のためにあり、チェーン導出値を流し込む先例を作ると (ii) の意味論が濁る

### 第 3 周(再点検)

- lease 経路は床を持たない初回同期クラス(§14.3-3)のままであることを確認 —
  規則 2 の導入は lease に床を要求しない(基準はサーバー非依存にチェーン導出)

**選択: 案 U-c(新規の床レコードなし)**。

## 5. 裁定 V: lease 経路での検証の層と、基準なし警告(SHOULD)の置き場

### 第 1 周

- **案 V-a: lease-client.ts に独立実装** — 棄却: 「一括 pull と lease の両経路に
  同一規則」(§6.3 / goal)を 2 実装で保つ形は乖離バグの温床(裁定 R と同根)
- **案 V-b: values.ts の共通骨格(verifyAll)に統合し、lease-client はワイヤの
  checkpointSnapshot を通すだけ** — verifyLeaseDistribution は既に verifyAll を
  呼ぶため、規則 2 も自動的に同一実装になる。future → 即時拒否の lease 意味論も
  既存の写像がそのまま適用される

### 第 2 周(上位互換探索)

- **案 V-c: ci-run.ts(コマンド層)での後段検査** — 棄却: 検証は復号・注入より
  前に完結すべき(values.ts の存在理由)。コマンド層に置くと run 経路(値付き
  pull — run.ts は pull 経路を使う)と検査位置が割れる

### 第 3 周(再点検)

- **基準なし警告(§6.3 SHOULD — 床を持たないクライアントは、値付き配布を受けた
  環境に基準が存在しないことを検出したら警告)の置き場**: 対象は「床を持たない
  クライアント」クラス(特にワークロード)。CLI の pull 経路は永続床を持つ
  クラスであり対象外(床未確立の初回 pull も「床を持てるクライアントの初回」で
  あって同クラスではない — 警告を出すと全新規プロジェクトの初回 pull が恒常的に
  警告し、SHOULD の意図〔このクラスの主要保証が働いていないことの可視化〕から
  外れる)。よって警告は verifyLeaseDistribution(ワークロード経路)に置き、
  既存の warnings 配列(非失敗)で表面化する

**選択: 案 V-b + lease 経路のみの基準なし警告**。

## 6. 裁定 W: cross-layer 回帰テストの要否

### 第 1 周〜第 3 周(要約)

- PR-F4 の先例(manifest.test.ts —「チェーンの checkpoint 基準線は床の規則 (a) を
  代替しない」)と同型の相互作用が M3 にも 1 つ実在する: 規則 2 の基準は
  checkpoint 時点で止まる(列挙の version 以上なら通す)ため、**床が checkpoint
  より新しい version を知っている場合の巻き戻しは規則 2 を通過し、床の規則 (a)
  だけが落とす**。この「規則 2 は床を代替しない」を 1 テストで固定する(逆方向 =
  「床なしでも規則 2 が巻き戻しを落とす」は M3 の主 negative 群が固定する)
- それ以上の全組み合わせ網羅(案 W-a)は棄却: 床規則群と規則 2 は独立実装・
  独立入力で、直積の網羅は費用対効果が立たない(F4 が同じ線引きをした)

**選択: 1 本の cross-layer 回帰(規則 2 通過 × 床規則 (a) 拒否)を CLI テストに
含める**。

## 7. 実装内容の要約

- **api-schema**(加法のみ): `CheckpointValueSnapshotEntrySchema`
  (variableId / version / valueSigHashHex)と `CheckpointValueSnapshotSchema`
  (chainSeq / entryHashHex / values — 裁定 S)を data.ts に置き、
  `EnvironmentPullSchema`(§12-7)と `LeaseResponseSchema`(§14-2)へ
  `checkpointSnapshot` を optionalKey で追加。metadata-only pull は対象外
  (§12-7 — 値を運ばない)
- **server**: data-store.ts に読み口 `checkpointSnapshot(environmentId)`
  (environment_checkpoints + checkpoint_snapshot_values の結合 — M2 の保存行
  そのもの。再構成しない)。pullEnvironmentProgram / issueLease が行の存在時のみ
  同梱(LeaseValue は EnvironmentPullValue 派生のため型は自動追随)。削除
  カスケード(§12-4)は既存挙動のまま(スナップショット行も削除済み)
- **CLI**: `checkpoint-integrity.ts`(裁定 R)—
  基準 = history.latestCheckpointFor(チェーン導出・サーバー非依存)。
  (1) 基準あり + 列挙なし = 拒否(MUST)、(2) locator の 2 分類(裁定 S)、
  (3) 列挙の重複 variableId 拒否 + computeEnvValuesDigest 再計算 =
  基準 values_digest 一致、(4) 配布各変数: version ≥ 列挙・等号ならハッシュ一致・
  前進 version の epoch ≥ 基準 epoch(床規則 (c) のチェックポイント版)、
  (5) 列挙にあって配布にない変数は検証済み tombstone で説明されない限り拒否、
  (6) 列挙にない配布変数は epoch ≥ 基準 epoch(version 0 相当と同型。
  マニフェスト整合は前段のダイジェスト再計算が担保)、(7) 基準なし + 列挙あり =
  locator の 2 分類で future / 拒否。values.ts の verifyAll(値付き経路)へ
  マニフェスト段の後に接続し、pull(有界再同期)と lease(future = 即時拒否)の
  両経路が同一実装を通る。lease 経路は基準なし環境の値付き配布に警告(裁定 V)
- **床**: 変更なし(裁定 U)
- **実装中の追補 1(移行許容と基準の整合)**: `--init-manifest` の「欠落の許容」は
  検証済みチェーン上に基準 checkpoint を持つ環境には適用しない(values.ts の
  マニフェスト段)。checkpoint タプルは manifest_version を束縛する(§6.2 /
  §12-4)ため、基準を持つ環境は必ずマニフェストを持つ — その欠落は移行操作下
  でも握り潰しの証拠(床のマニフェスト記録確立後の欠落拒否 — §6.3 — の
  チェーン導出版)
- **実装中の追補 2(証拠の型付け — F4 規律の規則 2 / 床への適用)**: 規則 2 の
  拒否と床違反の拒否は `CliError.evidence`(新フィールド)で型付けし、rotate の
  巡末分類(env-rotate.ts settlePass)は evidence 付きの再走査 pull 失敗を
  「未検証(再実行で直りうる)」でなく**即時中断(abort)**に分類する。M3 で
  「旧エポック値の巡中注入」の検出層が復号段(AEAD 失敗)から pull 検証段
  (規則 2)へ前進したため、型付けなしでは F4 が固定した「証拠を再実行案内へ
  格下げしない」規律が破れる(env-rotate.test.ts の該当テストで固定)
- **テストフィクスチャの正直サーバー化**: rotate 複合を受理する CLI モックは
  スナップショット保存(§16-2)と pull 同梱(§12-7)も模す。旧テスト 2 本が
  モデル化していた「受理時点突合と矛盾する複合の受理」「checkpoint 後の旧
  エポック変数の遅延出現」は、実サーバーでは 422(§12-4)/ 規則 2 拒否になる
  状態であり、テストを正直な形(422 → 再 pull 再試行 / 規則 2 の証拠中断)へ
  改めた(env-rotate.test.ts — 意図の保存はテスト内コメントに記録)
- **docs**: SELF_HOSTING.md に M3 の更新順(サーバー先行必須 — 新 CLI × 旧
  サーバーは checkpoint 済み環境の値付き pull / lease が規則 2 の MUST で全拒否)
  を追記。仕様本文の改訂は不要(M3 は Wave 3 D 承認済み文言への実装追随。
  ワイヤ座標の同梱 — 裁定 S — は §12-7 の「列挙」への advisory 追加であり、
  検証規則・保存規律の文言と矛盾しない)

## 8. テストの固定点(要約)

- サーバー(vitest-pool-workers): 値付き pull への同梱(基準確立後)と内容の
  保存列挙一致 / 基準なし環境では載らない / metadata-only pull に載らない /
  部分集合 checkpoint 後の環境ごとの対応(A 再 checkpoint 後も B は自基準の列挙)/
  lease 応答への同梱
- CLI(pull 経路): 受理正例(checkpoint 後の前進 version・tombstone で説明される
  消失・checkpoint 後の新規作成)と全拒否経路 — 列挙欠落・digest 不一致・
  version 後退・同版ハッシュ不一致・前進 version の旧エポック・tombstone なしの
  消失・スナップショット外変数の旧エポック作成・locator 偽装(seq ≤ 自ヘッドの
  hash 不一致)— session-27 §13-5 の該当項目
- CLI(lease 経路): 同一規則の到達(拒否 1 例 + 正例)+ 基準なし警告
- cross-layer(裁定 W): 規則 2 通過 × 床規則 (a) 拒否の 1 本
