# セッション 28 メモ(Phase 2 Wave 3 D 第 1 弾 — PR-M1: 環境マニフェストの実装)

日付: 2026-08-18。前提: Wave 3 D の仕様承認済み main(PR #80 マージ =
CRYPTO_SPEC 0.6 §4.3 / AUTH_SPEC 0.11 / AUDIT_SPEC 1.0 の所有者承認)。
スコープ: session-27 §14 の **PR-M1(環境マニフェスト)** の実装。
テストベクター先行 → crypto → api-schema → server → CLI の層順
(session-12 §9 の様式)。`packages/crypto` の変更を含むため人間レビュー必須。
M2(チェックポイント)・M3(値スナップショット)・M4(ヘッド申告)には
踏み込まない(中間状態でも保証が単調に増えることは session-27 §14 で設計済み)。

## 1. 実装の全体像(コミット構成)

1. `packages/crypto/test-vectors/env-manifest.json` — session-27 §13-2 の
   正例 6 + fork 2 + digest 正規形 4 + negative 25 を、chain-entries.json の
   正規チェーン参照(session-12 §8-1 の cross-file 先例)で収録。
   生成は `tools/generate_reference.py`(独立参照実装)+
   `tools/verify_reference.mjs` の突き合わせ。**実装より先にコミット**
2. crypto — `manifest-sign.ts`(`computeVariablesDigest` /
   `buildEnvManifestSignedBytes` / `computeEnvManifestSignedBytesHash` /
   `signEnvManifest` / `verifyEnvManifestSignature`)+ `manifest-verify.ts`
   (`verifyDistributedEnvManifest` — 履歴ベース複合検証)。ドメインは
   `maruhi/v1/env-manifest-sig` / `maruhi/v1/env-manifest-vars`(§4.3)。
   4 実行環境(node / browser / bun / workerd)の全ベクター通過
3. api-schema + server — `EnvironmentManifest` 型(発行形)/
   `DistributedEnvironmentManifest`(issuer 情報つき配布形)/
   `CreateEnvironmentManifestSchema`(v1・prev 空をワイヤで固定)。
   全メタ操作 API の複合受理(§12-5 (1)〜(7) — ダイジェスト再計算まで)、
   manifestVersion CAS(metaVersion CAS と同一トランザクション)、
   保持は最新 1 通(`environment_manifests` — 環境削除でカスケード)、
   pull 両モード + lease 応答への同梱
4. CLI — 発行(`env create` / `env rotate` / `push` の変数作成)、
   配布時検証(欠落 = 一律拒否)、床のマニフェスト拡張(規則 (a)(b)(c))、
   移行経路(`--init-manifest`)+ マニフェスト固有の結線テスト
5. 本ノート + 仕様明確化 2 件 + ROADMAP 注記

## 2. 実装判断(申し送りの本体)

### 2-1. 移行手段の選択: `maruhi env rotate --init-manifest`

session-27 §14 は「専用の初期化コマンド、または rotate」としていたが、
**rotate 経由**を採用した。理由:

- AUTH_SPEC §12-5 のマニフェスト受理は**メタ操作への同梱のみ**で、独立の
  初期化エンドポイントは仕様に存在しない。専用エンドポイントは仕様改訂
  (受理経路の追加)を要し、移行のためだけに恒久の攻撃面を増やす
- rotate 複合はマニフェストを必ず再発行する(§12-4)ため、既存コマンドに
  「欠落の許容」を足すだけで初期化が成立する。エポックも前進するので、
  導入前環境の旧エポック鍵の整理(§7 の再暗号化)まで同時に走る

`--init-manifest` の意味論(fail-closed の境界):

- 緩めるのは**サーバーがマニフェストを配布しない場合の欠落の許容のみ**。
  マニフェストが配布された場合の検証(署名・ヘッド束縛・認可・エポック整合・
  ダイジェスト再計算)はフラグの有無に関わらず全て行う
- **床にマニフェスト記録が確立済みの環境への欠落はフラグ下でも拒否**
  (初期化済みマニフェストが消える正当な経路は存在しない = 握り潰しの証拠)
- 初期化済み環境で付けた場合は警告つき no-op(通常の次 version 発行)

CAS 初期値: 保存済みマニフェストが存在しない環境では「最新 = 0」とみなし
manifestVersion 1(prev 空)を受理する(AUTH_SPEC §12-5 (6) に明確化を追記 —
§3 参照)。`CreateEnvironmentManifestSchema` が v1 を固定する作成複合とは別に、
rotate / メタ操作の `EnvironmentManifestSchema` は v1 も受理する(移行の
最初の操作が v1 を発行する)。

初期化が実際に必要(欠落を確認した)実行は **rotate 複合の送信を強制**する
(`--new-epoch` と同じ経路選択): 中断復旧(複合なしの再開)や「確認だけ」の
早期 return を取ると、成功に見えるのに v1 が発行されない(PR #81 レビュー
ボット指摘の修正)。

**依存関係の注意(PR #81 pullfrog レビュー)**: この経路は `env rotate` が
値付き pull(`pullVerifiedEnvironment` — `allowMissingManifest` を尊重)を
使うことに依存している。`pullVerifiedEnvironmentMetadata` は移行許容を持たない
(メタのみ pull に欠落許容の分岐はない)ため、**将来 rotate の前段をメタのみ
pull に載せ替えると移行経路が壊れる**。

### 2-2. 既存ドッグフーディング環境の移行手順(確定)

マニフェスト導入前に作成された各環境について、member 以上が 1 回だけ:

```
maruhi env rotate <environmentId> --init-manifest --reason "manifest initialization"
```

- 成功すると manifestVersion 1 が発行・保存され、以後の配布はマニフェスト
  検証込みになる(欠落 = 拒否に合流)。以後 `--init-manifest` は不要
- 実行順は任意・環境ごとに独立。未初期化環境への pull / run / push /
  ci run は初期化まで欠落拒否で失敗する(エラーメッセージが上記コマンドを
  案内する)ため、**本 PR のデプロイ後すみやかに全環境で実行する**
- **順序要件(PR #81 pullfrog レビュー)**: ① サーバーのデプロイ →
  ② 全環境の `--init-manifest` 初期化 → ③ CI(actions/setup-maruhi が拾う
  CLI)の更新、の順で行う。逆順の帰結: 旧サーバー × 新 CLI では rotate
  エンドポイントが manifest を受け取れず**案内された初期化手順自体が失敗**
  する(サーバー版数ネゴシエーションは存在しない)。環境の移行より先に CI が
  新 CLI を拾うと、`verifyLeaseDistribution` は移行許容を持たない(ワーク
  ロードは自力初期化できない)ため既存ジョブが欠落拒否で落ちる(文言は
  自己説明的 — 沈黙のロックアウトにはならない)
- SELF_HOSTING.md には載せない(公開前の内部移行 — 公開後のセルフホストは
  作成複合が v1 を必須同梱するため未初期化状態が構造的に存在しない)。
  ただし**公開前チェックリスト(ROADMAP)に「SELF_HOSTING.md の "Updates"
  節へ本移行の項目を追加する」を紐づけた**(サーバーと CLI が独立更新される
  セルフホストでは公開後に同じ形が起こるため — 2026-08-11 の client_id 移行の
  先例と同じ置き場)

### 2-3. 床ファイルの互換方針(罠 8 の決着)

床(`floor/<projectId>.json`)は厳格デコード(スキーマ不一致 = 全体破損)だが、
`EnvironmentFloor.manifest` フィールドは **optional とし、欠落は「マニフェスト
床なし」として許容**する:

- マニフェスト導入前に書かれた v1 床ファイルにはこのフィールドがなく、
  欠落を全体破損(fail-open の作り直し)に落とすと既存の値・メタ床の検出
  材料まで捨てることになる。床のバージョン(`v: 1`)は上げない
- フィールドが**存在するのに形が壊れている**場合は他フィールドと同じく
  全体破損(厳格デコードの原則は維持)
- マージは単調(manifestVersion の大きい側が勝ち、欠落側は負けない)。
  変数作成複合の床コミット(`commitPush`)にもマニフェスト前進を同乗させた

### 2-4. 検証実装は packages/crypto に 1 つ

`verifyDistributedEnvManifest`(manifest-verify.ts)がサーバー受理(§6.4)と
クライアント配布時検証(§6.3)の唯一の実装。value-verify / meta-verify と
同型(chain-history.ts の宣言ヘッド時点照会・headAuthorizationReason の共有)。

- **複合発行のエポック特例**(§12-5 (4) の検証側の形): 宣言ヘッド H で
  不一致でも「H+1 のエントリが当該環境にちょうどそのエポックを確立する」
  場合は受理(作成複合 = epoch 1、rotate 複合 = new_epoch)。エポックは
  エントリごとに高々 +1 しか動かないため両条件は同値。健全性論証
  (write 資格を失った鍵が特例を踏めないこと)は manifest-verify.ts の
  モジュールコメントに記載し、ベクター `composite_epoch_rule` 系で固定
- prev 連鎖の実在一致とエポック非減少は predecessor を渡された場合のみ検査
  (latest-only 配布 — 裁定 B の同型)。セッションを跨ぐ後退・同版相違・
  前進注入は床のマニフェスト拡張が担う

### 2-5. CAS 再試行の再署名(§12-5 (6))

- rotate のチェーン CAS(ChainHeadConflict)再試行は、エントリと
  マニフェストの**両方**を試行ごとに再署名する(宣言ヘッドが進むため)
- `ManifestVersionConflict`(409)の扱いはコマンドで分けた:
  - **rotate**: 実行内の再署名では解決しない(並行メタ操作でメタ集合自体が
    変わった可能性があり、pull からやり直さないと digest の材料が古い)ため、
    再実行を案内して中断
  - **push(変数作成)**: 既存の名前再解決ループ(MetaVersionConflict と
    同じ入口)に合流させ、メタ状態を取り直してステートメントとマニフェストの
    両方を再署名する
- 変数の一括投入は逐次実行(§12-5 の実装注意 — sweep-rotate は元々逐次)

### 2-6. サーバーの保持と配布

- `environment_manifests` は環境ごとに 1 行(UPSERT)— 全 manifestVersion を
  保存しない(§12-5 / §12-8。session-27 §16 で行数上限案を撤回した経緯)
- 環境削除カスケード(`retireEnvironment`)で行を削除。環境削除は
  マニフェストを再発行しない(§12-4)
- pull 両モード(値付き / メタのみ)・lease 応答(§14-2)に同梱。ワイヤ上
  optional なのは移行完了までの過渡状態のみ(サーバーは保存行があれば必ず
  同梱する)

## 3. 仕様乖離の有無(罠 1 の報告)

**意味論の乖離なし**。実装中に「仕様が言い切っていない」3 点を仕様側へ
明確化として追記した(いずれも既存様式の Status 行つき — 本 PR の「要裁定」):

1. **AUTH_SPEC §12-5 (6)**: manifestVersion CAS の初期値 — 保存済み
   マニフェストなし = 最新 0 → manifestVersion 1 受理(移行経路。専用の
   初期化エンドポイントは設けない)
2. **CRYPTO_SPEC §6.3**: 移行の明示初期化操作(`--init-manifest`)の境界 —
   緩めるのは欠落の許容のみ・床確立後の欠落は移行操作でも拒否
3. **CRYPTO_SPEC §6.3**: 床規則 (c) のマニフェスト適用の基準 —
   「pull 時点エポック床」と「床マニフェスト自身の epoch」の大きい方
   (レビューボット指摘: rotate 受理直後・有界再同期の形で pull 基準が
   遅れている窓に、旧エポック焼き込みの前進 manifestVersion が素通りする。
   マニフェスト連鎖のエポック非減少 — §4.3 epoch-regressed — の推移形
   なので誤検出を生まない強化)

## 4. テスト(session-27 §13-5 のマニフェスト項の対応)

- ベクター: env-manifest.json 全収録(正例 / fork / digest 正規形 / negative
  25)を 4 実行環境で通過。フィールド順・LP 正規形・複合エポック特例を固定
- server(vitest-pool-workers): 全メタ操作 API の複合受理(CLI 未実装の
  変数 rename / 削除・環境 rename の経路含む)・CAS 再試行(両署名の再発行)・
  サーバーのダイジェスト再計算(422)・保持 1 通・pull 両モード + lease 同梱・
  カスケード削除
- CLI(test/manifest.test.ts ほか): 欠落 = 一律拒否(移行案内の文言込み)・
  ダイジェスト再計算(変数 / tombstone の欠落)・エポック整合・issuer 役割
  不足・署名反転、床規則 (a) 後退 / (b) 同版相違 / (c) 旧エポック焼き込み /
  確立後の欠落、`--init-manifest` の 4 分岐(既定拒否・v1 初期化・no-op 警告・
  検証は緩和しない)、複合ボディの発行内容(v1 / 次 version・prev 連鎖・
  ダイジェスト再計算一致)

## 5. 申し送り

1. **M2(チェックポイント)への接続**: `latestCheckpoint` 導出・チェック
   ポイント整合検証(§6.3)は本 PR に含めていない。マニフェストの
   `signedBytesHashHex`(床記録・`VerifiedManifest`)が checkpoint の
   manifest 参照の材料になる形は確保済み
2. **メタ forward injection の残余**(§14.3-5 の縮小後): 床のマニフェスト
   規則でも「攻撃鍵の在籍区間終了後に一度も pull していないクライアント」
   への注入は検出されない(値の規則 (c) と同型の限界)。テストで非保証を
   固定済み(floor-detection.test.ts — マニフェストごと前進させる形)。
   より一般に、**巻き戻し方向の検出は M1 時点では完全にローカル床に依存**
   する(配布時検証は predecessor を渡さないため prev の実在一致・エポック
   非減少は発火せず、宣言ヘッドは検証済みチェーン上に実在すれば tip でなくて
   よい — 値・メタと同じ規約)。§4.3 の「鮮度アンカー」が本当に要る 2 場面
   (床のない初回接触・使い捨て CI ランナー)は M1 では守られない — 内部整合
   的な古いマニフェスト + 古いステートメント集合の配布は通る。この閉包は
   M2(チェックポイント整合)/ M4(ヘッドゴシップ)の担当(PR #81 pullfrog
   レビューでの確認事項 — 後続 PR で過大に読まないこと)
3. **CLI の変数 rename / 削除・環境 rename / 削除コマンドは未実装のまま**
   (本 PR の範囲外 — API 経路は server テストで固定済み)。新設時は
   マニフェスト同梱(signNextManifest)を忘れないこと — api-schema の
   payload 型が manifest を必須にしているため、忘れると型エラーで気づける
4. **一括投入の逐次実行**: 将来 CI からのバッチ作成を実装する場合、
   manifestVersion CAS により環境単位で直列化される(§12-5 の実装注意)
