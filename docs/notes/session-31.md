# セッション 31 メモ(PR-M1 環境マニフェスト — マージ後監査と修正作業の引き継ぎ)

日付: 2026-08-19。対象: PR #81(`a69cf63`、実装 head `885ab69`)。
形式: **監査・引き継ぎのみ**。本ノートを追加する PR では実装を修正しない。
修正は別チャット・別 PR で行う。

前提:

- PR-M1 の設計・実装判断は `docs/notes/session-27.md` §5 / §13 / §14 /
  §16、`docs/notes/session-28.md` を参照
- 暗号仕様の正は `docs/CRYPTO_SPEC.md` §4.3 / §6.3 / §6.4、
  受理・配布面の正は `docs/AUTH_SPEC.md` §12
- `packages/crypto` を変更する修正は CLAUDE.md に従い人間レビュー必須
- M2(チェックポイント)・M3(値スナップショット)・M4(ヘッド申告)が
  担う既知の非保証と、PR-M1 の実装不備を混同しない

## 1. 結論

平文・鍵素材の漏洩、暗号プリミティブの破綻、LP フィールド順の誤り、
`variables_digest` の tombstone / 空集合 / バイト順処理の誤りは
見つからなかった。一方、PR-M1 が意図したマニフェスト連鎖・ローカル床・
ローリング更新の fail-closed 性に、**修正すべき実装不備がある**。

優先度の高いものは次の 6 件:

1. 隣接 manifestVersion の prev 連鎖を CLI が検証していない
2. 新 CLI × 旧サーバーで `manifest` が黙って捨てられる
3. `env create → 新規変数 push` でも環境床が確立しない
4. 受理確認済み rotate のマニフェストが床に残らない失敗経路がある
5. 並行 CLI の床コミットが巻き戻し・equivocation 証拠を失いうる
6. H+1 エポック例外の適用範囲が広すぎ、H+1 エントリの actor / op を
   manifest issuer と束縛しない

以下で再現条件・影響・修正案・固定すべきテストを記録する。

## 2. 監査で確認した事実

### 2-1. マージ済みコードと検証結果

- PR #81 の merge commit `a69cf63` と実装 head `885ab69` の tree は同一
- PR マージ後の main CI / installer は成功
- ルート `bun run check` は成功(52 files / 1711 tests)
- crypto:
  - Node: 646 / 646
  - workerd: 646 / 646
  - Chromium: 646 / 646
  - Bun: 645 / 645
  - `test-vectors/tools/verify_reference.mjs`: 成功
- `fallow audit`:
  - dead code 0
  - complexity finding 0
  - duplication は warning のみ
- 監査中にリポジトリのファイルは変更していない

全テストが緑でも、後述の経路は既存テストが作っていない境界条件なので
検出されない。

### 2-2. 手元で再現したもの

1. Effect `Schema.Struct` は未知フィールドを拒否せず除去する:
   旧 payload schema に `{ ..., manifest: {...} }` を decode すると
   `manifest` が消え、既知フィールドだけが残る
2. ローカル床へ同じ manifestVersion・異なる hash を順に commit すると、
   後の hash が保存され、先の equivocation 証拠が消える
3. 床 v1 に対して、`prevManifestSigHashHex` が床 hash と異なる v2 を
   `checkEnvironmentPull` へ渡しても `null`(拒否なし)になる

## 3. 修正対象

### M1-A1 [高] CLI が隣接マニフェストの prev 連鎖を検証しない

該当:

- `apps/cli/src/manifest.ts`
  - `verifyDistributedManifest`
- `apps/cli/src/floor-check.ts`
  - `checkManifestAgainstFloor`
- `apps/cli/src/floor.ts`
  - `ManifestFloor`

現状:

- `verifyDistributedManifest` は常に `predecessor` を渡さない
- 床は `(manifestVersion, epoch, manifestSigHashHex)` を持っている
- 床検査は後退・同版異 hash・規則 (c) だけで、
  `prevManifestSigHashHex` を比較しない

CRYPTO_SPEC §4.3 は「床がある場合の prev 連鎖」を検証規則としている。
latest-only 配布でも、`pulled.manifestVersion === floor.manifestVersion + 1`
なら床が直前マニフェストそのものなので、prev を厳密に検証できる。

影響:

- 有効署名・正しい digest / epoch を持つ隣接版でも、任意の 64-hex prev で
  CLI 検証を通る
- manifest の分岐証拠化・連鎖保証が、サーバー受理側では有効なのに
  クライアント配布側では欠ける

修正案:

1. pulled version が床 version + 1 の場合:
   - `signedBytesHashHex = floor.manifestSigHashHex`
   - `epoch = floor.manifest.epoch`
   を `EnvManifestPredecessor` として共有検証器へ渡す
2. version に 2 以上の差がある場合:
   - 中間マニフェストを保持・配布しない設計なので、現行どおり
     predecessor の実在一致は検査不能と明示する
3. `manifest-prev-mismatch` 相当の床証拠文言を追加する場合は、
   pulled signature / issuer / declared head と床 hash を含める

固定テスト:

- floor v1 → 正しい prev の v2: 受理
- floor v1 → 異なる prev の v2: 拒否
- floor v1 → v3(version gap): latest-only の既知制約どおり受理
- metadata-only pull / value pull の両方で同じ結果
- `maruhi ci run` の lease 応答: **prev 連鎖検査は適用外**
  (`verifyLeaseDistribution` は床を使わない — ワークロードは床を
  持たない初回同期クラス〔§14.3-3〕で、`RepositoryAnchor` も
  manifest 座標を持たない。§11 の「使い捨て CI の永続床不在」と
  整合)。lease の固定テストは共有検証器の同一性に限定する:
  署名・digest・epoch 整合・欠落拒否が pull と同水準であること、
  および床由来の prev 検査が lease 経路で発火**しない**こと

### M1-A2 [高] 新 CLI × 旧サーバーが manifest を黙って捨てる

該当:

- `apps/cli/src/env-create.ts`
- `apps/cli/src/env-rotate.ts`
- `packages/api-schema/src/data-api.ts`
- 旧 main `5cf9138` 時点の create / rotate payload schema

現状:

- 新 CLI は create / rotate payload に `manifest` を送る
- 旧サーバー schema はそのフィールドを知らない
- Effect `Schema.Struct` は未知フィールドを除去するため、旧サーバーは
  manifest なしの旧処理を続行し 200 を返しうる

具体的な帰結:

- `env create`: CLI は成功を報告するが、サーバーにはマニフェストがない
- `env rotate --init-manifest`: 旧サーバーは rotate だけ受理し、
  CLI はサーバーが保存していない自己発行マニフェストを床へ記録しうる
- その後サーバーを更新すると missing manifest を床確立後の omission と
  判定し、通常の `--init-manifest` では復旧できない

`docs/notes/session-28.md` の
「サーバー → 環境初期化 → CI / CLI 更新」という運用順序は緩和になるが、
プロトコル自身は fail-closed ではない。セルフホストではサーバーと CLI が
独立更新されるため、文書だけに依存しないほうがよい。

修正案:

1. `/auth/config` 等へ capability を追加:
   - 例: `apiCapabilities: ["environment-manifest-v1"]`
2. 新 CLI は manifest を伴う変更操作の**前**に capability を必須確認
3. capability 欠落時は一切 mutation を送らず、サーバー更新を案内
4. create / init rotate の受理後は、サーバーから配布されたマニフェストを
   取得し、自計算した `(version, epoch, signed-bytes hash)` と照合してから
   床へ記録
5. 将来のサーバー schema は security-critical payload で未知フィールドを
   拒否する方針も検討する

固定テスト:

- capability なし旧サーバー: create / init rotate とも送信前に拒否
- capability あり新サーバー: 正常受理
- サーバーが 200 だが pull で manifest 欠落: 床を前進させず失敗
- サーバーが別 manifest を返す: hash 不一致で失敗

### M1-A3 [高] env create / 新規変数 push が床を確立しない

該当:

- `apps/cli/src/env-create.ts`
- `apps/cli/src/values.ts`
  - `enforceMetadataFloor`
- `apps/cli/src/floor.ts`
  - `applyPush`
- `apps/cli/src/push.ts`
  - `pushVariable` の受理後床コミット

現状:

1. `env create` は v1 とその signed-bytes hash を自計算するが、
   床へ渡さず破棄する
2. 新規変数 push の名前解決は metadata-only pull を使う
3. metadata-only pull は床を検査するだけでコミットしない
4. `commitPush` は環境床がない場合、pullEpoch を捏造しないため
   環境レコードを作らず、ヘッドだけ前進させる

再現可能な結果:

- env create(v1)→ 新規変数 push(v2) の両方が成功しても環境床が存在しない
- 悪意サーバーは、自身が過去に受信した正規 v1 と空変数集合を返すことで、
  新規変数を省略した巻き戻しビューを次の最初の full pull に受理させられる

修正案:

1. metadata-only pull 用の「環境水準だけの床コミット」を追加:
   - chain head
   - environment meta `(version, hash)`
   - manifest `(version, epoch, hash)`
   - 値を読んでいない active variable の値床は作らない
   - **pullEpoch(値規則 (c) の基準)は前進させない**(2026-08-19
     pullfrog レビュー反映 — CRYPTO_SPEC §6.3 の規範「規則 (c) の
     基準はチェーン同期単独で前進させてはならない」。詳細は §7
     裁定 3)
2. `env create` は受理をチェーン / 配布で確認後、
   空変数集合の環境床を作る
3. その後の `commitPush` が v2 + 新変数値床を同じ環境レコードへ追加する

型の選択肢:

- `EnvironmentFloor` を environment / manifest 部分と value floor 部分へ分離
- または metadata-only の部分床を別型で持ち、full pull で統合
- optional field bag で不可能状態を増やさず、判別可能な型にする

固定テスト:

- env create 後に v1 床が存在
- env create → variable create 後に v2 床が存在
- その後に v1 + 空集合を配布すると manifest rollback / omission で拒否
- metadata-only pull は値 version / value hash を捏造しない

### M1-A4 [高] 受理確認済み rotate が床コミット前に終了する

該当:

- `apps/cli/src/env-rotate.ts`
  - `describeSendFailure`
  - `appendRotation`

現状の `commitManifest` は次の後にある:

1. rotate HTTP が成功
2. チェーンを再同期
3. 現エポックが target epoch と完全一致
4. target epoch の DEK commitment が一致

床コミットに到達しないが受理を確認できる経路:

- HTTP 応答消失 / 502 後、`describeSendFailure` の probe が
  target epoch の commitment 一致を確認した
- HTTP 200 後、再同期までに別 rotate が進み currentEpoch が target を
  追い越したが、過去 epoch の commitment から自分の rotate 受理を確認できる

影響:

- CLI は「この rotate 自体は受理された」と知っているのに、
  自己発行 manifestVersion を床へ残さない
- 直後の悪意ある配布で、受理前の manifest / epoch 基準へ戻される窓が残る

修正案:

1. 各 CAS 試行で署名した manifest と entry を保持
2. 送信結果を次の判別可能な outcome にする:
   - `rejected`
   - `not-accepted`
   - `accepted-and-current`
   - `accepted-but-superseded`
   - `acceptance-unknown`
3. チェーン上の target epoch commitment が自分の値と一致した時点で、
   コマンドが最終的にエラー終了しても manifest floor を前進
4. probe 自体に失敗して acceptance unknown の場合は床を前進させない
5. capability / post-accept manifest 照合(M1-A2)と同じ確認経路へ統合

固定テスト:

- 502 + chain 上で自分の commitment 一致: エラー終了でも床は前進
- 200 + 直後に別 rotate: 自分の manifest は最低床として残る
- chain 上の commitment が別物: 床を前進しない
- probe 失敗: 床を前進せず unknown を案内

### M1-A5 [高] 並行 CLI の床コミットが証拠を失う

該当:

- `apps/cli/src/floor.ts`
  - `mergeHead`
  - `mergeVariableFloor`
  - `mergeManifestFloor`
  - `makeFileFloorStore.write`
- `apps/cli/src/floor-check.ts`
  - `makeFloorHandle.commitPush` のディスク環境レコード欠落時フォールバック
  - `makeFloorHandle.commitManifest` のプロセス内先行前進
- `apps/cli/src/values.ts`
  - 床検査と commit の分離

現状:

- コマンド開始時に読み込んだ床で配布を検査
- commit 時にファイルを再読込して単調 merge
- 同一 manifestVersion は `>=` で incoming が勝つ
- read → merge → temp write → rename の間にプロセス間ロックがない
- `makeFloorHandle` のプロセス内マージ 2 経路も
  `manifest.manifestVersion >= current.manifest.manifestVersion` で後勝ちになる。
  `floor.ts` のディスクマージだけを直しても、同一コマンド内の後続検査基準は
  同版異 hash で上書き可能なまま残る

問題:

1. 2 プロセスが古い同一床から別の同版マニフェストを検証すると、
   後の commit が先の hash を上書きできる
2. 真に同時の read-modify-write は、両方が同じ旧ファイルを読み、
   後の rename が先の union を失う last-writer-wins になりうる
3. ディスクに新しい床が存在しても、古い in-memory 床で既に配布を
   accept 済みなので、merge が新しい側を保存しても当該コマンドは
   stale データを使用して成功しうる

修正案:

1. project floor 単位のプロセス間ロックを導入
2. lock 下で:
   - 最新ファイル読込
   - incoming response / commit の再検査
   - merge
   - temp + rename
   を行う
3. 同座標の不一致は「後勝ち」にしない:
   - same chain seq + different hash
   - same value version + different hash
   - same metaVersion + different hash
   - same manifestVersion + different hash
   を typed conflict として拒否
4. `makeFloorHandle` のプロセス内フォールバック / 先行前進にも同じ
   typed conflict 判定を共有し、`>=` の単純置換を残さない
5. lower version / omitted known record も commit 時に再検査
6. ロックのクラッシュ回復を設計:
   - OS advisory lock を使う
   - または owner PID / timestamp 付き lock file + stale 判定
   - lock 取得失敗を床なしへ fail-open しない

固定テスト:

- 2 process / 2 store instance の実並行テスト
- 同版異 hash の片方が上書きされず、両証拠を伴う拒否になる
- 異なる変数の並行 commit は union される
- stale lower-version commit は当該コマンドも失敗する
- lock 保持プロセス異常終了後の復旧

### M1-A6 [中] H+1 エポック例外の適用範囲と actor 束縛

該当(検証器と、epoch の扱いを指定する必要がある呼び出し側の全部):

- `packages/crypto/src/internal.package/manifest-verify.ts`
  - `epochIntegrityReason`
- `packages/crypto/src/internal.package/chain-history.ts`
- `apps/server/src/verify-manifest.ts`
  - `acceptManifestForMetaOp`(strict 側の適用面)
- `apps/server/src/composite-programs.ts`
  - create / rotate の `acceptEnvManifest` 呼び出し 2 箇所
    (複合側の適用面 — 同梱エントリがアンカー材料)
- `apps/cli/src/manifest.ts`
  - `verifyDistributedManifest`(配布検証側の適用面 —
    検証済みチェーンの H+1 エントリがアンカー材料)

先に、**既に検査されている束縛**(監査で誤検出しないための記録):

- worker は composite create / rotate の両方で
  `ensureCompositeActor`(`handlers-environments.ts`)により
  `entry.actor.userId === principal.userId` を検査する
- DO は追記受理時に `verifyChain` を再実行し、
  entry actor の fingerprint とチェーン上のメンバーレコードの一致
  (`actor-key-mismatch`)を強制する
- server 受理の manifest issuer は wire を信用せず、
  `verify-manifest.ts` が呼び出し主体の member identity
  (`input.member.userId` / `keyFingerprintHex`)で上書き強制する

よって「actor / issuer ≠ caller のまま受理される」経路は server には
ない。残るずれは H+1 例外そのものの形:

1. `epochIntegrityReason` の H+1 例外は「H で不一致・H+1 で一致」だけを
   見て、H+1 エントリの actor / op を manifest issuer と比較しない。
   エポックは高々 +1 しか動かないため H+1 エントリが当該環境の
   create / rotate であることは帰結するが、**別メンバーの rotate** に
   相乗りした投機的エポック焼き込み(issuer が自分で確立していない
   epoch を宣言する manifest)を、配布検証(CLI 側)が受理する
2. 同じ H+1 例外が非複合メタ操作の server 受理
   (`acceptManifestForMetaOp`)にも効くため、ordinary meta op が
   「宣言ヘッド H では未成立、H+1 で成立した epoch」を焼き込める。
   AUTH_SPEC §12-4 の意図では H+1 例外は create / rotate composite の
   ためだけの例外である

修正案:

1. `verifyDistributedEnvManifest` の epoch mode を明示:
   - `strict-at-head`(非複合 server meta op)
   - `allow-composite-next-entry`(create / rotate、配布検証)
2. `ChainHistoryIndex` に H+1 entry の actor / op / environment 座標を
   検証済み情報として照会する API を追加
3. H+1 例外を使う場合:
   - op が当該環境の create / rotate
   - issuer user / fingerprint が entry actor と一致
   を要求
4. 本修正は `packages/crypto` を変更するため人間レビュー必須

固定ベクター / server テスト:

- create / rotate: issuer = H+1 entry actor → 受理
- issuer ≠ H+1 entry actor(別メンバーの rotate への相乗り)→ 拒否
- ordinary meta op で H+1 epoch を使う → 拒否
- 既存の actor / issuer 束縛(worker userId 検査・DO fingerprint 検査・
  server issuer 強制)の回帰をテストとして固定

## 4. 低優先度の修正

### M1-B1 v1 head pin が manifestVersion CAS より先に走る

`acceptManifestForMetaOp` は `manifestVersion === 1` の head pin を、
保存済み anchor の取得・CAS より前に検査する。

初期化済み環境へ stale v1 を送った場合、本来は
`ManifestVersionConflict` 409 + `currentManifestVersion` を返すべきところ、
`payload-mismatch` 422 になりうる。正当クライアントの再取得・再署名ループに
合流できない。

修正案:

- anchor 取得 → manifestVersion CAS の順を維持
- `anchor === null && incomingVersion === 1` の場合だけ head pin
- 初期化済みの場合は head の新旧に関係なく先に 409

### M1-B2 初期化済み環境での `--init-manifest` 文言

`rotateSituationWarnings` はマニフェストが既に存在すると
「この rotation は次 manifestVersion を再発行する」と表示するが、
path が `resume` / `up-to-date` の場合は rotate 複合を送らない。

修正案:

- `rotatePathOf` の結果確定後に文言を選ぶ
- `rotate`: 通常どおり次版を発行
- `resume`: フラグは不要、今回は再暗号化だけを再開
- `up-to-date`: フラグは不要、今回は何も発行しない

## 5. テストの修正・追加

### M1-T1 legacy init 正例が異なる DEK を使う

`apps/server/test/data-manifest.test.ts` の legacy-init 正例は、
`wrapDekForAll({ dek: makeDek() })` と
`commitmentOf(..., makeDek())` が別のランダム DEK を使う。

server は member 宛ラップの平文を開けないため受理するが、配布された
新エポック DEK は chain commitment と一致せず、peer CLI は拒否する。

修正案:

- 1 つの `const nextDek = makeDek()` を wrap / commitment の両方に使う
- server の 200 だけで終わらせず、CLI の pull / commitment 検証まで通す

### M1-T2 crypto 境界ベクターの補強

現状の UTF-8 順序ケースは ASCII が中心で、実装は正しいものの次を
直接固定していない:

- BMP と astral code point の UTF-8 バイト順
- fractional integer(`1.5`)
- `Number.MAX_SAFE_INTEGER + 1`
- 同じ長さの大文字 hex

追加先:

- `packages/crypto/test-vectors/env-manifest.json`
- 独立 Python 生成器 / JS 参照 verifier
- Node / Bun / workerd / Browser 共通チェック

テストベクター変更を含むため、**ベクター先行コミット → crypto テスト**
の規律を守る。

## 6. 修正 PR の推奨分割と順序

### PR-F1: 旧サーバー fail-closed(strict 受理の仕様原則化)

対象:

- M1-A2(裁定 1 の改訂推奨 = 案 1-E: 未知フィールド拒否の全面適用 +
  受理後照合。capability は任意の UX 後続)
- SELF_HOSTING / update 順序の公開文書

理由:

- 誤った更新順で新しい不整合状態を作らない入口の防御
- server / CLI のリリース前に先に閉じる
- 最初の作業 = Effect v4 の `onExcessProperty` を HttpApi 受理経路へ
  適用する方法の確認(§7 裁定 1)

### PR-F2: CLI manifest floor の完全性

対象:

- M1-A1
- M1-A3
- M1-A4
- M1-A5
- M1-B2

実装上は大きいため、さらに次へ分けてもよい:

1. adjacent prev + metadata floor + env create anchoring
2. rotate の acceptance outcome / floor commit
3. floor 保存形(§7 裁定 3 の採否に従う: 3-E 採用なら追記専用化 +
   fold、不採用なら §3 M1-A5 のプロセス間直列化)

### PR-F3: H+1 epoch mode と issuer 束縛

対象:

- M1-A6(§7 裁定 2 のはしご — 2-F / 2-E / 2-D — から所有者が選ぶ)
- M1-B1
- M1-T2 のうち H+1 / actor negative

注意:

- `packages/crypto` 変更あり
- ベクター先行
- 人間レビュー必須
- 2-F 採用時は合意規則の変更を含む: `chain-entries.json` 全再生成 +
  既存ドッグフーディングチェーンの re-genesis(§7 裁定 2 第 4 次)

### PR-F4: test hardening

対象:

- M1-T1
- M1-T2 の残り
- 全修正の cross-layer 回帰

## 7. 所有者裁定が必要な項目

修正の大半は既承認仕様への適合作業だが、次の 3 点は**仕様改訂を
先行させる**(CLAUDE.md — 仕様変更はまず仕様書を更新し人間の承認を
得てから実装する)。

### 裁定 1(PR-F1 / M1-A2): 旧サーバー fail-closed の方式

問題: 新 CLI × 旧サーバーで `manifest` フィールドが黙って除去され、
CLI が「サーバーが保存していないマニフェスト」を成功と誤認しうる。

案:

- **案 1-A: `/auth/config` へ capability 申告を追加(事前確認)**
  - `apiCapabilities: ["environment-manifest-v1"]` のような文字列
    配列。CLI は manifest を伴う mutation の**前**に確認し、欠落なら
    一切送らずサーバー更新を案内する
  - 利点: 不整合状態(チェーンには entry があるがマニフェストがない)
    を**作る前**に止まる。公開エンドポイントで認証不要・1 GET で判定。
    将来の機能追加にも使える汎用面。Workers は単一デプロイ単位なので
    config とハンドラの乖離は構造的に起きない
  - 欠点: AUTH_SPEC §4 の改訂が要る(本裁定の対象)
- **案 1-B: サーバーのバージョン番号申告 + CLI の最低要求**
  - 欠点: セルフホストのフォーク・部分適用と相性が悪く、番号は
    「どの機能があるか」の意味論を運ばない。将来も機能ごとに
    最低バージョン表を保守し続けることになる
- **案 1-C: 事後照合のみ(受理応答・pull で保存済みマニフェストを
  取得し、自計算の (version, epoch, hash) と照合)**
  - 利点: 「実際に保存された」ことを直接確認でき TOCTOU がない
  - 欠点: 単独では mutation 送信**後**の検出になる — rotate では
    チェーンに entry が刻まれた後に失敗し、M1-A2 の「missing
    manifest を omission と誤判定する不整合状態」を防げない
- **案 1-D: security-critical payload の未知フィールド拒否
  (サーバー schema の strict 化)**
  - 利点: 将来の同種事故(新フィールドの黙殺)の構造的な再発防止
  - 欠点: 既に配布済みの旧サーバーは直せないため、今回の問題
    そのものへの対策にはならない。Effect Schema の既定(除去)から
    の逸脱なので方針の明文化が要る
- 案なし(session-28 の運用順序文書のみ)は、セルフホストで
  サーバーと CLI が独立更新される以上、恒久策にならない — 却下

旧推奨(2026-08-19 初版): 案 1-A 主 + 案 1-C 併用 + 案 1-D は
新設スキーマから。→ 下の上位互換案で置き換える。

#### 上位互換案(2026-08-19 再検討)

**案 1-E: 「未知フィールド = 拒否」を security-critical 受理の
仕様原則にする(公開前の構造的 fail-closed)**

枠の再確認で判明した事実:

- maruhi は公開前(ROADMAP Phase 2 未到達)。仕様は「公開前のため
  後方互換条項を持たない」原則を §6.2(メンバー鍵一意性)・
  `checkpoint` op・grant_server 拡張で繰り返し使っている
- 「旧サーバー」は外部に存在しない。存在するのは内部
  ドッグフーディングデプロイのみで、その移行は session-28 §2-2 の
  手順が既に覆う
- チェーン層には同型の原則が既にある: **「未知 op = チェーン無効」の
  合意規則**。API 受理層だけが Effect Schema の既定
  (未知フィールドを黙って除去)という逆の既定を持つ —
  本案はこの非対称の解消として位置づけられる
- Effect v4(rc.109)は `SchemaAST` の `onExcessProperty` /
  `UnexpectedKey` を持ち、strict 受理を実装できる(HttpApi 経由での
  適用方法の確認は PR-F1 の最初の作業)

内容:

1. security-critical mutation payload(チェーン追記・複合・値 push・
   メタ操作・ラップ登録・リース請求)の受理を未知フィールド拒否
   (strict)にする。公開前のため後方互換条項なしで導入できる
2. 以後の wire 非互換変更の設計規範を仕様に 1 行で置く:
   「旧実装が構造的に拒否する形にする」— フィールドの追加・削除は
   strict が自動で捕捉する。意味論だけが変わる変更は必ず構造マーカー
   (新フィールド、または必須リテラル版ピンの bump)を伴う

capability(案 1-A)との比較:

- 1-A は**協調的** — すべての将来クライアントが確認を忘れない規律に
  依存する。1-E は**構造的** — 旧サーバー自身が拒否するため、
  クライアント側の規律が不要
- 1-A は列挙した capability しか守らない。1-E はフィールドの
  追加・削除を自動で全部捕捉する
- 1-A は確認と送信の間に TOCTOU 窓がある。1-E は受理時 decode での
  拒否 = リクエスト単位で原子的(複合は 1 リクエストなので
  部分受理は構造的に起きない)
- 1-A の残る優位は UX のみ(送信前に「サーバーが古い」と分かる
  誘導文言を出せる)
- **1-E の実装コスト(2026-08-19 pullfrog レビュー反映)**:
  `onExcessProperty` は decode 呼び出しの `ParseOptions` であって
  スキーマ注釈ではなく、現行の `HttpApiBuilder` は payload
  デコーダを ParseOptions なしで組み立てる。strict 受理へ到達する
  経路(エンドポイント定義でのオプション指定・手動 decode 層・
  upstream 対応のいずれか)の確認が PR-F1 の最初の作業であり、
  その結果で本案のコストが確定する

改訂推奨(第 2 次): 案 1-E を主防衛として仕様原則化し(公開前の
全面適用)、案 1-C(受理後照合)を防衛多層として維持、案 1-A は
UX 向上の任意追加(後続でよい)へ格下げする。1-D の「新設スキーマ
から」を「公開前の今、全面適用」へ強めた形であり、fail-closed を
プロトコル協調からデプロイ成果物の構造へ移す。仕様改訂の面も
AUTH_SPEC §4(新エンドポイント面)から §12 の受理原則 1 項へ縮む。

#### さらなる検討(2026-08-19 第 3 次)— 1-E の残余と成功定義の昇格

案 1-E が受け入れたままの前提を再点検した:

- (i) 意味論だけが変わる変更(スキーマ不変)は strict が捕捉できず、
  「構造マーカーを伴う」設計規範(人間の規律)に残る
- (ii) strict はサーバー**受理側**の防御であり、「クライアントが
  2xx を信じてよいか」は別の問題として残る

検討して棄却した案:

- スキーマ指紋の自動照合(payload にビルド時導出の schema hash を
  載せ、サーバーが受理集合と照合): (i) を塞げない(意味論変更は
  スキーマ不変)まま機構だけが増える — 過剰工学として棄却
- CLI とサーバーの厳密バージョン一致(完全ロックステップ):
  セルフホストの独立更新と互換修正の適用を不必要に拒否する
  運用硬直 — 棄却

採用する昇格 — **案 1-E′: 受理後照合を「成功の定義」へ昇格する**:

- security-critical mutation の成功 = 「2xx を受け取った」ではなく
  「**検証可能な配布物(チェーン・検証済み pull)で効果を確認した**」
  と仕様に定義する
- これは maruhi の既存原則(サーバーを信頼しない — E2EE・チェーン
  検証・配布時検証)の mutation 側への一貫適用であり、旧サーバー
  だけでなく**悪意・バグのある新サーバー**にも同じ防御が効く
- 1-E(受理の原子性 — 半端な状態を**作らせない**)と 1-E′(成功の
  真実源 — 作られたと**信じない**)は同じ原則の両面:
  「2xx は輸送層の事実でしかない」
- **確認材料は mutation 種別ごとに定める(2026-08-19 pullfrog
  レビュー反映)**: チェーン追記・複合はチェーン同期、メタ操作
  (ステートメント・マニフェスト)は metadata-only pull
  (`var.read` を記録しない経路)。**値 push は 1-E′ の適用外**:
  効果確認に使える配布物が値 pull しかなく、書き込み経路に
  `var.read` 監査を持ち込む(案 3-B の棄却根拠と同じ衝突 —
  `pullVerifiedEnvironmentMetadata` が push のために存在する理由の
  裏返し)。値 push の成功は従来どおりサーバーの CAS + 値署名検証と
  自床の `commitPush` が担い、値の巻き戻し検出は checkpoint(M2)の
  領分
- 床への記録(M1-A4 の受理確認)・ユーザーへの成功報告は、
  この確認を通過したものだけが行う — M1-A2 修正案 4 の
  「取得して照合」が防衛多層から定義そのものへ変わる

最終推奨(第 3 次): 1-E(strict 受理)+ 1-E′(成功定義の昇格)+
意味論変更の構造マーカー規範。capability(1-A)は従来どおり
任意 UX。(i) の残余はスキーマ指紋でも消せないため、
本形が本裁定の設計空間の天井と判断する。

#### 第 4 次検討(2026-08-19)— 残余規範の既存不変条件への還元

第 3 次で「人間の規律」として残した (i)(意味論のみの変更の
構造マーカー規範)を再点検した結果、**新しい機構なしで既存の
不変条件に還元できる**:

- maruhi の security-critical な構造(チェーンエントリ・値・
  ステートメント・マニフェスト・DEK ラップ・リース)は、すべて
  **ドメイン分離文字列付きの正規化 LP 署名バイト列**(§2.1)を持つ。
  署名構造の意味論変更は LP フィールド列の変更であり、旧実装は
  **署名検証の不一致として自動拒否する** — 署名自体が構造マーカー
- よって規範は「意味論変更にはマーカーを付ける」(運用規律)ではなく
  「**security-critical な意味論は必ずドメイン分離済み署名バイト列の
  中に置く**」(既存アーキテクチャの明文化)で足りる
- 人間の規律が残る面は 2 つ(2026-08-19 pullfrog レビュー反映 —
  当初の「実質空集合」は過大主張): (i) 非署名の運搬部分 — 座標は
  §12-5 のサーバー側再構成が担保済み、`reencryption` 等の advisory
  flag は設計上 security-critical でなく、実質空集合。(ii)
  **受理側の検証モード選択** — M1-A6 がまさに反例で、「エポックを
  宣言ヘッド時点で見るか H+1 まで許すか」はどの署名バイト列にも
  入らず、受理側のルーティングだけが決める。この残余は裁定 2 の
  帰結に依存する: 2-E / 2-F を採れば選択がデータ(署名フィールド /
  チェーン payload)へ構造化されて消え、2-D では呼び出し規約
  (既定 strict)の規律として残る

また、裁定 2 で案 2-F(逆向き束縛)を採用する場合、composite の
成功確認(1-E′)は**チェーン同期だけで完結する**(エントリが
マニフェストハッシュを運ぶため、配布 pull での照合が不要になる)—
相乗効果として記録する。

**最終推奨(確定): 1-E + 1-E′ + 「意味論は署名バイト列の中に置く」
の明文化**。第 4 次で新機構は不要と確認 — 本裁定の天井は、検証モード
選択の残余が裁定 2 の帰結(2-E / 2-F 採用で構造化されて消える、
2-D なら規律として残る)で決まることを条件とする。

### 裁定 2(PR-F3 / M1-A6): H+1 例外の仕様明文化

- CRYPTO_SPEC §4.3 検証規則 (2) と §6.3 のマニフェスト検証は、
  文言上「マニフェストの epoch = **宣言ヘッド時点**の現エポック」の
  厳密一致であり、複合発行形(宣言ヘッド H = 追記前ヘッド、エポックは
  H+1 の同梱エントリで成立)を受理する例外は**仕様に明文がない**
  (session-28 ノートと `manifest-verify.ts` のコメントのみ)
- 複合発行の正当なマニフェスト(create = epoch 1、rotate =
  new_epoch)は厳密一致では検証不能なので、何らかの例外は必要

案:

- **案 2-A: 検証モードの二値化 + H+1 エントリの op / actor 束縛を
  明文化**
  - `strict-at-head`(非複合 server meta op)と
    `allow-composite-next-entry`(create / rotate 複合受理、
    クライアント配布検証)を仕様の検証規則として書き分ける。
    後者は「H+1 エントリが当該環境の create / rotate であり、
    その actor(user + FP)が manifest issuer と一致する」ことを
    受理条件に加える
  - 利点: ワイヤ形式・保存形式の変更なし(検証規則の強化のみ)。
    既発行の正当なマニフェストは全て通り、再発行・移行が不要。
    投機的エポック焼き込み(他人の rotate への相乗り)と非複合での
    H+1 使用の両方を塞ぐ
  - 欠点: 検証器にモード引数、`ChainHistoryIndex` に H+1 エントリ
    照会 API が増える(crypto の API 面がやや太る)
- **案 2-B: 複合同梱マニフェストの宣言ヘッドを「追記後ヘッド
  (= 同梱エントリ自身)」へ変更し、例外を全廃して常に
  strict-at-head にする**
  - 利点: 例外という概念自体が消え、検証規則が単一化される
  - 欠点: **AUTH_SPEC §12-4 の既裁定(2026-08-03「同梱エントリ自身を
    ヘッドに宣言する形は受理しない — 検査対象チェーンが割れる曖昧さの
    排除」)の蒸し返し**。ステートメント(値・メタ)は追記前ヘッドの
    まま残るため、マニフェストだけ非対称になる。既発行マニフェストが
    旧形式になり、ドッグフーディング環境の再初期化(移行)が要る
- **案 2-C: 現状の無条件 H+1 例外をそのまま仕様へ追認する
  (束縛なし)**
  - 欠点: 投機的エポック焼き込みが仕様公認になり、非複合メタ操作の
    H+1 使用は AUTH_SPEC §12-5 (4) の現行文言と矛盾したまま。
    却下に等しい

旧推奨(2026-08-19 初版): 案 2-A。案 2-B は既裁定の蒸し返し
(CLAUDE.md が禁じる形)であり、得られる単純化に対して移行コストと
非対称の導入が見合わない。→ 案 2-A の趣旨を保ったまま、下の形が
上位互換になる。

#### 上位互換案(2026-08-19 再検討)

**案 2-D: モード列挙でなく「検証済み複合アンカーの明示提示」で
例外を有効化する(既定 = 厳密)**

案 2-A のモード引数(`strict-at-head` / `allow-composite-next-entry`)
は、呼び出し側が誤ったモードを渡す・既定が緩い側に置かれるという
fail-open の余地を残す。次の形に置き換える:

- `verifyDistributedEnvManifest` は省略可能な `compositeAnchor`
  (検証済み H+1 エントリの座標: op・environmentId・actor user + FP・
  確立エポック)を受け取る
- **未指定 = 厳密(宣言ヘッド時点の一致のみ)**。非複合メタ操作の
  server 受理は「何も渡さない」だけで正しくなる — 忘れた場合の
  失敗方向が安全側に固定される
- 指定時のみ受理を拡張し、次を**すべて**要求する:
  - anchor.op が当該環境の create / rotate
  - anchor が確立するエポック(create = 1、rotate = new_epoch)
    = manifest.epoch
  - **anchor.actor(user + FP)= manifest issuer**
- anchor の出所: server 複合受理は同梱エントリそのもの
  (直前に検証済み — 履歴照会不要)。クライアント配布検証は
  自分の検証済みチェーンの seq H+1 エントリから構成する
  (クライアントは全チェーンを保持している — §6.3。リース受信者も
  リース応答がチェーンを同梱する — AUTH_SPEC §14)

案 2-A との比較:

- 既定が strict なので、fail-open のモード渡し間違いが型的に消える
- 例外の前提(H+1 エントリの座標・actor)が検証器の**明示入力**に
  なり、テストベクターで直接固定できる。検証器の中に履歴照会が
  増えない — crypto コアが小さいままで人間レビューの負担も小さい
- `ChainHistoryIndex` への H+1 照会 API 追加が不要
  (呼び出し側が検証済み材料から anchor を組む — `entries` /
  `history` と同じ「呼び出し側の検証済み材料」信頼クラス)
- anchor 経路では `environmentStateAt` の照会自体が不要になり、
  検証規則の場合分けが「anchor の有無」の 1 軸に畳まれる

改訂推奨(第 2 次): 案 2-A の趣旨(例外の適用範囲の限定 +
issuer 束縛)を案 2-D の形で仕様化する。仕様文言は「例外は検証済み
アンカーの提示によってのみ有効化される。既定は厳密」とする —
モード名の列挙より規範として強い。

#### さらなる検討(2026-08-19 第 3 次)— 発行モードの自己記述

案 2-D が受け入れたままの前提: マニフェスト自身は「複合発行か
否か」を宣言せず、発行モードが**署名対象の外**にある(検証側が
strict → anchor の順に文脈から推定する)。これを崩す:

**案 2-E: `composite_entry_hash_hex` フィールドの追加 —
マニフェストが複合束縛を自己記述する**

- §4.3 の LP 署名対象へ `composite_entry_hash_hex` を追加(末尾)。
  複合発行 = 同梱エントリの entry_hash、非複合 = 空文字列
  (manifestVersion 1 の prev 空文字列と同型のパターン)
- 検証が単一パスで決定的になる:
  - 空 → 宣言ヘッド時点の現エポックと厳密一致(strict)
  - 非空 → `entryHashAt(H+1)`(`ChainHistoryIndex` に**既存**)との
    完全一致 + H+1 で確立されたエポック = manifest.epoch +
    **H+1 エントリの actor = manifest issuer**
- entry_hash は actor・payload(dek commitment 込み)の全体を覆う
  ため、**座標列挙(2-D の anchor)より暗号学的に強い束縛**:
  投機的相乗り(他人の**将来の** rotate への便乗)は entry_hash を
  予知できず構造的に不可能になる。残るのは事後の相乗り(チェーン上の
  公開 hash の写し)のみで、それは actor = issuer 規則が塞ぐ
- **§12-4 の既裁定(宣言ヘッド = 追記前)には抵触しない**:
  宣言ヘッドは H のまま(ヘッド実在検査の対象も不変)。
  追加フィールドはエポックアンカーの束縛であってヘッド宣言ではない
- CAS リトライは現行でも「エントリ・ステートメント・マニフェストの
  全部を再署名」しており(env-create.ts)、エントリ hash 確定 →
  マニフェスト署名の順序は既存の構築順で成立する

コスト(2-D にない、本案唯一の負担):

- ワイヤ・署名対象の変更 = `env-manifest.json` ベクターの全再生成 +
  既存ドッグフーディング環境のマニフェスト再発行(各環境 1 回の
  メタ操作 / rotate。サーバー保持は最新 1 通なので旧形式は自然に
  消える。床の prev 連鎖は hash が不透明値のため影響なし)
- crypto 差分が 2-D より大きい(ただし検証ロジック自体は probe が
  消えて単純化する)

判断材料 — 先例: grant_server リースポリシー拡張(§6.2)は
「公開前に payload 形式を確定することで grandfathering のコストを
支払わずに解消する」としてベクター全再生成を選んだ。
**公開後は本案は選べなくなる**(後方互換条項が必要になる)ため、
選ぶなら今しかない。

最終推奨(第 3 次): 所有者がベクター再生成 + マニフェスト再発行の
一時コストを受け入れるなら案 2-E、受け入れないなら案 2-D。

#### 第 4 次検討(2026-08-19)— 束縛の向きの反転

案 2-E が受け入れたままの前提: 束縛の向きが「マニフェスト →
エントリ」であり、事後の相乗り(チェーン上の公開 entry_hash の写し)
が可能なため **actor = issuer 規則が独立検査として残る**。
向きを反転するとこの規則ごと消える:

**案 2-F: 逆向き束縛 — チェーンエントリが manifest を運ぶ**

- `create_environment` / `rotate_epoch` の payload に
  `manifest_version` + `manifest_sig_hash_hex` を追加する。
  **checkpoint op の payload エントリ
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
  values_digest_hex)` と同じフィールドの同型**(§6.2)であり、
  「チェーンは manifest ハッシュを運び、内容はチェーン検証では
  検証不能(データ層が担う)」の先例に完全に載る
- 検証規則が単一検査になる: manifest の epoch は宣言ヘッド時点の
  現エポックと一致する。例外は「**H+1 エントリが当該環境の
  create / rotate であり、その payload の manifest_sig_hash_hex が
  本マニフェストの signed_bytes ハッシュと一致する**」場合のみ
- **actor = issuer 規則が不要になる**: エントリの actor は
  「このマニフェスト(ハッシュ)を伴って rotate する」と署名して
  おり、双方向の暗号束縛が成立する。事後の相乗りは自分の
  マニフェストのハッシュがエントリに載っていないため構造的に不可能
  — 投機的・事後的の両方が検査規則なしで消える
- **マニフェストのワイヤ形式は不変**(2-E の `composite_entry_hash_hex`
  追加が不要になる — env-manifest ベクターは負例追加のみで
  形式再生成なし)
- 波及効果(本案が同時に強くするもの):
  - **発行時チェーンアンカー**: rotate / create のマニフェストの
    ハッシュが認証済みブロードキャスト(チェーン)に載る。
    checkpoint(周期)に加えて、エポック境界という最重要点が
    発行時点で即座にアンカーされる
  - M1-A4: 受理確認 = チェーン上の自エントリ確認だけで、
    manifest の床コミット材料(version + hash)が揃う
  - M1-A3: env create 直後の床のマニフェスト記録がチェーン導出で
    確立できる
  - 1-E′: composite の成功確認がチェーン同期で完結
- 構築順序は成立する: マニフェスト署名(宣言ヘッド H を束縛)→
  ハッシュ計算 → エントリ構築・署名。CAS リトライは現行どおり
  全部再署名(順序が入れ替わるだけ)

コスト(2-E より重い — 本案唯一の負担):

- チェーン**合意規則**の変更 = 全実装の同時更新 +
  `chain-entries.json` ベクターの全再生成(expected_head_states
  含む)+ **既存ドッグフーディングチェーンの作り直し(re-genesis)**
  — 既存チェーンは旧形式の create / rotate エントリを含むため。
  checkpoint op が「既存 op payload に触れない」ことを利点として
  明記した(§6.2)ことの裏返しのコスト
- **re-genesis はチェーン層に閉じない(2026-08-19 pullfrog レビュー
  反映 — 当初の見積もりは過小)**: projectId = genesis ハッシュで
  あり、値・環境メタ・マニフェストの署名バイト列はいずれも
  project_id と chain_head_hash_hex を焼き込む(§4.1 / §4.2 / §4.3)。
  genesis を作り直すと既存の署名済みデータは新チェーンで検証不能に
  なるため、**データ層の全再構築** — 全変数の再 push・メンバー
  再登録・リポジトリアンカーの再ピン・床の破棄 — を伴う。2-E の
  「各環境 1 回のメタ操作で再発行」とは粒度が 1 段違う
- PR-F3 の crypto 差分・人間レビュー負担が最大になる

判断材料: grant_server リースポリシー拡張・rotate への commitment
追加はいずれも「公開前に payload 形式を確定して grandfathering を
支払わずに解消」を選んだ先例。**公開後はチェーン op の形式変更は
事実上不可能になる**(全既存チェーンへの後方互換条項が要る)ため、
本案も今しか選べない。

**最終推奨(確定)— 強度と一時コストのはしご**:

1. **案 2-F**(推奨): re-genesis(**データ層の全再構築を含む** —
   上のコスト行)を許容できるなら最強 — 検査規則が最少で、
   エポック境界の発行時アンカーという恒久的な構造利得が付く。
   maruhi のこれまでの選択(公開前に払って恒久的に単純へ)と一貫する
2. 案 2-E: マニフェスト再発行のみ許容する場合
3. 案 2-D: ワイヤ変更を一切避ける場合

どれも本 finding は塞ぐ。2-F / 2-E は公開前限定の選択肢。

- なお **AUTH_SPEC §12-5 (4) は現行文言が既に「rotate 複合の同梱分」に
  例外を限定している** — 非複合メタ操作の strict-at-head 化は
  適合修正であり裁定不要。裁定対象は CRYPTO_SPEC 側の
  クライアント検証規則の明文化と actor / op 束縛の追加のみ
- `packages/crypto` 変更のため人間レビューも必須(§3 M1-A6)

### 裁定 3(PR-F2 / M1-A3): 床確立契機の拡張

問題: CRYPTO_SPEC §6.3 のローカル床は記録契機を「最後に成功した
pull(検証込み)」と定義しており、`env create → 新規変数 push` の
流れでは環境床が一度も確立しない。

**裁定対象の限定(2026-08-19 pullfrog レビュー反映)**: rotate の
受理確認後の床記録(M1-A4)は本裁定の対象外 — CRYPTO_SPEC §6.3 は
「rotate 複合の受理直後(受理マニフェストの床昇格は行うが pull 基準は
次の pull まで動かない)」と、rotate 受理時の床昇格を既に前提として
規則を書いている。M1-A4 は適合修正(本ノートの裁定不要リストと整合)。
裁定対象は **metadata-only pull の環境水準コミットと、env create
受理確認後の v1 床**の 2 契機のみ。

案:

- **案 3-A: 記録契機を「検証成功したすべての配布・受理確認」へ
  一般化し、環境水準の部分床を明文化する**
  - metadata-only pull は環境水準(chain head / envMeta / manifest)
    のみコミットし、**値を読んでいない変数の値床は作らない**
    (捏造しない)。env create は受理をチェーン / 配布で確認した
    後に自己発行の v1 を記録する
  - **値規則 (c) の基準(pull 基準)は再定義しない**(2026-08-19
    pullfrog レビュー反映 — 当初の「出所を問わない最新観測」への
    再定義は撤回): CRYPTO_SPEC §6.3 は「**規則 (c) の基準は
    チェーン同期単独で前進させてはならない** — pull を経ずに基準へ
    昇格させると、ローテーション後・再暗号化完了前の正当な最新値
    (旧エポックのまま — AUTH_SPEC §12-7)を誤拒否する。この基準
    時点は規範である」と明記する。metadata-only の環境水準コミットが
    pull 基準まで前進させると、値床のない変数(version 0 相当)の
    正当な旧エポック値が stale-epoch-injection で誤拒否される
    (誤拒否列: epoch 1 のまま未再暗号化の変数 Y を、metadata-only
    で基準 5 を得た床が初回 full pull で受け取ると拒否)
  - 環境水準コミットが前進させてよいのは: チェーンヘッド床・
    envMeta 床・マニフェスト床(規則 (a)(b) と、マニフェスト規則 (c)
    baseline のうち床マニフェスト epoch 側)のみ。pull 基準は
    従来どおり値床と原子的にのみ前進する
  - 欠点: 床型が環境水準 / 値水準の二層になり、型・マージの
    実装が複雑化する(M1-A3 の型設計に記載)
- **案 3-B: 床意味論は不変のまま、作成系コマンドの直後に CLI が
  自動で full pull を行い床を確立する**
  - 利点: 仕様改訂が「作成後に full pull を行う(SHOULD)」の
    一文で済む
  - 欠点: **読んでいない値の暗号文 + DEK を取得することになり、
    `var.read` が変数ごとに記録される(AUTH_SPEC §12-7)。
    「読んでいないものを読んだと記録しない」監査規律と衝突し、
    要ローテーション検出(AUDIT_SPEC §4.1)の「確実に取得した」
    ランクにも混入する**。監査を汚さないために metadata-only を
    使うなら、床がコミットされないという現状の問題に戻る(循環)
- **案 3-C: 現状維持 + 運用ガード(手動 full pull 推奨)の恒久化。
  検出は M2 チェックポイントに委ねる**
  - 欠点: env create 直後 = チェックポイント未発行の窓が構造的に
    残る。本ノート §11 の「先送りしない」線引きに反する

旧推奨(2026-08-19 初版): 案 3-A。案 3-B は監査意味論との衝突が
本質的(full pull を自動化する限り回避不能)で筋が悪い。
→ 案 3-A を包含する一般化が下にある。

#### 上位互換案(2026-08-19 再検討)

**案 3-D: 床を「検証済み観測の単調 join」として再定義する
(案 3-A を包含する一般化)**

案 3-A は「契機の列挙(metadata-only pull・受理確認)を足す」形だが、
契機を列挙する限り、将来の新しい経路(リース・環境一覧・次の新機能)
のたびに同じ裁定が再発する。床の定義自体を置き換える:

- 床 = **これまでに検証へ成功した事実(チェーンヘッド・環境エポック
  観測・envMeta・manifest・値)の単調 join(結合半束)**。
  「最後に成功した pull のスナップショット」ではない
- 記録規則はただ 1 つ: **検証に成功した事実は必ず join する。
  値床は値を実際に検証した場合のみ**(捏造しない — 案 3-A と同じ対)
- 同座標で比較不能な事実(同版・異 hash)には join が定義されない
  = typed conflict として equivocation 証拠化(床規則 (b) が
  マージ意味論そのものになる)
- エポック観測は単一の格子点ではなく**型付きの 2 座標**として
  join する(2026-08-19 pullfrog レビュー反映 — 当初の「出所を
  問わない最大値」は CRYPTO_SPEC §6.3 の規範「規則 (c) の基準は
  チェーン同期単独で前進させてはならない(未再暗号化の正当値の
  誤拒否 — この基準時点は規範である)」と衝突するため撤回):
  - (i) **値規則 (c) の pull 基準** — 値床カバレッジと原子的に
    確立された観測**のみ**が前進させる。規範を join の定義の中に
    座標の型として保持する(「床にない変数 = version 0 相当」の
    前提〔基準前進と値床記録の原子性〕が崩れない)
  - (ii) **環境水準のエポック観測** — マニフェスト規則 (c) の
    baseline・巻き戻し / equivocation 検出に使い、出所を問わず
    join する(こちらは値を誤拒否する経路を持たない)

これが同時に解くもの:

- M1-A3: metadata-only 同期・env create 受理確認の事実が join される
  (契機の列挙が不要になる)
- M1-A4: 「受理をチェーンの commitment で確認した自己発行 manifest」
  も検証済み事実なので、コマンドがエラー終了しても join される —
  「どのタイミングで commit するか」という設計問題自体が消える
- M1-A5 のマージ意味論: ディスク merge とプロセス内 merge が同一の
  join 演算になり、`>=` 後勝ちの重複実装(監査で見つけた 3 経路の
  不整合の温床)が構造的に消える。プロセス間ロック(read-join-write
  の原子性)は依然必要 — join が「何を書くか」を、ロックが
  「安全に書く」を担う分離

コスト: §6.3 床節の書き直しが案 3-A の追記より大きい。ただし
保証内容は「案 3-A + M1-A4 / A5 修正」の合成と同一であり、
新しい保証は発明しない(定義の一般化のみ)。

改訂推奨(第 2 次): 案 3-D を仕様の形とし、実装は M1-A3 → A4 →
A5 の順で段階的に join へ寄せる。案 3-A 単体より、将来の
「この操作は床に書くべきか」という裁定の再発を止められる点で
上位互換。

#### さらなる検討(2026-08-19 第 3 次)— 保存形の追記専用化

案 3-D が受け入れたままの前提: join の意味論を定めても、保存形が
「単一ファイルの read-modify-write」である限り、プロセス間ロックが
**証拠保全のクリティカルパス**に残る(ロック実装のバグ = 証拠喪失の
再発点)。これを崩す:

**案 3-E: 保存形を append-only 観測ログ + 導出 join にする**

- 床ファイルを「最新状態のスナップショット(更新 = 全体の
  読み・merge・書き戻し)」から「**検証済み観測の追記専用ログ**
  (1 観測 = 1 行)」へ置き換え、床 = ログを fold した join として
  **導出**する
- 追記は O_APPEND でオフセット競合が排除され、1 行単位の write は
  ローカル FS で実用上交錯しない(破損末尾行は fold が無視 —
  自己回復)。並行プロセスの観測は**両方ログに残る** — 同座標・
  異 hash の 2 観測は fold 時に typed conflict として顕在化する。
  **上書きによる証拠喪失が「禁止」から「表現不能」になる**
- read-modify-write がクリティカルパスから消えるため、プロセス間
  ロックはコンパクション(まれ・非クリティカル)だけに縮む。
  ロックが取れなければ追記を続ければよい(fail-safe = ログが
  伸びるだけで、証拠は失われない)
- 先例との整合: メンバーシップチェーンも監査ログも append-only —
  「証拠を運ぶ構造は追記専用」という maruhi の既存パターンの
  3 例目になる
- 実装形の選択肢: JSONL(可読・診断容易・非機密ローカル状態の
  透明性)を第一候補、`bun:sqlite`(CLI は Bun 固有 API 可 —
  CLAUDE.md の禁止はサーバーのみ。追加依存ゼロで WAL が並行を
  実証済みに解く)を Windows の追記意味論が問題になった場合の
  代替とする

最終推奨(第 3 次): 意味論 = 案 3-D(単調 join)、保存形 = 案 3-E
(append-only ログ)。3-D 単体との差は「join を正しく実装する」
から「join 以外を書けなくする」への格上げであり、M1-A5 の根本原因
(RMW の競合)をロックの正しさに依存せずに消す。

#### 第 4 次検討(2026-08-19)— 記録タイミングの規律とコンパクション

検討して棄却した案:

- ログ行の自己ハッシュ連鎖(ローカル改竄・切り詰めの検出):
  ローカル書き込み権限を持つ攻撃者は CLI バイナリ自体を差し替え
  られるため脅威モデル外(床は非機密ローカル状態)— 過剰工学として
  棄却
- 床のサーバー側保管・チェーン化: 前者はサーバー不信と矛盾、
  後者は M2(checkpoint)/ M4(gossip)の領分そのもの — 範囲外

採用する昇格 — 3-E が受け入れたままの前提「記録は使用の後」を崩す:

**案 3-E′: journal-before-release(WAL 規律)**

- 観測の追記(journal)を、**値・DEK の解放、床検査の合格判定の使用、
  成功報告のすべてに先行**させる規律を仕様に置く
- 追記が安価(3-E)だから初めて置ける規律であり、「検証したのに
  記録前にクラッシュ・中断した」窓が閉じる — 記録漏れの失敗方向が
  「観測が残りすぎる」(安全側)に固定される
- 現行の pull 経路は概ねこの順序(検証 → 床 → 復号)だが、規律と
  して明文化されておらず、rotate・エラー終了経路(M1-A4)では
  成立していない — 明文化により M1-A4 の「どこでコミットするか」が
  規律から機械的に導出される

コンパクション方針(2026-08-19 pullfrog レビュー反映 — checkpoint
は §6.2 の起草のみで未実装、かつ本修正群は M2 へ広げないため、
M1 の暫定方式を規定する):

- **M1 の暫定方式**: サイズ閾値(行数 / バイト数 — 起草値は実装で
  決める)を超えたら、ロック下で「現在の fold 結果のスナップショット
  行 + それ以降の観測」へ書き直す。**同座標 conflict の証拠行は
  切り詰め対象にしない**(証拠は fold で消えない)。ロックが取れ
  なければ追記を続ける(fail-safe — 成長は次回コンパクションまで
  先送りされるだけで、証拠は失われない)
- **M2 到達後**: 基準を「検証済み checkpoint 以下の観測」へ移行し、
  チェーンが恒久保持する基準へローカルログの成長を接続する
- 規模感: 床は 1 プロジェクト 1 ログ・1 観測 = 数行程度であり、
  暫定方式で実用上十分に有界

**最終推奨(確定): 意味論 = 3-D、保存形 = 3-E、記録規律 = 3-E′、
コンパクション = checkpoint 基準連動**。第 4 次で構造の変更は
不要と確認 — 残余(初回クライアント・使い捨て CI の床不在)は
設計どおり M2 / M4 の領分。

**3-E を採る場合の読み替え(実装ブリーフの一意化 — 2026-08-19
pullfrog レビュー反映)**: §3 M1-A5 の修正案 1 / 2 / 6(プロセス間
ロック下の read-modify-write・lock 失敗の fail-open 禁止)と固定
テスト「lock 保持プロセス異常終了後の復旧」は、**追記 + fold 前提へ
置き換わる** — ロックはコンパクションのみ、取得失敗は追記継続
(fail-open ではない: 追記は証拠を失わないので「床なしへの
fail-open」に相当する状態が生じない)。§3 の同座標 typed conflict
(修正案 3 / 4)と再検査(修正案 5)は fold 側の規則としてそのまま
生きる。§6 PR-F2 の分割 3 は「floor 保存形の追記専用化 + fold」と
読み替える。3-E を採らない場合のみ §3 の記述が原文どおり生きる。

### 裁定不要と確認できたもの

- M1-A1: CRYPTO_SPEC §4.3 検証規則 (1) が「prev 連鎖(床がある場合)」
  を既に要求している — 適合実装
- M1-A6 のうち非複合メタ操作の strict-at-head 化:
  AUTH_SPEC §12-5 (4) の適合実装(上記裁定 2 の注記)
- M1-A4 / A5 / B1 / B2 / T1 / T2: CLI 実装・テストの範囲。
  A5 の同座標不一致の拒否は床規則 (b)(同一版・異 hash = 分岐の証拠)
  の要求どおりで、意味論の変更ではない

## 8. 修正完了までの運用ガード

コード修正前に守ること:

1. **旧サーバーへ新 CLI の create / `--init-manifest` を実行しない**
2. 更新順は server → 全環境 init → CI / CLI
3. 同一プロジェクトへ複数 CLI を並行実行しない
4. env create / 新規変数作成後は full pull を行い、床を確立する
   (これは honest server 運用上の緩和であり、コード修正の代替ではない)
5. rotate が応答消失・post-accept failure を報告したら、
   接続復旧後に full pull と再実行で状態を確認する
6. 非複合 API 経由で manifestVersion 1 を初期化しない。
   文書化済みの `env rotate --init-manifest` だけを使う

## 9. Definition of Done

修正群の完了条件:

- M1-A1〜A6 の各固定テストがある
- M1-B1 / B2 が API / CLI テストで固定される
- legacy init の DEK commitment を CLI が実検証する
- crypto ベクターを変更した PR は Node / Bun / workerd / Browser 全通過
- server の全メタ操作 API:
  - create / rename / delete variable
  - rename environment
  - create / rotate composite
  - environment delete cascade
  の回帰なし
- metadata-only / value pull / lease のマニフェスト検証が同水準
  (同水準の範囲 = 署名・digest・epoch 整合・欠落拒否。prev 連鎖は
  床を持つ経路のみ — M1-A1 の lease 適用外の注記と整合)
- 真の 2-process floor test が通る
- 裁定 1 のテストは対象サーバー構成ごとに分ける(2026-08-19
  pullfrog レビュー反映):
  - strict 導入後のサーバー: 未知フィールドを含む複合 payload を
    decode 段で拒否する(strict 拒否のテスト)
  - strict 未導入の旧サーバー: 受理後照合が「保存されていない
    マニフェスト」を検出し、CLI が床を前進させず失敗する
    (受理後照合のテスト。不整合状態の発生自体の防止は §8 運用
    ガード 1 / 2 と session-28 §2-2 の更新順が担う — 1-C は
    rotate ではチェーン追記後の検出になるため)
- `bun run check` 全緑
- crypto 変更に人間レビューが付く

## 10. 別チャット開始用の指示

別チャットでは、最初に本ノートと次を読む:

- `docs/notes/session-27.md` §5-1 / §13-2 / §13-5 / §14 / §16
- `docs/notes/session-28.md`
- `docs/CRYPTO_SPEC.md` §4.3 / §6.3 / §6.4
- `docs/AUTH_SPEC.md` §12-2 / §12-4 / §12-5 / §12-7 / §12-8
- 本ノート `docs/notes/session-31.md`

開始時の依頼文:

> session-31 の PR-M1 マージ後監査を読み、推奨分割に従って修正する。
> まず対象 finding の再現テストを失敗させる。§7 の裁定対象
> (strict 受理 + 成功定義の昇格 / 複合束縛〔2-F・2-E・2-D の
> はしごから所有者が選ぶ — 特に 2-F はチェーン re-genesis を伴う〕/
> 床の単調 join + append-only 保存形 + journal-before-release)は
> 各裁定の**最終推奨(確定)**を基に仕様書の改訂を先に起草し、
> Status 行と PR 本文の「要裁定」で所有者裁定を仰いでから実装する。
> `packages/crypto` 変更はベクター先行・人間レビュー必須。
> 隣接 cleanup や M2〜M4 へ広げない。

## 11. 既知の非保証との線引き

本ノートの修正対象ではないもの:

- 床を持たない初回クライアントへの内部整合した古いビュー
- 使い捨て CI の永続床不在
- チェーンヘッド自体の freshness
- manifestVersion gap > 1 の中間 predecessor 実在一致

これらは session-27 / session-28 に記録済みで、M2(checkpoint) /
M4(gossip)の担当である。

ただし、次は M2 / M4 へ先送りしない:

- 隣接版で床 predecessor が既知なのに prev を検査しない
- 自分が受理させたマニフェストを床へ記録しない
- 並行床 commit が既知の証拠を消す
- 旧サーバーが manifest を黙って捨てる
- H+1 例外が issuer と H+1 entry actor を束縛しない
