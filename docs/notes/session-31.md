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
6. composite の actor / issuer 束縛と H+1 エポック例外の適用範囲が広すぎる

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
- `maruhi ci run` の lease 応答でも、隣接版の正しい prev は受理し、
  異なる prev は拒否(lease も `values.ts` の共有検証へ流れるため、
  適用面として明示的に固定する)

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
   - pullEpoch
   - environment meta `(version, hash)`
   - manifest `(version, epoch, hash)`
   - 値を読んでいない active variable の値床は作らない
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

### M1-A6 [中] composite actor / issuer 束縛と H+1 例外

該当:

- `apps/server/src/composite-programs.ts`
- `packages/crypto/src/internal.package/manifest-verify.ts`
  - `epochIntegrityReason`
- `packages/crypto/src/internal.package/chain-history.ts`

確認した 3 つのずれ:

1. server composite は chain entry actor と認証済み caller/member の一致を
   明示検査していない
2. H+1 エポック例外は「次エントリで epoch が確立した」ことだけを見て、
   manifest issuer と H+1 entry actor を比較しない
3. 同じ H+1 例外を非複合メタ操作の server 受理にも使うため、
   ordinary meta op が「宣言ヘッド H では未成立、H+1 で成立した epoch」を
   焼き込める

AUTH_SPEC §12-4 は chain actor / statement author / wrap signer /
manifest issuer = 呼び出し主体の厳密一致を要求する。
H+1 例外は create / rotate composite のためだけの例外である。

修正案:

1. server composite 入口で:
   - `entry.actor.userId === member.userId`
   - `entry.actor.keyFingerprintHex === member.keyFingerprintHex`
   を要求
2. `verifyDistributedEnvManifest` の epoch mode を明示:
   - `strict-at-head`(非複合 server meta op)
   - `allow-composite-next-entry`(create / rotate、配布検証)
3. `ChainHistoryIndex` に H+1 entry の actor / op / environment 座標を
   検証済み情報として照会する API を追加
4. H+1 例外を使う場合:
   - op が当該環境の create / rotate
   - issuer user / fingerprint が entry actor と一致
   を要求
5. 本修正は `packages/crypto` を変更するため人間レビュー必須

固定ベクター / server テスト:

- create / rotate: caller = entry actor = issuer → 受理
- entry actor と caller/issuer が異なる → 拒否
- ordinary meta op で H+1 epoch を使う → 拒否
- create / rotate 以外の H+1 entry では例外を使わない

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

### PR-F1: protocol capability と旧サーバー fail-closed

対象:

- M1-A2
- SELF_HOSTING / update 順序の公開文書

理由:

- 誤った更新順で新しい不整合状態を作らない入口の防御
- server / CLI のリリース前に先に閉じる

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
3. floor file のプロセス間直列化

### PR-F3: composite actor / epoch mode

対象:

- M1-A6
- M1-B1
- M1-T2 のうち H+1 / actor negative

注意:

- `packages/crypto` 変更あり
- ベクター先行
- 人間レビュー必須

### PR-F4: test hardening

対象:

- M1-T1
- M1-T2 の残り
- 全修正の cross-layer 回帰

## 7. 修正完了までの運用ガード

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

## 8. Definition of Done

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
- 真の 2-process floor test が通る
- 旧サーバー capability 欠落時に mutation 0 件
- `bun run check` 全緑
- crypto 変更に人間レビューが付く

## 9. 別チャット開始用の指示

別チャットでは、最初に本ノートと次を読む:

- `docs/notes/session-27.md` §5-1 / §13-2 / §13-5 / §14 / §16
- `docs/notes/session-28.md`
- `docs/CRYPTO_SPEC.md` §4.3 / §6.3 / §6.4
- `docs/AUTH_SPEC.md` §12-2 / §12-4 / §12-5 / §12-7 / §12-8
- 本ノート `docs/notes/session-31.md`

開始時の依頼文:

> session-31 の PR-M1 マージ後監査を読み、推奨分割に従って修正する。
> まず対象 finding の再現テストを失敗させ、仕様改訂が必要なら Status 行と
> PR 本文の「要裁定」を先に更新する。`packages/crypto` 変更は
> ベクター先行・人間レビュー必須。隣接 cleanup や M2〜M4 へ広げない。

## 10. 既知の非保証との線引き

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
- composite actor / issuer が一致しない
