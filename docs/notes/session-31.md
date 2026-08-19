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

### M1-A6 [中] H+1 エポック例外の適用範囲と actor 束縛

該当:

- `packages/crypto/src/internal.package/manifest-verify.ts`
  - `epochIntegrityReason`
- `packages/crypto/src/internal.package/chain-history.ts`
- `apps/server/src/verify-manifest.ts`
  - `acceptManifestForMetaOp`

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
3. floor file のプロセス間直列化

### PR-F3: H+1 epoch mode と issuer 束縛

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

**改訂推奨: 案 1-E を主防衛として仕様原則化し(公開前の全面適用)、
案 1-C(受理後照合)を防衛多層として維持、案 1-A は UX 向上の
任意追加(後続でよい)へ格下げする**。1-D の「新設スキーマから」を
「公開前の今、全面適用」へ強めた形であり、fail-closed を
プロトコル協調からデプロイ成果物の構造へ移す。仕様改訂の面も
AUTH_SPEC §4(新エンドポイント面)から §12 の受理原則 1 項へ縮む。

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

**改訂推奨: 案 2-A の趣旨(例外の適用範囲の限定 + issuer 束縛)を
案 2-D の形で仕様化する**。仕様文言は「例外は検証済みアンカーの
提示によってのみ有効化される。既定は厳密」とする — モード名の
列挙より規範として強い。

- なお **AUTH_SPEC §12-5 (4) は現行文言が既に「rotate 複合の同梱分」に
  例外を限定している** — 非複合メタ操作の strict-at-head 化は
  適合修正であり裁定不要。裁定対象は CRYPTO_SPEC 側の
  クライアント検証規則の明文化と actor / op 束縛の追加のみ
- `packages/crypto` 変更のため人間レビューも必須(§3 M1-A6)

### 裁定 3(PR-F2 / M1-A3): 床確立契機の拡張

問題: CRYPTO_SPEC §6.3 のローカル床は記録契機を「最後に成功した
pull(検証込み)」と定義しており、`env create → 新規変数 push` の
流れでは環境床が一度も確立しない。

案:

- **案 3-A: 記録契機を「検証成功したすべての配布・受理確認」へ
  一般化し、環境水準の部分床を明文化する**
  - metadata-only pull は環境水準(chain head / エポック基準 /
    envMeta / manifest)のみコミットし、**値を読んでいない変数の
    値床は作らない**(捏造しない)。env create / rotate は受理を
    チェーン / 配布で確認した後に自己発行分を記録する
  - 明文化の核心は規則 (c) の基準の再定義: 「値床の有無に依らず、
    検証済みチェーン導出エポックの最新観測(メタのみ同期を含む)」。
    論証は現行と同一 — その観測以降に受理される正規 push は当時の
    現エポック以上でしか起きないため、基準は値の取得と独立に健全
    (むしろ観測頻度が上がる分、強くなる)
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
- 規則 (c) の基準 = join 済みエポック観測の最大値(出所を問わない)
  — 案 3-A の再定義と同値だが、定義から自動的に従う

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

**改訂推奨: 案 3-D を仕様の形とし、実装は M1-A3 → A4 → A5 の順で
段階的に join へ寄せる**。案 3-A 単体より、将来の「この操作は床に
書くべきか」という裁定の再発を止められる点で上位互換。

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
- 真の 2-process floor test が通る
- 旧サーバー(strict 未導入)への新 CLI 複合が黙って部分受理されない
  (§7 裁定 1 — strict 拒否のテスト + 受理後照合のテスト)
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
> (strict 受理の仕様原則化 / H+1 例外のアンカー形の明文化 /
> 床の単調 join 再定義)は各裁定の**改訂推奨**(上位互換案)を基に
> 仕様書の改訂を先に起草し、Status 行と PR 本文の「要裁定」で
> 所有者裁定を仰いでから実装する。`packages/crypto` 変更は
> ベクター先行・人間レビュー必須。隣接 cleanup や M2〜M4 へ広げない。

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
