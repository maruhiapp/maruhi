# セッション 15 メモ(名前真正性の実装 — セッション 12 仕様の実装 PR-3)

日付: 2026-08-04。前提: PR #30(実装 PR-2 = 値真正性。squash merge `9b9fec1`)が
祖先であることを確認して開始。
スコープ: session-12.md §9 の **PR-3 = メタデータステートメント(案 D)**。承認済み
CRYPTO_SPEC §4.2 に従い、変数・環境の署名付きメタデータステートメント(作成・
改名・削除)と認証済み名前解決を、ベクター先行 → crypto/core → api-schema →
server → CLI の層順でコミット。

## 1. やったこと

1. **テストベクター先行**(実装より先の独立コミット。人間レビュー対象):
   - `metadata-signature.json` 新規(session-12 §8-2): chain-entries.json の正規
     12 エントリチェーンを参照(cross-file の先例)。正例 9 件は「作成 → rename →
     削除」の prev 連鎖(削除は直前 active 名を保持)・環境版(複合同梱の宣言
     ヘッド = 追記前ヘッド・削除のみ admin 水準)・削除済み author の在籍中
     ヘッド・**`var-meta-head-before-env-create` = positive**(エポックアンカー
     不在 = 環境の存在を検査しない意図された非対称 — §14.3-5 / AUTH_SPEC §12-4)
     を固定
   - 改竄・移植系 negative 15 件(tampered-status = 無署名の削除偽造の遮断、
     nfc-variant = byte-exact 署名の固定、cross-kind-transplant = var / env
     ドメイン分離を含む)と検証規則系 negative 11 件(ヘッド 2 種・在籍・鍵束縛・
     role 水準差 `env-delete-role-insufficient`・prev 形 / 連鎖・
     `revive-after-delete`)。`rename_fork`(同一 metaVersion の分岐 = 両方 verify
     成功の equivocation 証拠)と `name_swap`(名前入替は署名失敗)は専用セクション
     (session-14 §5 の教訓 — negative の形にすると誤実装を検出できない)
   - verify_reference.mjs に独立検証を追加(全 425 検査 PASS)。既存 8 ベクター
     ファイルは oxfmt 適用後 byte-identical(git diff で機械的に確認)
2. **crypto**: `meta-sign.ts`(var-meta-sig / env-meta-sig の LP 正規化・
   signMetaStatement / verifyMetaStatementSignature / computeMetaSignedBytesHash)、
   `meta-verify.ts`(`verifyDistributedMetaStatement` — 裁定 A どおり PR-2 の
   verifyDistributedValue の同型で ChainHistoryIndex を再利用。機構の二重実装
   なし)。`MetaInvalidReason`(10 種)+ `MetaStatementInvalid` kind を新設し、
   core は `CryptoMetaStatementInvalidError` へ完全写像
3. **api-schema**: `VariableMetaStatement` / `EnvironmentMetaStatement`(リクエスト
   形はライフサイクルで narrow: 作成 = metaVersion 1・active・prev 空 / rename =
   active / 削除 = deleted)+ 配布専用 Distributed*(author 情報)。変数作成 =
   v1 値 + ステートメント同梱(裸の variableId / name を廃止)、rename / 削除に
   ステートメント、複合環境作成の `name` を置換。**名前を返す全応答を改訂**
   (EnvironmentSummary / EnvironmentPull / PulledVariable + `deletedVariables`)。
   422 `MetaStatementRejected`(値署名と共有の 3 語彙)/ 409
   `MetaVersionConflict`(最新番号のみ)/ 422 `NameNotNfc`
4. **server**: `variable_meta_statements` / `environment_meta_statements`
   (NOT NULL 生 DDL — §4 参照)、`acceptMetaStatement`(上限 → CAS →
   predecessor → 署名検証)を rename / 削除 4 経路で共有、NFC 検査(検査のみ・
   正規化しない)、削除ステートメントの name 保持検査(byte-exact)、複合作成の
   宣言ヘッド = 追記前ヘッドの厳密一致 + 追記前履歴での検証、削除ステートメント・
   削除済み環境 tombstone の配布継続、audit 5 種への author 鍵 FP
5. **CLI**: pull の全検証をステートメントへ拡張(環境・active・tombstone。
   future head は PR-2 の有界再同期を流用)、名前解決の検証経由必須化(NFC
   正規化キー + byte-exact・同名 active 重複 = 解決拒否)、push 新規作成の
   ステートメント著者署名同梱、winnerRegression のメタ同型拡張(metaVersion
   後退・同一 metaVersion の signed bytes 相違 = 拒否)、env create の複合 CAS
   再試行で**エントリとステートメントの両方を再署名**、非 NFC 配布の警告
6. **テスト**: crypto 4 実行環境のベクター駆動(metadata-signature チェック追加)
   + server 193 / CLI 127(§7 参照)
7. **docs**: 本メモ

## 2. 裁定の細部(複数案比較 → 推奨で仮進行。確定条件 = PR レビュー承認)

### 2-1. MetaInvalidReason は Value と別語彙(タスク裁定 A の実装形)

crypto 層の理由コードは `author-*` 前綴りの独立語彙(10 種)にした。
ValueInvalidReason の流用は「writer」の語がメタの意味論(author)と乖離し、
`epoch-not-current-at-head` / `epoch-regressed` の 2 種が構造的に不能値として
残るため。ワイヤは仕様どおり 3 語彙(session-12 §6-7)へサーバーが写像する
(`META_REJECT_REASONS` — Record 型の網羅を静的検査)。

### 2-2. 検証側の deleted 意味論: predecessor が deleted なら後続は全拒否

§4.2 の「deleted 後の再 active 化は禁止」を、predecessor 付き検証では
「deleted の後続ステートメントは status を問わず拒否(`revived-after-delete`)」
として実装した(deleted → deleted の重ね書きにも正当なユースケースがなく、
tombstone は終端)。署名側は結合違反(metaVersion 1 ⇔ prev 空、metaVersion 1 =
active)を InvalidInput で拒否する(value-sign と同じ非対称 — 検証側は「有効
署名 + 規則違反」の wire を理由コード付きで拒否する必要がある)。

### 2-3. リクエスト Schema のライフサイクル narrow(仮裁定)

作成 = `metaVersion: Literal(1)`・`status: Literal("active")`・`prev: Literal("")`、
rename = active・metaVersion ≥ 2・prev 64hex、削除 = deleted・同左、を**ワイヤ
Schema で固定**した(「作成なのに deleted」等はサーバー検査でなく 400)。配布形は
全ライフサイクルの union。代替(単一 Schema + サーバー検査)はワイヤが緩くなる
だけで利点がない。この結果、変数作成への `MetaVersionConflict` は実質到達不能
だが、CAS の契約としてエンドポイントに宣言した(DO の防衛 CAS の写像先 +
並行 rename 競合の受け皿 — CLI は名前から再解決する)。

### 2-4. 削除ステートメントの配布チャネル(仮裁定)

「保存・配布し続ける」(§12-4/-5)の具体化として、(a) 一括 pull に
`deletedVariables`(削除済み変数の tombstone ステートメント列 — 暗号文は削除済み
なので値なし)を追加、(b) 環境一覧は削除済み環境も最新 deleted ステートメント
付きで列挙する形にした。クライアントは tombstone も検証し、同一 variableId の
active / deleted 併置(無断復活の運搬形)を拒否する。環境削除時の**配下の変数
ステートメントは削除**する(環境 ID はチェーン合意規則で再利用不能のため、
変数側 tombstone に検出材料としての残存価値がない — 環境自身の deleted
ステートメントが検出材料)。

### 2-5. 削除ステートメントの name 保持はサーバーが byte-exact で強制

`statement.name !== 保存済み現行名` の削除は 422 `PayloadMismatch`(field =
"name")。保存済み名は受理時に NFC 検査済みなので、削除側の独立 NFC 検査は
不要(等値がより強い)。

### 2-6. meta-versions 上限(仮裁定 — §12-8 の表にない受理ポリシー追加)

rename のステートメント行に「バージョン数 / 変数」と同値(1,000)の上限を
適用した(`meta-versions` resource)。ステートメント行は §12-8 のどの上限にも
束縛されず、rename 連打で無制限に積めたため(受理ポリシーであり合意規則では
ない — セルフホストでの引き上げは合意を破らない)。仕様表への追記は PR レビュー
承認後に AUTH_SPEC 側で行う想定。
**削除(status deleted)は上限の対象外**(§8 レビュー②③ major の修正):
tombstone は連鎖の終端で追加行は高々 1 行であり、削除まで遮断すると上限到達
リソースがどの role でも恒久的に削除不能になる(§12-8 の「削除で解放される」
原則と衝突し、remove エンドポイントの wire 契約 — `DataLimitExceededError`
未宣言 — にも違反する)。判定は保存済み状態(latest + 1 > 上限)基準
(`metaVersionsExceeded` — stale な申告 metaVersion を limit-exceeded と
誤報しない)。

### 2-7. 複合作成の宣言ヘッドは厳密一致で検査

§12-4 の「同梱ステートメントの宣言ヘッドは追記前の現ヘッド(= 同梱エントリの
prev と同一)とし」を、存在検査でなく**等値検査**(hash + seq とも)で実装した
(不一致 = 422 `PayloadMismatch` field "statementChainHead")。存在検査のみだと
「古い実在ヘッドの宣言」が通り、実装間で受理範囲が割れる(仕様文の「とし」を
規範として読む)。ヘッド CAS(親ヘッド不一致)が先に判定されるため、正当な
再試行フローは 409 → 両方再署名 → 200 のまま。

## 3. DDL・ストレージ(裁定 E)

Project DO SQLite に生 DDL・NOT NULL で追加(D1 / Drizzle / migration は不変):

| テーブル / 列 | 内容 |
|---|---|
| `variable_meta_statements` | (environment_id, variable_id, meta_version) PK。suite / name / status / prev_meta_sig_hash_hex / 宣言ヘッド(hash + seq)/ signature_hex / **サーバー再計算** signed_bytes_hash_hex(prev 検査・409 再試行の材料。配布しない)/ author_user_id + author_key_fingerprint(受理時点のチェーン導出)/ created_at |
| `environment_meta_statements` | 同上から variable_id を除いた形((environment_id, meta_version) PK) |
| `variables.latest_meta_version` / `environments.latest_meta_version` | 最新ステートメントの導出キャッシュ(metaVersion CAS・配布 join 用。name 列も同様に最新ステートメントの写し) |

signed bytes 本体・公開鍵は保存しない(座標とチェーンから再構成できる)。
backfill・nullable 遷移は作らない(公開前・適用済み環境なし)。
**古いローカル dev の `.wrangler/state` は本ブランチで動かす前に破棄が必要**
(session-08 §3 / session-13 / session-14 と同じ注意 — 旧スキーマの environments /
variables 行は latest_meta_version 列を持たず、新テーブル 2 つも
`CREATE TABLE IF NOT EXISTS` では既存 DB に不足列を足せない)。

配布は保存済みステートメント + author をそのまま返し、現メンバー集合から
再導出しない(削除済み author の過去ステートメントを当時の鍵で検証可能に保つ —
統合テストで固定)。audit は author の鍵 FP のみを写し、署名・signed bytes・
hash は載せない(AUDIT_SPEC §3.3)。環境削除のカスケード var.deleted は個別
ステートメントを持たないため、env 削除ステートメントの author FP を写す
(「FP = 署名の証跡」の意味論 — この削除を認可した署名は env 側)。

## 4. 既知の制約・v1 許容(本 PR が保証**しない**もの)

- **メタの前進注入は v1 未検出**(§14.3-5 — 最重要の正直な記録): メタ
  ステートメントはエポックアンカーを持たず(§4.2)、「member 以上の在籍区間」を
  チェーン履歴上に持つ鍵の保持者 + サーバーは、在籍区間内の宣言ヘッドで
  **実最新の次の metaVersion** の偽ステートメント(帰属付き)を署名・連鎖検証を
  通る形で注入できる。値署名のエポック単調性 + 床規則 (c) に相当する検出は
  構造的に存在せず、**床(PR-4)を導入しても検出されない**。v1 は fork 証拠化
  (prev 連鎖の分岐 = 否認不能な証拠)まで。閉包は Phase 2 の環境マニフェスト /
  チェックポイント(CRYPTO_SPEC 未決 #12)・ヘッドゴシップの責務。
  ベクター `var-meta-head-before-env-create`(positive)と本 PR の検証実装が
  epoch 検査を**持たない**ことがこの非対称の意図的な固定である —
  「検出済み」と誤認するテスト・実装を置いていない
- **latest-only**: pull は predecessor を持たず、メタの prev 実在一致・
  revive-after-delete は配布時には検査できない(形の検査のみ。サーバー受理と
  predecessor 付き検証 — 409 手順 — では検査する)。rollback / omission の
  永続検出は PR-4 のローカル床(メタは metaVersion の床 — 前進注入は上記の
  とおり床でも閉じない)
- CLI に rename / delete コマンドは追加していない(タスク裁定 F)。ステート
  メントの著者署名は作成経路のみで、rename / 削除のサーバー受理は統合テストが
  検証する
- 実行制御系変数名 denylist(session-11)は防衛層として維持し、検証済み name に
  適用される(名前の真正性が入っても、正規 member が悪意の名前を署名する経路 —
  G9 — は残るため)
- gossip / checkpoint / manifest / rotate CLI / チェーン操作 CLI /
  remove+rotate 複合化 / DO total-size guard / session-11 後続 PR / 変数名の
  秘匿は本 PR に含めない(タスク指定のスコープ外)

## 5. ハマったこと・環境知見

- **「名前の運搬」を 1 本化すると壊れるテストが最多**: 裸 `name` の廃止
  (EnvironmentSummary / PulledVariable / 作成ペイロード)は server 84 / CLI 127
  テストの fixture をほぼ全て触る。fixture 側に「最新ステートメント + author の
  記録」(varStatements / envStatements の Map)を持たせ、rename / 削除の prev
  連鎖をテストヘルパで自動化する形に寄せた
- **CLI mock の pull 応答はステートメントの宣言ヘッドを genesis(seq 1)にすると
  全ビューで成立する**: genesis の entry hash = projectId はどの延長ビューにも
  実在し、owner は seq 1 から member 以上。future-head 系テスト(短いチェーン →
  再同期)でもステートメント側が意図せず future にならない
- **audit の期待列はカスケード削除の位置で 1 箇所ずれる**: 環境削除は
  「残存変数の var.deleted(env author FP)→ env.deleted」の順で書くため、
  変数を先に個別削除したテストではライフサイクル末尾が 5 行になる(ヘルパで
  event 名と FP の対で固定)
- **fallow の audit ゲートは changed files 基準**: rename / 削除の 4 プログラムが
  「上限 → CAS → predecessor → 署名」の同型 4 連になり dupes / complexity で
  ゲートに落ちた。`acceptMetaStatement` への抽出で解消(テスト支援の cli / server
  クローン群は session-11 裁定済みの独立 PR の領分のままベースライン警告に留まる)
- **`unicodedata.normalize`(Python)と `String.prototype.normalize`(JS)の
  NFC は一致する**: nfc-variant ベクターは Python で NFD を生成し、JS 側
  (verify ツール・実装・テスト)の normalize("NFC") 照合と突き合わせて固定した

## 6. 申し送り

- **PR-4(CLI ローカル床)**: values.ts が返す metaVersion /
  metaSignedBytesHashHex が床の記録材料になる(値側の signedBytesHashHex /
  version / epoch と同じ立て付け)。**メタの床は巻き戻し検出のみで前進注入は
  閉じない**(§4 のとおり)ことを床の文書にも明記すること
- **AUTH_SPEC §12-8 の表への `meta-versions` 追記**(§2-6 の仮裁定が承認された
  場合): 「metaVersion 行数 / 変数(環境)= 1,000(status deleted は対象外)」を
  受理ポリシー表に追加する仕様同期 PR を推奨
- **AUTH_SPEC §12-4 のカスケード対象の明文化**(レビュー③ minor): 環境削除の
  カスケード対象列挙(「配下の変数・バージョン・ラップ済み DEK」)に「変数メタ
  ステートメント」を明記する改訂を人間に提案する(根拠 = 環境 ID のチェーン
  再利用不能。§2-4 の裁定の仕様側固定)
- **crypto の防御的検査の一貫性(独立 PR 候補 — レビュー① minor / ③ nit)**:
  (a) `meta-sign.ts` / `value-sign.ts` の context 検査に projectId /
  environmentId の非空検査を追加する(LP により空でも符号化は無曖昧 = 脆弱性では
  ないが、他フィールドの検査水準と不揃い)。(b) `verify_reference.mjs` の署名
  フィールド順をベクター JSON 由来でなく仕様ハードコード + JSON との一致検査に
  する(chain-entries の `payload_field_order` も同型なので同時に)
- **テスト支援の共有抽出(session-11 §5 の裁定済み独立 PR)**: 本セッションで
  signMetaStatementAs / statementFor 系のクローンが cli / server 両側にさらに
  増えた(fallow dupes 8 グループ)。抽出時にベースラインごと解消する
- session-11 §5 の残り(公開設定エンドポイント / pull メタデータのみモード —
  実装時はメタのみ応答にも §4.2 ステートメント + 署名を同梱すること =
  session-12 §13)・チェーン追記系コマンド + remove_member の全環境 rotate
  (session-12 §10-7 の複合化検討込み)は未着手のまま有効

## 7. テスト結果

- vectors tools: `bun run generate`(既存 8 ファイル byte-identical)+
  `bun run verify` 全 425 検査 PASS(metadata-signature 追加分込み)
- `@maruhi/crypto`: node 460 / workerd 460 / browser 460 / Bun 459(vitest の
  集約 1 件差は従来どおり)— metadata-signature チェック追加
- server(vitest-pool-workers): 194 tests green(メタ受理検証 10 件を新設、
  既存 fixture をステートメント必須へ全面更新 — 公開前の意図的な wire 非互換。
  レビュー修正で上限到達時の削除受理テストを追加)
- CLI: 128 tests green(ステートメント配布時検証 9 件・push のメタ 409 手順
  4 件・複合 CAS 両方再署名の検査を追加。レビュー修正で隣接 prev 不一致の
  拒否テストを追加)
- `bun run check`(fmt / lint / typecheck / importlint / fallow / doctor / test)
  green(809 tests)

## 8. レビュー→修正ループ(PR 内。3 観点の並行レビュー → 修正)

実装完了後、独立の 3 観点レビュー(① セキュリティ・暗号 ② 正しさ・並行性・
fork ③ 仕様・ベクター・wire)を並行実施した。blocking 指摘なし。major 1 件
(②③ が独立に同一指摘)と minor 1 件をコードで修正し、残りは記録・申し送りで
決着した。

### 修正した指摘

- **[major / ②③] meta-versions 上限が削除ステートメントも遮断し、上限到達
  リソースが恒久的に削除不能**: latest_meta_version = 1,000 の変数・環境への
  削除(metaVersion 1,001)も `limit-exceeded` になり、以後どの role でも削除
  できない(member が 999 回 rename した環境が admin にも削除不能な active の
  まま残り、active 環境枠 100 を恒久占有できる)。さらに remove エンドポイント
  は `DataLimitExceededError` を宣言しないため応答は 500(wire 契約違反)。
  → `ensureMetaQuota` を **status deleted は対象外** + **保存済み状態
  (latest + 1)基準**に修正(§2-6 に裁定を追記)。上限到達状態をシードした
  削除受理テストと純関数 `metaVersionsExceeded` の判定テストで固定
- **[minor / ②] `winnerMetaRegression` に隣接 predecessor の prev 一致検査が
  ない**: 値側 `winnerValueRegression` は winner.version = known + 1 のとき
  prev と検証済み signed bytes hash の一致を検査する(PR-2 レビューループ由来)
  が、メタ側に同型検査がなく、隣接 metaVersion を保持する再試行セッション内で
  無償検出できる分岐連鎖を逃していた。→ `VerifiedPulledValue` に検証済み
  ステートメントの `prevMetaSigHashHex` を追加し、同型の隣接検査を実装。
  prev 不一致の後続ステートメント配布を拒否する CLI テストで固定

### 記録で決着した指摘(コード変更なし)

- [minor / ①] `meta-sign.ts` の projectId / environmentId 非空検査の欠落:
  LP により空でも符号化は無曖昧・サーバーは座標を自前再構成するため脆弱性では
  ない。PR-2 の `value-sign.ts` と同形のため、両方まとめて独立 PR で整備
  (§6 申し送り)
- [minor / ③] 環境削除カスケードでの変数ステートメント物理削除は AUTH_SPEC
  §12-4 の列挙にない実装裁定: 環境 ID のチェーン再利用不能により実害はない
  (§2-4)。仕様側の明文化を人間に提案(§6 申し送り)
- [nit / ②] `ensureMetaQuota` の判定基準: major 修正に同梱(状態基準へ変更)
- [nit / ②] 削除の name byte-exact 検査(422)が metaVersion CAS(409)より
  先に判定される: どちらも決定的な拒否でセキュリティ差はない。CLI に delete
  コマンドを足す際(裁定 F)に 409 駆動の再試行から競合が見えない点だけ留意
  (現順序 = 意図。name 検査は「ペイロードの形」の検査で CAS より手前の層)
- [nit / ②] `reresolveTarget` が検証済み floor を無比較で破棄する経路: 到達
  可能なのは create 試行のみで create には floor が存在せず、現行契約では
  不到達。エラー契約を広げる際に `winnerRegression` 適用を足すこと(PR-4 の
  床実装と同時が自然)
- [nit / ①] 変数作成への `MetaVersionConflict` 宣言が実質不到達である旨:
  `data-api.ts` の該当箇所に既存コメントで明記済み(§2-3)
- [nit / ③] `verify_reference.mjs` のフィールド順がベクター JSON 由来:
  chain-entries の既存パターンと同型。独立 PR で仕様ハードコード化(§6 申し送り)

### 再レビュー

修正 2 件はどちらも受理範囲を狭める・検査を増やす方向のみ(削除の quota 免除は
「上限による削除遮断」という欠陥の除去で、CAS・署名検証・prev 連鎖検査は不変)。
修正後に全品質ゲートを再実行して green を確認し、blocking / 新規重大指摘ゼロで
収束した。
