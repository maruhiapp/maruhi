# セッション 14 メモ(値真正性の実装 — セッション 12 仕様の実装 PR-2)

日付: 2026-08-04。前提: PR #28(実装 PR-1 = DEK 真正性。merge `3250571`)と
PR #29(docs 同期 `808c61e`)が祖先であることを確認して開始。
スコープ: session-12.md §9 の **PR-2 = 値署名(案 A + C 最小核)**。承認済み
CRYPTO_SPEC §4.1 に従い、値の writer 署名・認可時点束縛・prev 連鎖・fork 証拠化を
ベクター先行 → crypto/core → api-schema → server → CLI の層順でコミット。

## 1. やったこと

1. **テストベクター先行**(実装より先にコミット。人間レビュー対象):
   - `value-signature.json` 新規(session-12 §8-1): chain-entries.json の正規
     12 エントリチェーンを参照(cross-file の先例)。ciphertext は
     `environment_deks` のダミー DEK による実 AES-GCM 暗号文(値署名 → §4 復号が
     一続きの実データ)。正例 6 件は §6.3 の inclusive 規約を境界で固定
     (create / rotate エントリ自身を宣言ヘッドとする push、削除済み writer の
     在籍中過去値、rotate 実行者の再暗号化 push = エポック単調 prev 連鎖)
   - 改竄・移植系 negative(元署名の Ed25519 失敗)14 件と、検証規則系 negative
     (**署名は有効**のまま `expected_reason` で拒否)12 件。ヘッド不一致の 2 種
     (`chain-head-mismatch` = 即時証拠 / `chain-head-future` = 再同期の入口)、
     tenure 跨ぎ(`tenure_extension` = 正規 12 + seq 13 新鍵 re-add の派生
     チェーン — chain-entries.json 本体は変更しない)、prev の形 / 連鎖 /
     エポック単調性を理由コードごと固定
   - `fork_same_version`: 同一座標への 2 有効署名 = equivocation の証拠化
   - `dek-wrap-signature.json` の description に欠落していた `signer_user_id` を
     追記(session-12 §13 の申し送り。`signed_fields_order` は変更なし)。他の
     既存ベクターは oxfmt 適用後 byte-identical を確認
2. **crypto**: `value-sign.ts`(LP 正規化・signValue / verifyValueSignature /
   computeValueSignedBytesHash)、`chain-history.ts` + `verifyChainWithHistory`
   (裁定 A の ChainHistoryIndex — §2 参照)、`value-verify.ts`
   (`verifyDistributedValue` = §6.3 の 1〜4・6 の複合検証)。
   `ValueInvalidReason` / `ValueInvalid` kind を新設し、core は
   `CryptoValueInvalidError` へ完全写像(kind 対応表の網羅を静的検査化)
3. **api-schema**: `EncryptedPayload` に署名ブロック(prevValueSigHashHex =
   ""|64 hex / chainHeadHashHex / chainHeadSeq ≥ 1 / signatureHex)、配布専用
   `DistributedEncryptedPayload`(writerUserId + writerKeyFingerprintHex)、
   `PulledVariable.value` を配布型へ。422 `ValueSignatureRejected`(3 理由)
4. **server**: `variable_versions` に NOT NULL 7 列を追加(§4 参照)、
   StateCache を state + 履歴索引の対へ、push / create(同梱 v1 も同一検証)の
   受理検証を CAS の直後・数量ポリシーの前に挿入(裁定 D の判定順)、pull は
   保存済み writer / 署名ブロックをそのまま配布、`var.created` /
   `var.version_pushed` に chain-derived writer FP(AUDIT_SPEC §3.3)
5. **CLI**: 復号前の全値検証(values.ts)、future head の有界再同期 + 延長検査
   (sync.ts の ensureExtensionOf)、push の prev 連鎖(検証済み latest の
   自計算 hash)・自分の user id + master sig 鍵での署名、409 VersionConflict の
   winner 再取得手順、EpochConflict の延長検査付き再同期
6. **テスト**: crypto 4 実行環境のベクター駆動(chain-history / value-signature
   チェック追加)+ server 181 / CLI 109(§7 参照)
7. **docs**: 本メモ

## 2. 裁定の細部(複数案比較 → 推奨で仮進行。確定条件 = PR レビュー承認)

### 2-1. ChainHistoryIndex は verifyChain のループ内で構築する(裁定 A の実装形)

| 案 | 評価 |
|---|---|
| **`verifyChainWithHistory` が検証ループと同時に索引を構築(採用)** | 索引は「検証済みチェーンからしか生まれない」ことが構成的に保証され、状態機械(role 遷移・エポック遷移)の意味論が verifyChain と 1 実装に揃う。エントリハッシュは検証ループが prev 連鎖のためにどのみち計算しており、記録は無償 |
| 独立の `buildChainHistoryIndex(entries)` | 未検証チェーンから索引を作れる誤用面が生まれ、role/tenure の導出ループが verifyChain と二重になる(将来の合意規則追加で意味論が割れる温床) |

索引の照会 API は最低限(裁定 A)に揃えた: `entryHashAt`(seq → hash)、
`memberStateAt`(inclusive 時点の role / 鍵束縛 / tenure 開始 seq — remove →
re-add は別 tenure)、`environmentStateAt`(作成済みか + 時点エポック)、
`sigKeyByFingerprint`(§6.3-1 の鍵選択 — 全 tenure 対象。ヘッド時点の束縛検査は
`memberStateAt` が別途行うため、tenure 跨ぎは「署名は検証 → 束縛不一致で拒否」の
順になる = 検査順(仮裁定 C)どおり署名壊れが先に判定される)。
timestamp は索引のどの照会にも使わない。CLI の既存 `keyHistory` は DEK ラップの
§5.1 検証(ヘッド束縛を持たない意味論)専用として残し、値検証には使わない。

### 2-2. 422 理由の写像(仮裁定 C — 確定条件 = PR レビュー承認)

仕様(session-12 §6-7)の 3 理由のみを wire に置き、crypto 層の詳細理由
(`ValueInvalidReason` 12 種)からサーバーが写像する(`toValueRejectReason`):

- `signature-invalid` ← valid-format の Ed25519 失敗のみ
- `chain-head-unknown` ← `chain-head-mismatch` / `chain-head-future`(サーバーに
  とって「自チェーンに存在しない seq」は同じ不在。再同期分岐はクライアント側の
  概念でサーバーには無い)
- `chain-head-state-mismatch` ← 残り全部(head 時点の在籍・鍵束縛・role・環境・
  エポック、prev の形 / 保存 predecessor との不一致、writer-unknown)

**代替案の比較**:

| 案 | 評価 |
|---|---|
| **3 理由 + 検査順 = 署名壊れ → unknown head → state mismatch(採用)** | 仕様の理由列挙と一致。prev 不一致が Ed25519 failure に潰れない(裁定 B)。クライアントは 3 理由とも「自分の組み立てか同期状態のバグ / サーバーとの視界差」として同じ復旧経路(再同期 → 再構築)に入るため、wire 粒度はこれで足りる |
| prev 不一致を `signature-invalid` に含める | 「署名自体は正しいが連鎖が違う」証拠情報を潰す。fork 証拠化(§14.2-5)のデバッグ性を損なうため不採用 |
| 4 つ目の理由(例: `prev-mismatch`)を追加 | wire 変更(理由語彙は API 契約)であり仕様の 3 理由列挙の改訂を要する。粒度が必要なら将来 PR で仕様改訂とセットで行う |

### 2-3. latest-only の限界の実装形(裁定 B)

`verifyDistributedValue` は predecessor 引数の有無で検査範囲が変わる:

- **常に検査**: 署名・ヘッド(2 種の区別)・宣言ヘッド時点の在籍 / 鍵束縛 /
  role・環境作成済み / エポック整合・座標(呼び出し側が期待座標で context を
  組む)・prev の**形**(version 1 = 空 / version > 1 = 64 hex —
  `prev-shape-mismatch`)
- **predecessor を渡された場合のみ**: prev の実在一致(`prev-hash-mismatch`)と
  エポック非減少(`epoch-regressed`)。渡されない場合に「検査済み」と偽らない

server は version > 1 で保存済み N-1 の signed_bytes hash を必ず渡す(CAS 通過後
なので必ず存在 — 欠落は defect)。CLI の pull は latest-only のため渡せない
(rollback / omission / 前進注入の永続検出は PR-4 のローカル床の領分 — §6 参照)。
push の 409 手順では「検証済み winner」が predecessor 相当の役割を果たす
(次 version の prev に自計算 hash を使う)。

なお署名側(`signValue`)は version ↔ prev の結合違反を InvalidInput で拒否する
(結合違反の署名を自分では作らない)が、検証側は「有効署名 + 規則違反」の wire
データを理由コード付きで拒否する必要があるため結合を検証規則に置く非対称がある
(ベクター `v1-nonempty-prev` / `v2-empty-prev` が固定)。

### 2-4. future head の扱い(裁定 G の実装形)

- `seq <= 自ヘッド` でハッシュ不一致 → 即時拒否(`chain-head-mismatch` —
  分岐または偽造の硬い証拠)
- `seq > 自ヘッド` → **1 回だけ**再同期(有界)。新スナップショットは
  syncProject の全体検証・genesis 一致に加えて **延長検査**
  (`ensureExtensionOf`: 新ヘッド ≥ 旧ヘッド かつ 旧 verified head の seq/hash が
  新スナップショット内で一致)を通す。その後 pull 応答の**全値**を新ビューで
  再検証し、なお future のままなら拒否
- EpochConflict の再同期も同じ延長検査を通す(サーバーの currentEpoch 申告を
  真実源にしない従来規律に加えて、別整合チェーンへの誘導も拒否)

### 2-5. server の判定順(裁定 D)

`Schema(400)→ 値サイズ(413)→ AAD 座標整合(422)→ token scope / チェーン
role / 存在(404 / 403)→ epoch / version CAS(409)→ 値署名(署名 → 宣言
head → head 時点状態 → predecessor = 422 の 3 理由)→ 数量ポリシー(422)→
原子書き込み`。既存の判定順に対して値署名は CAS と数量の間に**挿入のみ**。
宣言 head は現 head と同一でなくてよく(同じ epoch・tenure・role を満たす古い
head は受理 — ベクター positive が固定)、宣言 head seq の単調性・サーバー独自の
エポック単調比較は追加しない(「現エポックのみ受理 + rotate +1 + version CAS」の
帰結として構造的に単調 — AUTH_SPEC §12-5 の 2026-08-03 明確化のとおり)。
全 crypto await は検証 Effect 内で完了し、同期 SQL 書き込みフェーズに await を
挟まない(PR-1 と同じ規律)。不受理時は variable / version / latest / audit の
いずれも変更しない(テストで固定)。

versions-per-variable の数量上限テスト(latest_version の直接引き上げ)は、
検証順の変更(CAS → 値署名 → 数量)により predecessor 行の実在が前提になった
ため、上限直前の version 行をシードする形へ更新した(§12-8 の判定自体は不変)。

## 3. DDL・ストレージ(裁定 E)

`variable_versions` に NOT NULL で追加(Project DO SQLite の生 DDL 直接変更。
D1 / Drizzle / migration は触っていない):

| 列 | 内容 |
|---|---|
| `prev_value_sig_hash_hex` | 直前 version の value_signed_bytes の SHA-256(version 1 は空文字列) |
| `chain_head_hash_hex` / `chain_head_seq` | 宣言ヘッド(exact pair) |
| `signature_hex` | 値の書き込み署名(Ed25519) |
| `signed_bytes_hash_hex` | **サーバー再計算**の signed_bytes ハッシュ(次 version の prev 検査・409 再試行の検証材料。**配布しない**) |
| `writer_user_id` / `writer_key_fingerprint` | 受理時点のチェーン導出 writer(user_id + 鍵 FP) |

signed bytes 本体・公開鍵は保存しない(座標とチェーンから再構成できる)。
backfill・nullable 遷移は作らない(公開前・適用済み環境なし)。
**古いローカル dev の `.wrangler/state` は本ブランチで動かす前に破棄が必要**
(session-08 §3 / session-13 と同じ注意 — 旧スキーマの variable_versions 行は
NOT NULL 列を持たず、`CREATE TABLE IF NOT EXISTS` は列を足さない)。

pull は保存済みの writer / 署名ブロックをそのまま返し、現メンバー集合から
再導出しない(削除済み writer の過去値を、チェーン履歴の当時の鍵で検証可能に
保つ — 統合テストで固定)。audit は chain-derived writer FP のみを写し、署名・
signed bytes・hash・nonce・暗号文・平文は載せない。rename / delete / env 系の
FP は PR-3(メタステートメント)の領分。

## 4. 既知の制約・v1 許容(本 PR が保証**しない**もの)

- **latest-only**: 初回同期・pull は predecessor を持たず、prev の実在一致・
  エポック非減少・rollback / omission / 前進注入の永続検出はできない(§14.3-3/5)。
  ローカル床は PR-4(session-12 §10-4 の裁定済み方針)
- **名前の真正性**: 名前 → variable_id の解決は PR-3(VariableMetaStatement /
  EnvironmentMetaStatement / NFC 検査 / 認証済み名前解決)まで非認証のまま。
  値署名は名前を認証しない(§4.1 の意味論)。実行制御系変数名 denylist
  (session-11)は防衛層として維持
- **fork の検出は証拠化まで**: 同一座標の 2 有効署名は否認不能な証拠になる
  (ベクター fork_same_version / CLI の 409 equivocation 拒否)が、split view の
  機構的検出は Phase 2 ヘッドゴシップ(§14.3-4)
- gossip / checkpoint / manifest / rotate CLI / チェーン操作 CLI /
  remove+rotate 複合化 / DO total-size guard / session-11 後続 PR は本 PR に
  含めない(タスク指定のスコープ外)

## 5. ハマったこと・環境知見

- **「versions 上限」テストの前提が判定順の変更で壊れる**: latest_version だけを
  SQL で引き上げる従来のショートカットは、「CAS 通過後の predecessor 行は必ず
  存在する」という新しい不変条件(欠落 = defect)と矛盾する。テスト側で上限直前の
  version 行(signed_bytes_hash_hex 込み)をシードして解消した — 実運用では CAS +
  行の個別削除なし(変数削除は全行削除)により不変条件は常に成立する
- **CLI の移植系テストの期待メッセージが「前段化」する**: 旧実装で復号失敗
  (AAD 不一致)まで進んでいた座標移植・暗号文差し替えは、値署名の座標整合
  (§6.3-5)が復号より前に落とすようになった。防御の意味論は同じで検出层が
  手前に移った(GCM 層の防衛は §4 のとおり独立に残る)
- **fork 証拠のテストは「両方 verify 成功」を先に固定する**: fork_same_version は
  negative でなく専用セクションにした。negative の形(must_fail)にすると
  「単体で落ちる」誤実装(例: prev 連鎖だけで分岐を検出したつもりになる)を
  検出できない
- **mock サーバーの旧 fixture は Schema 400 で全滅する**: EncryptedPayload の
  必須フィールド追加はワイヤ互換を壊す(公開前の意図的な非互換)。CLI テストの
  値 fixture は全件、writer・宣言ヘッド・prev を持つ署名付きへ更新した

## 6. 申し送り

- **PR-3(メタデータステートメント)**: metadata-signature.json →
  crypto(§4.2)→ api-schema(VariableMetaStatement / EnvironmentMetaStatement、
  環境一覧の name → ステートメント置換)→ server(メタ CAS・非 NFC 422・
  `env.created` 等への author FP)→ CLI(名前解決の検証経由化)。
  検証機構(宣言ヘッド・認可時点・prev 連鎖)は本 PR の
  ChainHistoryIndex / verifyDistributedValue の同型を再利用できる
- **PR-4(CLI ローカル床)**: 床の拡張規則 (c)(pull 時点エポック基準)まで
  含めて session-12 §12 ループ 2 の規範どおりに。values.ts が返す
  signedBytesHashHex / version / epoch が床の記録材料になる
- テスト支援の共有抽出(session-11 §5 の裁定済み独立 PR): 本セッションで
  signValueAs / encryptValueFor / valueHashOf 系のクローンが server / CLI 両側に
  増えた。抽出時に fallow dupes ベースラインも解消する(session-13 §3-6)
- 409 の再試行上限(5 回)・有界再同期(1 回)は実装定数。運用で不足が観測されたら
  設定化を検討する

## 7. テスト結果

- vectors tools: `bun run generate`(既存ベクター byte-identical)+
  `bun run verify` 全 PASS(value-signature 追加分込み)
- `@maruhi/crypto`: node 364 / workerd 364 / browser 364 / Bun 363(vitest の
  集約 1 件差は従来どおり)— chain-history / value-signature チェック追加
- server(vitest-pool-workers): 181 tests green(値署名の受理検証 8 件を新設、
  既存 fixture を値署名必須へ全面更新)
- CLI: 109 tests green(値署名検証・future head・409 winner 手順の negative 追加)
- `bun run check`(fmt / lint / typecheck / importlint / fallow / doctor / test)
  green

## 8. レビュー→修正ループ(PR 内。3 観点の並行レビュー → 修正)

### ループ 1 の指摘と対応

3 観点(セキュリティ・暗号 / 正しさ・並行性・fork / 仕様・ベクター・wire)を
並行実行。**[高] 1 = [中](セキュリティ観点)の同根**を独立検出:

1. **409 リトライがセッション内の検証済み latest からの後退を検出しない
   (正しさ [高]・セキュリティ [中] が同根を独立検出)**: `adoptConflictWinner`
   の整合検査が (a) `winner.version < currentVersion`(申告との不整合)と
   (b) `winner.version === known.version` のハッシュ相違(equivocation)のみで、
   `currentVersion < known.version` / `winner.version < known.version`
   (このセッションで §6.3 検証済みの latest からの後退)を拒否していなかった。
   悪意サーバーが巻き戻し申告 + 巻き戻しビュー(単体では全検証を通る古い正規値)を
   配布すると、正直 writer が**巻き戻しブランチの座標へ自分の署名で連鎖**して
   しまう(実史との same-coordinate fork 証拠の片割れを被害者自身に作らせる)。
   ローカル床(PR-4)は「セッションを跨ぐ永続検出」であり、**同一 push フロー内で
   `state.target.latest` を保持している以上、後退はゼロコストで検出できる**のが
   論点。→ 対応: `winnerInconsistency` を新設し、(i) `currentVersion < known.version`
   / `winner.version < known.version` = 巻き戻しの証拠として拒否、を追加。正直
   サーバーでは latest_version 単調(行の個別削除なし)のため誤拒否なし
2. **隣接 predecessor を持つ 409 経路で §6.3-6(prev 実在一致・エポック非減少)を
   検査していない(正しさ [中])**: 裁定 B は「pull は latest-only で predecessor
   を渡せない」だが、`winner.version === known.version + 1` のときクライアントは
   まさに直前 version の検証済みアンカーを保持している。→ 対応:
   `winnerInconsistency` に (ii) `winner.version === known.version + 1` のとき
   `winner.prevValueSigHashHex === known.signedBytesHashHex` と
   `winner.epoch >= known.epoch` を直接比較、を追加(VerifiedPulledValue に
   `prevValueSigHashHex` を追加)。fork した履歴への連鎖を無償で検出する
3. **自ビュー外の新規メンバーが書いた値が `writer-unknown` で即時拒否され、
   §6.3-2b の有界再同期に入らない(セキュリティ [低])**: 検査順(仮裁定 C:
   署名 → ヘッド)により鍵選択がヘッド束縛検査より先に走るため、宣言ヘッドが自
   ビューより先 **かつ** writer が未同期区間で追加された新規メンバーの場合、
   `chain-head-future` に到達する前に `writer-unknown` で落ちる。fail-closed だが
   §6.3-2b の「まず再同期」規範から外れ、悪意サーバーが警告疲れを誘発できる。→
   対応: `values.ts` の分類で「`writer-unknown` かつ `chainHeadSeq > 自ビューの
   headSeq`」を future と同じ有界再同期経路に入れる(再同期後も unknown なら拒否)。
   crypto 層の検査順は不変
4. **[低]・[情報] 群**: winner 欠落メッセージに並行削除の可能性を併記
   (正しさ [低])/ `dataEvent` の JSDoc を「クライアント署名を伴う操作
   (dek.registered / var.created / var.version_pushed)が署名者 FP を写す」へ更新
   (契約 [低] — 実装は仕様どおりで JSDoc のみ旧世代)/ サーバー側の
   `epoch-regressed` 分岐は CAS 通過後は到達不能だが共有検証器の無害な防衛線
   (正しさ [情報])/ create 経路の quota が CAS 前なのは「既存判定順への挿入
   のみ」で整合(正しさ [情報])/ tenure 跨ぎ拒否のサーバー統合テスト追加を推奨
   (セキュリティ [情報])

3 観点とも **blocking / 新規重大指摘は上記のみ**で、署名対象バイト列・検証規則・
サーバー受理・原子性・inclusive 境界・キャッシュ一貫性・ベクター仕様適合・wire
契約・規範仕様の無変更はいずれも「確認済み(問題なし)」と判定された。

### ループ 2(修正の再検証)

3 観点ともループ 1 の修正を**十分・新規ブロッキングなし**と判定(巻き戻し・
equivocation・prev 連鎖・新規メンバー再同期の各分岐が正直サーバーの不変条件 —
latest_version 単調性・delete = 404 / tombstone — の下で誤拒否を生まないことを
検証)。新規 [低] 2 件 + [情報] を検出・対応:

1. **非隣接 winner のエポック単調性が未検査(正しさ [低])**: §4.1 の単調性は
   推移的なので、`winner.version > known.version` でありさえすれば版番号ギャップ
   越しでも epoch 非減少を要求できる。旧実装は隣接(`known.version + 1`)のみで
   検査しており、版番号を +2 以上ずらすと削除済みメンバーの旧エポック署名注入が
   隣接検査を迂回できた。→ `winnerRegression` の epoch 検査を `winner.version >
   known.version` 全体へ持ち上げ(prev 実在一致は隣接のみ維持)。正直サーバーは
   受理順にエポック非減少のため誤拒否なし。版番号ギャップ越しの後退拒否テストを追加
2. **サーバー tenure 跨ぎテストの変異検出力(契約 [低])**: 新規テストの prev が
   ダミー 64hex だと、tenure 検査を変異で消しても `prev-hash-mismatch` が同じ
   ワイヤ理由(`chain-head-state-mismatch`)を返してテストが緑のまま通る。→
   prev を保存済み v1 の実 signed-bytes ハッシュにし、tenure 検査(head 時点状態 —
   prev 検査より前段)を単独の失敗要因に固定
3. [情報]: `winnerRegression` の二重 JSDoc の統合、`winnerInconsistency` の
   ドキュメント追記(いずれも分割時の残骸)

品質ゲート再実行: `bun run check` green(686 tests)、crypto 4 実行環境 green、
vectors verify 全 PASS。

### ループ 3(最終確認)

ループ 2 の 3 分岐(エポック単調性の持ち上げ・テスト検出力・ドキュメント)を
反映後、残余は [情報](エポック後退ブランチの専用負テスト = 追加済み、
「writer-unknown → 再同期後も unknown → 拒否」の負テスト = 有界性・延長検査の
既存負テストでカバー)のみで、ブロッキングゼロ。経過: ループ 1 = 高 1(2 観点
同根)・中 1・低 3・情報数件 → ループ 2 = 低 2・情報 → ループ 3 = ゼロ。
