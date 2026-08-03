# セッション 10 メモ(チェーンのメンバー鍵一意性 = セッション 09 裁定の案 B。暗号層 + 後片付け 2 件)

日付: 2026-08-03。前提: PR #21 マージ済み(2-E = DEK ラップ登録署名。マージをもって
CRYPTO_SPEC §5.1 — signer_user_id 束縛 = 案 A を含む — は所有者承認済み)。
スコープ: session-09.md §5 の申し送り「チェーン合意規則での鍵重複禁止(案 B)」の
**検討 → 結論に応じて実装**(2026-08-03 所有者判断「別 PR で検討」の実施。
**裁定済みは「検討する」まで — 導入可否を含む細部は複数案比較 → 推奨で仮進行し、
確定条件 = PR レビュー承認 = 合意規則改訂の所有者承認**)+ 独立 PR 2 件
(ROADMAP 注記、空 `deks: []` の決着)。

## 1. やったこと

### 主 PR(#22。出口 (a) = 合意規則として導入)

コミット順 = 層順(spec → ベクター先行 → 実装 → テスト → レビュー対応 → 本メモ):

1. **spec**: CRYPTO_SPEC v0.3-draft(§6.2 に「メンバー鍵の一意性」bullet 新設。
   §5.1 / AUTH_SPEC §12-6 の「add_member は鍵の重複を拒否しない」事実記述 5 箇所を
   更新 — §5.1 の規範 = 署名対象・検証規則は無変更)
2. **test-vectors**: chain-entries.json に authz negative 6 件(鍵一式流用・
   enc 片鍵・sig 片鍵・owner 鍵流用・順序固定 2 件)+ `valid_appends` セクション
   新設(許容境界の positive 2 件)を**実装より先にコミット**(初回コミットは
   3 件 + レビューループで 3 件・positive 2 件を追加)。生成は
   generate_reference.py 経由、verify_reference.mjs 全 PASS
3. **crypto**: chain-verify.ts に鍵索引(MutableChainState の
   memberEncPubs / memberSigPubs Set)と applyAddMember の検査を実装。
   ChainInvalidReason / api-schema の同期リストに `duplicate-member-key`
4. **server**: 実装変更なし(§6.4 は verifyChain 再実行のため自動追随)。
   data-programs.ts / dek-wrap-sign.ts の事実記述コメントのみ更新
5. **テスト**: 346 → 363 green(crypto / サーバー両層。消したテストの代替は §4)
6. **docs**: 本メモ

### 独立 PR 2 件(フルループ不要の後片付け)

- **#23 ROADMAP**: Phase 1「サーバー」行に PR #20 / #21 完了を追記 + Phase 0
  「監査ログのスキーマ設計」のチェック漏れ(AUDIT_SPEC は PR #18 で承認済み)修正
- **#24 空 `deks: []`**: 登録側を削除側と同じ 400(`Schema.isMinLength(1)`)に
  統一(§2-6)。session-08 §5 / session-09 §5 の申し送りを閉じた

## 2. 裁定事項の細部(複数案比較 → 推奨で仮進行。確定条件 = PR レビュー承認)

### 2-1. 導入可否 = 導入する

| 案 | 評価 |
|---|---|
| **導入(採用)** | (i) 「鍵 → 主体」の一意逆引きは §5.1 クライアント検証(signer FP 照合)・監査 UI(FP 表示)・§6.3 ラップ先一致検査が依存する性質で、不変条件化の価値が高い。(ii) 案 A が塞いだ帰属付け替えの根本原因の解消 = 防衛の多層化(§5.1 が実装バグ・将来改訂で破れてもチェーン層で成立しない)。(iii) CLI / Web(クライアント検証の実装)が世に出る前・適用済みチェーンなしの今が導入最安 |
| 見送り | 正当な鍵共有ユースケースの有無を検討した(session-09 §5 の論点): v1 は 1 ユーザー = 1 master keypair(デバイス鍵分離なし — §3)で、**ユーザー間**の鍵共有に正当ケースがない。同一人物の複数アカウントも各自が鍵を生成すれば足りる。デバイス鍵分離(未決事項 #2)は**ユーザー内**の複数鍵であり本規則と直交(導入時は §3 側の改訂を伴う)。見送りの利得なし |

### 2-2. 判定単位 = enc / sig 個別鍵(FP 単位ではない)

- FP(enc‖sig)一致のみだと片鍵流用のソック垢が通る。sig 単独流用 =「dek-wrap
  署名の検証が通る主体が複数」の多義性(FP 照合で一意にはなるが、暗号層の
  一意性が壊れている状態)。enc 単独流用 = 同一鍵への複数ラップ + 削除・
  ローテーション意味論の濁り(削除したはずの鍵が残存メンバーとして生き続ける)。
  いずれにも正当ユースケースがなく強い側を採用
- クロス種比較(新 enc == 既存 sig)は不要: X25519(HPKE)と Ed25519(署名検証)は
  用途が交わらず、バイト一致はエンコーディングが異なるため同一スカラーの流用すら
  意味しない(混同攻撃を構成できない)。レビューでも確認済み

### 2-3. 禁止範囲 = 現メンバー集合のみ(履歴全体ではない)

- **remove → 同一鍵 re-add(同一人物の復帰)は禁止しない**(session-09 §5 の
  線引きどおり)。現集合限定なら自然に成立し、例外則が不要
- **削除済みメンバーの鍵を別 user_id が再利用**も許容: admin / owner の
  「任意の公開鍵のメンバーを追加できる」権限内の行為と等価。FP がチェーンに残り
  機械的に追跡可能で、ラップの帰属は案 A(signer_user_id)が独立に防衛する
- 履歴全体禁止は「同一 user_id なら自分の過去鍵は再利用可」の例外則を要して
  複雑化し、追加防御(上記の別名再登場の禁止)が権限モデル上の利得にならない
- **既存フィクスチャへの拘束**: `authz-admin-adds-admin`(削除済み
  user-member-0002 の同一鍵 re-add を insufficient-role で固定)は、現集合限定 +
  検査順序 role 先行により期待理由不変。`chain-negative.ts` の「add_member
  duplicate」も流用元が削除済みのため無影響(duplicate-member のまま)

### 2-4. 規則の階層 = 合意規則(出口 (a))

| 案 | 評価 |
|---|---|
| **(a) 合意規則 §6.2(採用)** | クライアント(§6.3)にも拒否させたい性質(クライアントが不変条件として依存する)。`duplicate-member`(user_id 一意性)の鍵版として同格。§6.1 サイズ上限 vs §6.4 の書き分け先例 =「実装間で食い違うと分裂する意味論は合意規則、調整可能な資源保護は受理ポリシー」— 鍵重複は前者 |
| (b) 受理ポリシー §6.4 | セルフホストが無効化でき、クライアントは不変条件に依存できない(多層化の意義が半減)。合意を破らない利点はあるが本件の目的と不整合 |

- 公開前・適用済みチェーンなしの前提で後方互換の例外規定は持たない
  (「規則導入前に受理されたチェーンは存在しない」旨を §6.2 に明記)

### 2-5. 対象 op の網羅と理由コード

- genesis: メンバー集合が空で重複は構造上不可能。genesis 由来の owner 鍵は以後の
  add_member の比較対象になる(仕様に明記。レビューループ 1 の [高] でベクター化)
- change_role / remove_member / rotate_epoch: 鍵を登録しない → 対象外
- grant_server: サーバー enc 鍵とメンバー鍵の衝突は対象外(受信者クラス・FP 定義が
  別 — §9。owner 限定 + サーバー宛ラップは Phase 2 未実装)。**ただし grant_server
  自体は稼働済みの合意規則のため、Phase 2 で禁止する場合は grandfathering を要する
  ことを §6.2 に明記した**(レビューループ 1 の指摘。先送りコストの可視化)
- 理由コード: `duplicate-member-key`(`duplicate-member` の体系に整合)。検査順序
  role → duplicate-member → duplicate-member-key は理由コードごとベクターで固定

### 2-6. 空 `deks: []` の統一(独立 PR #24)= 揃える(登録側も 400)

- 空登録に意味のある呼び出しユースケースがない(初回登録の空集合は完全一致要件の
  422 recipient-missing が既に拒否、追記の空集合は純粋な無意味呼び出し)。
  silent no-op はクライアントバグ(空配列の送信を登録完了と誤認)を隠す。
  公開前でワイヤ契約変更のコストなし。削除側と同じ「黙って成功させない」規律
- 据え置き案(非破壊で実害なし)は非対称の説明コスト永続とバグ隠しの欠点で却下
- session-09 の現挙動固定テストは negative(400 + 監査行なし)へ改修。
  環境作成の同梱 deks は対象外(タスク指示どおり変更しない)

## 3. ハマったこと・環境知見

- **chain-entries.json への追記 = 全体再生成の整形差分**(session-09 §3 の知見の
  適用): 生成ツールの JSON 出力(Python `indent=2`)と oxfmt は配列折り返しが
  異なるが、**再生成 → 全ベクター JSON に oxfmt 適用**で既存 5 ファイルは無差分・
  chain-entries.json は追加行のみとなった。既存部分の byte-identical 再現は
  git diff で機械的に確認できる(PR に方針を明記)
- fallow の複雑度ゲート: テストのケース表(semanticCases)に `?? ""`
  フォールバックを足すと cyclomatic が閾値超過。ベクター固定鍵の欠落は
  フィクスチャ破損なので throw 型ヘルパ(keysOf。entryAt と同じ流儀)に寄せて解消
- 変異実験がレビューの主装備になった: 「テストが規則を拘束しているか」は
  green だけでは分からない。applyGenesis の索引登録 2 行を削除する変異が全テスト
  green のまま通る(= owner 鍵流用が未検査)ことをレビュアーが発見し([高])、
  ベクター追加後は同変異が crypto / サーバー両層で fail することを確認した。
  順序入替・remove 時の索引残留の変異も同様に複数テストで検出されることを実測済み
- `.wrangler/state` の破棄(session-09 §3 の DDL 直接変更対応)は本環境では不要
  だった(state 未生成)。ローカルに main の state が残っている環境では破棄が必要

## 4. 既存テストへの影響(消したテストの代替担保)

- `data.test.ts`「rejects third-party re-submission into a deleted slot, even via
  a duplicated chain key」(session-09)は鍵重複 add_member を前提にしていたため
  改修: (1) 第三者を**自前鍵の正規メンバー**に変えて署名者不一致(422
  signature-invalid)の検査を維持、(2) 鍵流用ソック垢の add_member 自体が 422
  duplicate-member-key になるチェーン層テストを新設。消えた「鍵一致・user_id
  不一致」の最強形は crypto 層の `transplant-signer` ベクター +「rejects wraps
  signed by someone other than the caller」テストが固定し続ける(§6.2 導入後は
  サーバー上で当該状態が成立不能のため、crypto 層が唯一かつ正しい固定場所)
- `chain-negative.ts` の「add_member duplicate」チェック: 「現メンバー集合のみ」
  案のため無影響(流用元が削除済み。期待 reason は duplicate-member のまま)
- そのほか横断確認済み: `data.test.ts` の recipientEncPubHex 流用(330 行・350 行
  付近)はラップ層のみでチェーンに鍵を載せないため無影響。membership / audit /
  auth テストに鍵重複の前提なし

## 5. 次セッションへの申し送り

- **CLI 実装(次セッションの本命)**: `maruhi run`(メモリ注入)/ push / pull /
  device flow / OS キーチェーン + §6.3 クライアント同期検査 + §5.1 配布時署名検証。
  チェーン検証は @maruhi/crypto の verifyChain をそのまま使う(§6.2 の鍵一意性を
  含む)。クライアントはラップ生成 → signDekWrap → 登録を一続きで行い、配布側は
  RecipientDek の signerUserId + signerKeyFingerprintHex をチェーン履歴と照合
  (session-09 §5 の申し送りの継続)
- **grant_server とメンバー鍵の衝突検査(Phase 2)**: §6.2 の注意書きどおり、
  導入するなら grandfathering 条項が必要(grant_server は稼働済みの合意規則で
  「既存チェーンなし」の論法が使えない)。grant_server のデータプレーン実装
  (サーバー宛ラップ)と同時に検討する
- **§6.3 の差分検証を実装する場合の注意**: 鍵索引(Set)は verifyChain の 1 回
  実行内のローカル状態。検証済み位置から再開する差分検証では、検証済み members
  Map から索引を再構築すること(規則が一意性を保証するため復元は自明 —
  レビューループ 1 の観察)
- **Phase 2 の F(DO ストレージ総量ガード)**: session-09 §5 の設計メモ
  (会計バイト予算 + databaseSize 警報の二段)は未着手のまま有効
- session-07.md §5 の申し送り(CLI の 409 リトライループ、リカバリーブロブの
  レート制限等)は未着手のまま有効
- 空 `deks: []` の申し送り(session-08 §5)は PR #24 で**クローズ**

## 6. レビュー→修正ループ(PR #22 内。3 観点の並行レビュー → 修正)

### ループ 1 の指摘と対応

1. **genesis 由来の owner 鍵流用が未検査(テスト [高])**: negative 3 件がすべて
   add_member 由来の鍵に偏り、applyGenesis の索引登録を削除する変異が 355 件
   green のまま通ることを変異実験で実証された。→ ベクター
   `authz-add-member-duplicate-owner-key` を追加(変異が fail になることを確認)
2. **role → 鍵の検査順序が未固定(テスト [低])**: → ベクター
   `authz-add-member-role-precedes-duplicate-key`(admin が鍵流用対象に role
   admin 付与 → insufficient-role)を追加
3. **「削除済み鍵の別 user_id 再利用は許容」の positive 欠落(正しさ・テスト
   [低])+ re-add positive がベクター層に不在(セキュリティ [低])**: →
   chain-entries.json に **`valid_appends` セクションを新設**(許容境界の
   positive 2 件。「履歴全体との重複禁止」の誤実装を落とす)。実装テストを
   ベクター駆動化し、re-add 後の索引再形成(seq 11 での再重複拒否)も追加
4. **README 規約 12 の順序依存の帰属が不正確(テスト [低])**:
   authz-admin-adds-admin は順序非依存(流用元が削除済み)である旨へ修正
5. **grant_server 衝突先送りの後方互換コスト未明記(セキュリティ [低])**:
   §6.2 に grandfathering の注意書きを追加(§2-5)

### ループ 2(修正の再検証)

3 観点とも **[高]・[中] の残指摘ゼロ**。レビュアーが変異実験を独立に再現
(genesis 索引削除 → 新ベクターのみ fail、順序入替 → 2 テスト fail、remove 時の
索引残留 → 3 テスト fail)。残った [低] 1・[情報] 2 も対応: verify_reference.mjs の
valid_appends 検査に payload_bytes / entry_bytes / entry_hash の一致検査を追加、
user_id → 鍵の順序もベクター化(`authz-add-member-duplicate-user-precedes-key`)、
ヘッダコメント更新。

### ループ 3(最終確認)

3 観点とも**指摘ゼロ**を確認(セキュリティ = 禁止側・許容側・順序の固定点が
ベクター層で完結 / 正しさ = 参照検証器の完全性まで閉じた / テスト・契約 =
5 点相互拘束〔仕様・生成ツール・ベクター・実装・両層テスト〕の完成)。経過:
ループ 1 = 高 1・低 5 → ループ 2 = 低 1・情報 2 → ループ 3 = ゼロ。
`bun run check`(363 件)+ `wrangler deploy --dry-run` + 4 実行環境の crypto
テスト全通過。以降は ready 化 → 所有者指示によるマージ(マージ = §6.2 合意規則
改訂の所有者承認)。
