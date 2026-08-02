# セッション 08 メモ(レビュー裁定 3 件の実装 PR A = 非暗号層)

日付: 2026-08-02。前提: PR #18 マージ済み(変数値 API + 監査ログ。マージをもって
AUDIT_SPEC の所有者承認が確定)。ROADMAP 注記は先行の独立 PR #19。
スコープ: session-07.md §3.5 の所有者裁定済み 3 件のうち暗号層に触れない PR A
(1-B + 3-D + 2 の B/D)。2-E(ラップ登録への署名必須化)は次の PR B。

## 1. やったこと(コミット順 = 層順)

1. **spec**: AUTH_SPEC v0.4(§12-2 suite / §12-3 表 / §12-6 修復経路 /
   §12-8 行数上限 + Phase 2 予告)、AUDIT_SPEC v0.3(§3.3 に dek.registered /
   dek.deleted、Status の承認確定反映)。**CRYPTO_SPEC は無変更**(裁定どおり)
2. **api-schema**: WrappedDek / RecipientDek に suite(Literal `"maruhi/v1"`
   ピン留め)、DekWrapRef、DELETE .../deks(修復経路)、DekWrapNotFound(404)、
   DataLimitResource に dek-wrap-rows
3. **server(DO)**: do-schema の suite 列(DDL 直接変更 — 公開前・適用済み環境
   なし。新テーブルなしのため PROJECT_DO_TABLES 無変更)、policy の
   MAX_PROJECT_DEK_WRAP_ROWS、data-store の suite 読み書き + countWrapRows +
   deleteWrap、data-programs の行数上限結線 + dek 監査イベント +
   deleteDekWrapsProgram、chain-do の deleteDekWraps RPC
4. **server(HTTP)**: data-http の写像(dek-wrap-not-found → 404)と
   toValueInput の suite 経由、handlers-deks の remove(admin)、
   handlers-variables の suite を保存行から返す形へ
5. **テスト**: 7 件追加(311 件 green)。修復経路はクライアント復号までの
   ラウンドトリップで検証
6. **docs**: 本メモ

## 2. 裁定済み事項の実装形(細部のみ提案 — 確定条件 = PR レビュー承認)

裁定自体(session-07.md §3.5)は蒸し返さない。以下は「値・名前・粒度」の
実装細部の提案:

### 2-1. dek_wraps の累積行数上限値 = 1,000,000(1-B の細部)

現実的利用はメンバー × 環境 × エポックで数百〜数千行(例: 10 メンバー ×
10 環境 × 10 エポック = 1,000 行)。裁定の「現実的利用の 3 桁上」に従い
100 万行。1 行 ~300 バイト想定で最悪 ~300 MB と DO SQLite 10 GB に対して
安全側。検査は環境作成・DEK 登録が共有する ensureWrapSetAcceptable の
1 箇所に結線(挿入の全経路がここを通る)。「現在保存中の行数」であり
環境削除・ラップ削除で解放される。

### 2-2. dek.registered / dek.deleted の粒度 = 1 受信者 1 行(2-B の細部)

| 案 | 内容 | 評価 |
|---|---|---|
| A: 1 リクエスト 1 行(受信者リストを payload に) | 行数最小 | §5.1 の列構造(target_user_id は単値)と不整合。受信者での索引が payload の JSON 走査になる |
| **B: 1 受信者 1 行(採用)** | target_user_id に受信者 | (target_user_id, seq) 索引でそのまま引ける。§3.4 ミラーの 1 行 1 target と一様。登録は低頻度(ローテーション・メンバー追加時のみ)で、行数は §12-8 のラップ行数上限が束縛 |

イベント名は裁定済みの `dek.registered` に対し削除を `dek.deleted` とした
(領域.動詞の体系。var.created / var.deleted と同型)。環境作成時の
エポック 1 同梱分も dek.registered の対象(登録経路の一様性)。

### 2-3. ラップ削除のエンドポイント形(2-D の細部)

`DELETE /projects/:id/environments/:envId/deks` + body `{ wraps: [{epoch,
recipientUserId}] }`。(環境, エポック, 受信者) をパス断片にしない:
recipientUserId はチェーン合意規則上の自由文字列(1024 バイト以下)で、
パスセグメントとして安全に表現できないため。Effect HttpApi の DELETE は
payload を JSON ボディとして受ける(HttpMethod.hasBody は GET / HEAD /
OPTIONS / TRACE のみ false)。

受理規則の細部: 存在しないタプルは 404(黙って成功させると「消したつもりの
毒ラップが残る」)。列挙全件の存在検証 → 削除の順で、部分削除を作らない
(検証は permit 下、削除 + 監査は単一の同期タスク)。重複列挙は 422
duplicate-recipient(登録側と同じ語彙)。件数は登録側と同じ
MAX_DEK_WRAPS_PER_REQUEST で束縛。

### 2-4. 権限水準 = 環境削除と同水準(2-D の細部、タスク指示の起点どおり)

トークンスコープ admin × チェーン role admin 以上。削除は他メンバーの復号
可能性を奪う操作で、member 水準に置くと上書き禁止(§12-6)が塞いだ可用性
攻撃が削除経由で復活するため。

### 2-5. suite の読み出し(3-D の細部)

保存行の suite は読み出し時に `storedSuite`(未知値は defect)で literal 型
へ戻し、pull / 配布応答はワイヤのハードコードでなく**保存行の値**を返す
(CRYPTO_SPEC §2 設計原則 4 の「行が自身のスイートを持つ」を応答生成にも
貫く)。書き込みは Schema の Literal が強制するため、既知以外の値は
ストレージ破損としてしか到達しない。

## 3. ハマったこと・環境知見

- **Effect HttpApi の DELETE は payload = JSON ボディ**(上記 2-3)。
  GET のような urlParams 化は起きない
- **fallow の新規クローン警告 1 件は据え置き**: data-store.ts の
  listActiveVariables と latestVersions の骨格(Effect.sync + exec + map)が
  トークン列として一致する構造的な検出。suite 列の追加で変更行に入ったため
  表面化しただけで、抽出すると 2 つの異なるクエリがかえって不明瞭になる。
  warn 水準で check は green
- **audit.test.ts のイベント列アサーションは env.created 直後の
  dek.registered × メンバー数を織り込む**必要がある(`.at(-1)` で env.created
  を拾う既存テストは find に変更した)
- 100 万行のシード(WITH RECURSIVE の単文 INSERT)は workerd の DO SQLite で
  数秒で通る(スイート全体 +3 秒程度)。行数上限のプラミング検証は実生成で
  成立した(純関数 wrapRowsExceeded の単体検証も併置)

## 4. 既知の制約・v1 許容

- dek.registered は v1 の要ローテーション検出(§4.1)に関与しない(候補集合は
  全メンバー × 全環境)。環境スコープ role(CRYPTO_SPEC 未決 #11)導入時の
  証跡として記録する(AUDIT_SPEC §3.3 の注記)
- DO ストレージ総量ガード(databaseSize 閾値 = 裁定の F)は §12-8 に
  Phase 2 予告として注記のみ(実装なし)
- 削除 → 再登録の間、当該受信者は当該エポックを復号できない(修復の性質上
  不可避。削除者 = admin が再登録の完了まで責任を持つ運用)

## 5. 次セッションへの申し送り

- **PR B(2-E: ラップ登録への署名必須化)**: CRYPTO_SPEC 改訂 → テスト
  ベクター先行 → packages/crypto の人間レビューの順を厳守。署名対象に本 PR の
  suite が入る(だから PR A が先)。裁定事項の一覧は session-07.md §3.5
- 本 PR で WrappedDek のワイヤに suite が入ったため、**CLI / Web 実装は
  suite を必ず運ぶ**(クライアント生成側も SUITE_ID を使う)
- 修復経路の UI / CLI 表示: 「削除 → 再登録が完了するまで対象受信者は復号
  不能」の明示が必要(Web ダッシュボード実装時)
- session-07.md §5 の申し送り(CLI の 409 リトライループ、クライアント同期の
  §6.3 検査、リカバリーブロブのレート制限等)は未着手のまま有効
