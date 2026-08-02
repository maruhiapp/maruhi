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
MAX_DEK_WRAPS_PER_REQUEST で束縛。**空列挙は 400**(レビューループ 1 で追加。
§4-2 参照)。

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
- **suite 列(NOT NULL)の DDL 直接変更により、main で作った `.wrangler/state`
  のローカル dev ストレージはこのブランチで動かす前に破棄が必要**
  (`CREATE TABLE IF NOT EXISTS` は既存テーブルを変更しない)。未リリースの
  前提では許容(session-07 裁定 10 のとおり migration 機構は見送り継続)。
  リリース後は同種の変更に ALTER 経路が必要 = 裁定 10 の再評価トリガー

## 3.5 レビュー→修正ループ(PR #20 内。3 観点の並行レビュー → 修正)

### ループ 1 の指摘と対応

3 観点(セキュリティ / 正しさ・並行性 / テスト・契約)とも実装欠陥の高・中は
ゼロ。採用・修正した指摘:

1. **空の `wraps: []` 削除が 204 no-op(3 観点が独立検出。契約観点は中)**:
   監査痕跡を一切残さない破壊系 API の呼び出し形になっており、§12-6 の
   「黙って成功させない」規律(不存在タプル 404)と緊張。仕様に「列挙は
   1 件以上(空列挙は 400)」を明記し、Schema の `isMinLength(1)` で拒否 +
   negative テスト化。登録側(`deks: []` の no-op)は main 由来・非破壊系の
   ため本 PR では触れない(揃えるなら独立 PR — 申し送り)
2. **「全ラップ削除後の再登録は初回登録として完全一致」の新規仕様文が
   未テスト(中)**: 全削除 → 部分再登録 422 recipient-missing → 完全集合
   204 → 復号のテストを追加
3. **削除エンドポイントの EnvironmentNotFound / 件数上限(dek-wraps-per-
   request)が未テスト(中)**: tombstone 環境への削除 404(ボディが
   environmentId であり DekWrapNotFound でないこと)と 10,001 件の 422 を
   テスト化(宣言済みエラーの到達可能性を全て固定)
4. **低**: dek.registered の actor_api_token_id 検証、拒否された削除が
   dek.deleted を 0 行に保つこと(検証/書き込み分離の対偶)をテストに追加

### 採用せず記録に留めた観察(対応不要と判断)

- **削除〜再登録の間に member が空きスロットへ毒ラップを再充填できる**
  (セキュリティ観点・情報): member は従来から空スロットへの毒登録が可能で
  新しい能力ではない(上書きは 409 のまま)。dek.registered が登録者を
  actor として記録するため帰属は追える。サーバー不信の帰属は PR B(2-E の
  ラップごとクライアント署名)が本線。§4 にも記載
- **fallow の構造クローン警告**(§3 のとおり据え置き)

### ループ 2(修正の再検証)

3 観点とも指摘ゼロを確認(セキュリティ = 空列挙 400 の Schema 強制と迂回路の
不在、正しさ = 追加テスト後も書き込み規律・permit 設計に変化なし、契約 =
削除エンドポイントの宣言エラー 6 種すべてに到達テストが存在)。
`bun run check` + `wrangler deploy --dry-run` green。

## 4. 既知の制約・v1 許容

- dek.registered は v1 の要ローテーション検出(§4.1)に関与しない(候補集合は
  全メンバー × 全環境)。環境スコープ role(CRYPTO_SPEC 未決 #11)導入時の
  証跡として記録する(AUDIT_SPEC §3.3 の注記)
- DO ストレージ総量ガード(databaseSize 閾値 = 裁定の F)は §12-8 に
  Phase 2 予告として注記のみ(実装なし)
- 削除 → 再登録の間、当該受信者は当該エポックを復号できず、空いたスロットは
  member 権限で再充填できる(空スロットへの登録は従来からの能力で、修復経路が
  新たに与えるものではない)。削除者 = admin が再登録の完了まで 1 セッションで
  責任を持つ運用とし、登録の帰属は dek.registered(将来は PR B の署名)で追う

## 5. 次セッションへの申し送り

- **PR B(2-E: ラップ登録への署名必須化)**: CRYPTO_SPEC 改訂 → テスト
  ベクター先行 → packages/crypto の人間レビューの順を厳守。署名対象に本 PR の
  suite が入る(だから PR A が先)。裁定事項の一覧は session-07.md §3.5
- 本 PR で WrappedDek のワイヤに suite が入ったため、**CLI / Web 実装は
  suite を必ず運ぶ**(クライアント生成側も SUITE_ID を使う)
- 修復経路の UI / CLI 表示: 「削除 → 再登録が完了するまで対象受信者は復号
  不能」の明示が必要(Web ダッシュボード実装時)
- 登録 API の空 `deks: []`(no-op 204)を削除側の「空列挙 400」と揃えるかは
  独立の軽微 PR で判断(main 由来・非破壊系のため本 PR では触れていない)
- session-07.md §5 の申し送り(CLI の 409 リトライループ、クライアント同期の
  §6.3 検査、リカバリーブロブのレート制限等)は未着手のまま有効
