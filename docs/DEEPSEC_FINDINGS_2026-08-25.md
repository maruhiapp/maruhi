# deepsec 残課題(2026-08-25 再検証)

`DEEPSEC_FINDINGS_2026-08-24.md` の 8 論点の修正を検証した run で残った / 新たに
出た true-positive。前文書はこの run でクローズ済み(7 論点 fixed、R4 のみ残存)。

## 位置づけ

- 対象: 追跡 117 ファイル。`process` は 08-24 の修正で変更された候補 13 ファイル
  (`--reinvestigate 2 --manifest`)、`revalidate` は同 13 ファイル上の全 26 finding
  を `--force` で再判定
- モデル: `claude-opus-5`、thinking `medium`、Claude Agent SDK(ローカル認証)
- run: `scan 20260825002713-ed6224238ec2c19a` /
  `process 20260825002935-0e1bfd164a1a9165` /
  `revalidate 20260825003446-4a6d6d6964b0c376`
- 費用: process $8.26、revalidate $3.18(合計 $11.44)
- 判定: fixed 13、false-positive 3、duplicate 5、**true-positive 5**

## 2026-08-27 S1 / S3 / S4 追加再検証

- 対象: S1 / S3 / S4 の実装候補 7 ファイル(manifest)。matcher 候補のある 6 ファイルを
  `--reinvestigate 3` で再調査し、同 manifest 上の 12 finding を `--force` で再検証
- モデル: `claude-opus-5`、thinking `medium`、Claude Agent SDK(ローカル認証)
- run: `scan 20260827132550-694fee0d3217c8cc` /
  `process 20260827132600-6cba472eba489f0d` /
  `revalidate 20260827133028-743b76363689b140`
- 費用: process $3.63、revalidate $1.24(合計 **$4.87**)
- 対象3件の帰結: **S1 / S3 / S4 はすべて `fixed`**
- process は新規2件(S7 / S8)を検出。加えて、前回 false-positive だった
  `maruhi run` の資格情報継承を S6 として true-positive(BUG)へ再判定
- 現在の未解消: **S2 / S5 / S6 / S7 / S8 の5件**

## 2026-08-27 S2 / S5〜S8 追加再検証

- 対象: 実装候補10ファイル(manifest)。matcher候補のある8ファイルを
  `--reinvestigate 4` で再調査し、同manifest上の26 findingを `--force` で再検証
- モデル: `claude-opus-5`、thinking `medium`、Claude Agent SDK(ローカル認証)
- run: `scan 20260827140524-349506fcf80b67f7` /
  `process 20260827140543-400e1c0d37c9c1bf` /
  `revalidate 20260827141220-055396ecda27491f`
- 費用: process $4.96、revalidate $2.90(合計 **$7.86**)
- 対象5件の帰結: **S2 / S5 / S6 / S7 / S8 はすべて `fixed`**
- process は新規3件(S9 / S10 / S11)を検出。S9 / S10 は同ブランチで実装済み、
  S11 はセルフホストのアカウント受入・project quota方針として別途裁定

## 2026-08-27 S9 / S10 追補と最終再検証

- 1回目: `scan 20260827142502-5f2e610abc385fdd` /
  `process 20260827142505-0b1b8b09e2b3f974` /
  `revalidate 20260827142831-98a1fb82adbb859f`
- 2回目: `scan 20260827143142-d939917e2ceb7dfc` /
  `process 20260827143144-8b605f1ef9c06c78` /
  `revalidate 20260827143508-61f94c1f58e5af7b`
- 追補修正後の最終revalidate: `20260827144100-13a228b53f0c0734`
- 費用: process $2.82、revalidate $3.03(合計 **$5.85**)
- S9 / S10 と追補の S12 / S13 はすべて `fixed`
- 最終reportのtrue-positiveは **S11 (MEDIUM) 1件のみ**

2026-08-25 の run で変更のない 104 ファイルは 08-22 / 08-24 の分析結果を据え置いている
(08-25 のモデル実行で再確認したわけではない)。

## 残課題(true-positive 5 件)

新規 4 件のうち **S1 と S3 は 08-24 修正のすぐ隣**で、同じ回避が対策範囲の 1 歩外に
残っていた形。S2 と S4 は既知の申し送り(ADR-0016 決定 7 の 申し送り / B9 の
「invite counter にも同型がある」)に対応する。

> **対応状況(2026-08-27)**: S1〜S10 / S12 / S13 は実装・deepsec再検証とも完了。
> 未実装は **S11 の1件**。

### S1. `chain_seq` が `chain.*` 外の行でも無ラベル表示される — BUG(新規)

- 場所: `apps/cli/src/audit.ts`(`trailerParts` / `renderListEvent` / `fetchAllMirrorRows`)
- slug: `other-trust-label-bypass` / confidence medium
- 問題: 信頼ラベルの計算(`renderListEvent`)と verify の取得(`fetchAllMirrorRows`)は
  どちらも**イベント名の前置**で分岐する一方、`trailerParts` は `chainSeq` を持つ
  **あらゆる行**に `chain_seq=N` を出す。`trust === null` のときはラベルなしの素の
  座標になる。`chainSeq` を正当に設定するのは `chainMirrorEvent` だけ(サーバーは
  echo するのみ)なので、`member.add` や `chainx.grant` のような名前で
  `chain_seq=7` を持つ行は**正直なサーバーでは存在し得ない** = 偽造の指標だが、
  CLI は普通の座標として黙って描画し、verify は名前空間の外なので 1 行も取得しない。
- 08-24 の R1 との関係: R1 は「名前空間の**内側**で写像に無い名前」を塞いだ。
  この指摘は同じ回避が**名前空間の 1 歩外**に残っている、というもの。
- 影響の範囲(再検証で縮小): verify の OK 文言は「chain entries 1..N ↔ chain.* mirror
  rows」と範囲を明示しているため文言としては嘘をつかない。悪意あるサーバー + 素の
  座標を検証済み provenance と読む運用者の両方が必要。BUG 相当。
- 推奨: ラベル付けの起点をイベント名の前置から **`chainSeq` の存在**へ移す。
  `chainSeq` があるのに trust を計算できない行は
  `(mirror=unverified — event name is outside the chain.* namespace)` を明示し、
  整合性違反として数える。verify 側でも `chain_seq` を持つ非 `chain.` 行を取得して
  偽造の証拠として報告する。
- **対応済み**(2026-08-25): 一覧の trust 判定は `chainSeq` の存在をイベント名より
  先に見る。名前空間外なら
  `mirror=unverified (chain_seq is invalid outside the chain.* namespace)` を明示し、
  警告 + exit 1 にする。`trailerParts` 自体にも trust が null の `chain_seq` を
  無ラベル表示しない fallback を置いた。D1 経路(invites / self)は正当な
  chain provenance を持たないため、同じ形を受け取ったら明示ラベル + exit 1。
  verify は従来の `eventPrefix=chain.` に加えて新しい
  `chainSeqPresent=true` フィルタを全ページ取得し、row_id で和集合にしてから
  名前空間外の claim を偽造として報告する。同じ row_id が 2 クエリ間で異なる内容を
  返した場合もサーバー応答の自己矛盾として中止する。非 admin の verify にも届くよう、
  `chain_seq IS NOT NULL` は AUDIT_SPEC §6 のクラス 1 とした(正直な書き手でこの列を
  設定するのは chain.* ミラーだけなので、正常なクラス 2 行は開示しない)。
  CLI の一覧 / verify / D1 表示と workerd の presence filter / reader 可視性に
  回帰テストを追加。
- **再検証**(2026-08-27): `fixed`。表示側は `chainSeq` の存在を名前より先に判定し、
  verify 側は `chain.` 名前空間と `chain_seq IS NOT NULL` の和集合を検査すること、
  非 chain 行を警告 + exit 1 にすることを確認した。追記境界も非 `chain.*` の
  `chain_seq` を defect として拒否する。

### S2. リカバリーコードの表示に TTY 検査がない — MEDIUM(新規)

- 場所: `apps/cli/src/recovery.ts`(`issueRecoveryCodeOp` / `recoverMasterKeyOp`)
- slug: `other-key-material-to-disk` / confidence medium
- 問題: 表示のゲートが `io.agentProfile().isAgent`(fail-open の deny-list)1 層だけで、
  256-bit のコードを stderr へ書く。stderr も stdout と同様にリダイレクト可能で、
  `maruhi key recovery 2> code.txt`、`> out 2>&1`、`script` / `tee`、両ストリームを
  捕捉する CI ランナーはいずれもコードをディスク・ビルドログへ永続化する。
  保存確認プロンプトは**表示の後**で、`promptLine` は非 TTY では
  `readPipedLine()` にフォールバックするため対話性を強制しない。
- 非対称性: 値表示(`showValues` → `ensureValueDisplayAllowed`)は「stdin と stdout の
  両方が端末」の fail-closed を一次境界に持つ。より機微な(master 秘密鍵を開く)
  リカバリーコードが deny-list 1 層、という向きの逆転になっている。
- 既知性: ADR-0016 決定 7 は recovery を**意図的に** deny-list に据え置いており、
  その申し送りが「未知のエージェント下では一次境界の保護を受けない」としてこの
  クラスを次の裁定候補に挙げている。したがって見落としではなく**繰り延べ**。
- 要判断: 「リダイレクトの軸」は ADR が実際には扱っていない別の懸念である。
  非 TTY の CI 発行を壊さずに TTY 検査を入れられるか(発行と表示を分けるか)を
  決めてから実装する。ADR-0016 の改訂として人間に提示すること。
- **対応済み**(2026-08-27): ADR-0016 決定 7 を改訂し、リカバリーコードの表示・入力は
  stdin / stdout / stderr の全てが TTY のときだけ許可する。既知 agent 判定は二次層。
  発行は recovery status / PUT より前、復元は blob GET より前に fail-closed し、
  `2>` を含む3チャネル各単独の非TTYテストで、コード表示・prompt・server到達が
  いずれもないことを固定。既知 agent で鍵生成後の発行を黙ってスキップする経路は、
  コードを表示しないため据え置いた。
- **再検証**(2026-08-27): `fixed`。発行・入力の両入口が3チャネルTTYを確認し、
  serverアクセスと鍵素材の剥がしより前に拒否することを確認した。

### S3. denylist が maruhi 自身の認証 env を覆っていない — MEDIUM(新規)

- 場所: `apps/cli/src/run.ts`(`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-hijack` / confidence medium
- 問題: `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN` が denylist に無い。変数名は
  write 権限を持つ共同メンバーが決められる平文メタデータなので、悪意あるメンバーが
  自分の PAT を値に持つ `MARUHI_TOKEN` を作れる。被害者が `maruhi run -- make deploy`
  を実行し、その makefile が `maruhi pull` を呼ぶ形(CI で非常に一般的)だと、
  `resolveSession` は env のトークンを**キーチェーンより先に**見るため、入れ子の
  `maruhi` が攻撃者として認証される。`MARUHI_TOKEN_ORIGIN` も攻撃者が設定できるので
  `sessionFromEnvToken` の origin 束縛も効かない。
- 影響: 入れ子の読み取りが攻撃者のプロジェクト値を返し、被害者のパイプラインが
  それを自分のシークレットとして扱う。入れ子の書き込みは攻撃者のアカウントへ入る。
- 推奨: `DENIED_ENV_PREFIXES` に `MARUHI_` を足す(最低でも `MARUHI_TOKEN` と
  `MARUHI_TOKEN_ORIGIN` を `DENIED_ENV_NAMES` へ)。既存の prefix 機構に乗る 1 行。
- **対応済み**(2026-08-25): `DENIED_ENV_PREFIXES` に `MARUHI_` を追加した。個別名の
  列挙ではなく包括 prefix を採ったのは、**maruhi 自身が予約する名前空間**であり
  巻き込む「正当な変数」が原理的に存在しない一方、個別名だと将来 `MARUHI_*` を
  増やしたときに同じ穴が再発するため(NODE_ / PYTHON_ / BUN_ の包括拒否を採らない
  M2 の裁定とは、名前空間の所有者が違うので矛盾しない)。この時点では親環境の本物の
  `MARUHI_TOKEN` の継承には触らなかった(後の S6 で除外)。回帰テストつき
  (修正を戻すと落ちることを確認済み)。
- **再検証**(2026-08-27): S3 本体は `fixed`。保存された変数が `MARUHI_*` を名乗って
  入れ子の maruhi を乗っ取る経路は閉じた。ただし親環境に本物の
  `MARUHI_TOKEN` がある場合の**継承そのもの**は別論点 S6 として true-positive。

### S4. invite の pending 上限・発行窓が check-then-act — BUG(新規)

- 場所: `apps/server/src/db.package/repos.ts`(`InviteRepo.create`)
- slug: `rate-limit-bypass` / confidence medium
- 問題: pending 件数と 1 時間窓の 2 つの admission control を素の SELECT で評価し、
  その後に無関係な `db.batch` で insert する。カウントは insert の WHERE に入って
  おらず、CAS も条件付き INSERT…SELECT もカウンタ行も無い。N 並行の POST は全部が
  同じ under-limit を観測して全部 insert するため、`MAX_PENDING_INVITES_PER_PROJECT`
  (100)と `INVITE_ISSUE_WINDOW_LIMIT`(30/h)を並行度ぶん超過できる。
- 既知性: JSDoc は「ベストエフォート」と書き、対等な例として recovery の取得計数を
  指しているが、**そちらは B9 で単一の条件付き UPDATE に直った**ので対等でなくなった。
- 影響の範囲: 実行には認証済みの project admin(または漏れた admin PAT)が必要で、
  そもそも 30 件/時は正当に発行できる。1 バーストぶんの上限超過に留まり、権限・
  機密の境界は越えない。BUG 相当。
- 推奨: `recordFetch` と同じ形に畳む。insert を `INSERT … SELECT` にして WHERE で
  両カウントを再評価し 0 行を拒否とするか、`login_failed_windows` と同型の
  per-project カウンタ行を 1 文の条件付き UPSERT + `RETURNING` で回す。
  `invite.created` は `acceptCas` / `revokeCas` と同じ `changes() = 1` ガードで
  同一 batch に残す。
- **対応済み**(2026-08-25): スキーマ・上限値・判定順は変えず、pending 件数と
  lookback 件数を同じ `INSERT … SELECT … WHERE` の相関サブクエリで再評価する。
  `RETURNING` が 1 行なら作成成功、0 行なら説明用に pending → lookback の仕様順で
  再読して型付き 429 を導出する。`invite.created` は直後の
  `changes() = 1` ガード付き INSERT…SELECT と同一 D1 batch に置き、作成の勝者と
  1:1 にした。pending 上限 / 発行窓を残り 1 枠にした状態で 8 並行 POST を送り、
  どちらも成功 1・拒否 7・保存件数が上限ちょうど・監査行 1 を workerd で固定。
  条件を一時的に外すと両テストが成功 8 になって失敗することも確認済み。
- **再検証**(2026-08-27): `fixed`。pending / lookback の両上限が単一の
  `INSERT … SELECT … WHERE` で再評価され、`RETURNING` と `changes() = 1` 監査が
  作成の勝者と一致することを確認した。

### S5. `auth.login_failed` の上限が `auth_method` 共有のまま — BUG(R4 の残存)

- 場所: `apps/server/src/db.package/audit.ts`(`appendLoginFailed`)
- slug: `other-audit-suppression` / confidence medium
- 状態: 08-24 の R4 で `auth_method` バケット化 + 抑制件数の可観測化を実装したが、
  **同一 method 内の被覆は残る**(実装時に「残る限界」として明記したとおり)。
  再検証はバケット化と 10 の冪マーカーの効果を認めた上で severity を MEDIUM → BUG
  に下げ、残余を true-positive として維持している。
- 残余の具体: 100 件/時の枠は method ごとにデプロイ全体で共有。R7 で入れた
  レート制限(callback 30/分・device exchange 10/分)は**バーストは抑えるが、
  単一 IP から 1 時間で 100 件に達すること自体は防げない**(OAuth 側は約 4 分)。
  枠が飽和すると同 method の標的型攻撃の個別行が落ちる。破壊されるのは行の存在
  ではなく**試行ごとの `reason`**(マーカーで量は残る。`auth.login_failed` は
  actor user_id を持たないため本人軸の読み取りには元から現れず、失われるのは
  運営者ビューの情報)。
- 要判断: 攻撃者が被害者と共有できない次元を与える。§1-2 の識別子規則に収まる案は
  (a) 解決済みアカウントに帰属できる失敗は `auth_method` + 内部 `user_id` で
  バケットし、解決前の失敗だけを共有枠に落とす、(b) 共有枠(小)と per-account 枠を
  別に持つ。最低でもマーカーに reason 別ヒストグラムを載せる。**発信元単位**の
  次元は AUDIT_SPEC §3.1 が明示的に否定しているので、この選択肢は取らない。
- **対応済み**(2026-08-27): 現行の失敗は認証前で target user_id を持たず、個別行が
  運ぶ分類は `auth_method` と `reason` だけなので、その直積を独立バケットにした。
  marker payload にも reason を載せ、ある理由の洪水が同じ method の別理由を失明
  させない。`state-mismatch` の枠を飽和させても `code-exchange-failed` が個別行として
  残り、抑制 marker は reason と count を運ぶ workerd テストを追加。IP / provider ID は
  counter key・監査 actor のどちらにも追加していない。
- **再検証**(2026-08-27): `fixed`。`auth_method + reason` のJSON keyで独立計数し、
  markerもreasonを運ぶため、別理由の洪水で試行分類が失われないことを確認した。

### S6. `maruhi run` が親環境の maruhi API token を子へ継承する — BUG(再判定)

- 場所: `apps/cli/src/live.ts`(`makeBunProcessRunner`) / `apps/cli/src/run.ts`
- slug: `other-credential-inheritance` / confidence high
- 状態: 2026-08-25 は false-positive としたが、08-27 の再検証で true-positive
  (MEDIUM → BUG)へ変更
- 問題: child env は `{ ...process.env, ...extraEnv }` で、keychain-less / CI の
  `MARUHI_TOKEN` と `MARUHI_TOKEN_ORIGIN` もそのまま渡る。S3 の `MARUHI_` denylist は
  **保存された変数がその名前を名乗ること**だけを防ぎ、親環境の継承には効かない。
  `maruhi run -- npm test` 配下の悪意ある依存は注入された値だけでなく、後からも使える
  PAT を読み出し、run 終了後も token scope 内の read / write を行える。
- 推奨: child 用の親環境コピーから maruhi の資格情報変数を除く。少なくとも
  `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN`、将来の auth 用 `MARUHI_*` も同じ境界で除外する。
- 要判断: 入れ子の `maruhi` を明示的にサポートするか。strip すると
  `maruhi run -- make deploy` 内で再び maruhi を呼ぶ既存ワークフローは認証を失うため、
  互換性と「子へ渡すのは消費対象の値だけ」という security boundary を先に裁定する。
- **対応済み**(2026-08-27): ADR-0016 に「子へ `MARUHI_*` を継承しない」を追加。
  `buildChildEnvironment` が親環境と extraEnv の両方から case-insensitive に
  `MARUHI_` prefix を除き、一般環境・注入値は維持する。keychain-less / CI の入れ子
  maruhi は親 PAT を暗黙利用せず、必要な maruhi 操作は run の外で行う線引き。
- **再検証**(2026-08-27): `fixed`。本番 `Bun.spawn` が filtered env を使い、親・
  extraEnvの両方から将来の `MARUHI_*` を含めて除外することを確認した。

### S7. API token のユーザー上限が check-then-act — BUG(新規)

- 場所: `apps/server/src/auth.package/token.ts`(`issueToken`) /
  `apps/server/src/db.package/repos.ts`(`countByUserExcludingName` /
  `replaceForUserAndName`)
- slug: `other-race-condition` / confidence high
- 問題: ユーザーの他名 token 数を SELECT し、上限 100 を比較した後、別の D1 round-trip
  で insert する。異なる token 名の並行 device exchange は全て同じ under-limit を
  観測して挿入でき、並行度ぶん上限を超える。`UNIQUE(user_id, name)` は名前が異なる
  ため効かない。S4 で invite 上限を直したのと同じ競合。
- 推奨: `replaceForUserAndName` の insert を
  `INSERT … SELECT … WHERE (count(user_id, name <> requested) < 100)` にし、
  `RETURNING` 0 行を `TokenLimitReachedError` へ写す。事前 count は拒否理由導出用に
  限定し、admission は単一文に持たせる。異名の並行発行テストを追加する。
- **対応済み**(2026-08-27): repo 内で「既存同名の原子的ローテーション → 新規名の
  条件付き `INSERT … SELECT … WHERE count < 100` → 同名競合時の再ローテーション」を
  実行し、サービス層の事前 count を削除。同名は上限到達時も許可し、実際に消える旧 id
  を `replacedTokenId` に載せる R6 の監査を維持した。残り1枠で異名8並行を送り、
  成功1・TokenLimit 7・保存100行・作成監査2行(初回 + 勝者)を固定。
- **再検証**(2026-08-27): `fixed`。quotaは新規INSERTの相関subqueryで評価され、
  service層に独立countが残っていないことを確認した。

### S8. `TokenRepo.revokeById` の DELETE に user 所有条件がない — BUG(新規)

- 場所: `apps/server/src/db.package/repos.ts`(`revokeById`)
- slug: `other-missing-ownership-predicate` / confidence medium
- 問題: `revokeById(id, userId, nowMs)` は userId を監査 actor にだけ使い、
  DELETE は token id だけで行う。現行の唯一の呼び出し元は提示 token を hash 解決した
  `record.id` / `record.userId` を渡すため**現在の exploit 経路はない**。ただし将来
  token id 指定の管理 API を足すと、別 user の token を削除して監査 actor は呼び出し
  user と誤記録する latent な認可欠落になる。
- 推奨: DELETE の WHERE を `id = ? AND user_id = ?` にする。既存の
  `RETURNING` + 0 行 early return により、非所有 id は監査行なしの no-op へ
  fail-closed でき、現行経路の挙動・コストは変わらない。
- **対応済み**(2026-08-27): DELETE を `id AND user_id` へ変更。別 userId で repo を
  直接呼ぶ回帰テストで、token が残り `auth.token_revoked` も増えないことを確認した。
- **再検証**(2026-08-27): `fixed`。非所有idはRETURNING 0行→監査なしのno-opになる。

### S9. invite linkのraw tokenをstdoutへ出し、リダイレクトで永続化できる — BUG(新規)

- 場所: `apps/cli/src/invite.ts`(`inviteCreateOp`)
- slug: `secrets-exposure` / confidence low
- 問題: 単回使用tokenを含むリンクをstdoutへ出すため、`maruhi invite create > file` や
  CI captureでcredentialがディスク・ログへ残る。従来は既知agentだけを拒否し、
  非TTY・未知harnessは通った。tokenは7日expiry + 受諾後FP確認があるため直接の
  membership bypassではないが、diskless不変条件には反する。
- **対応済み**(2026-08-27): ADR-0016 決定7を追加改訂し、invite link表示も
  stdin / stdout / stderrの3チャネルTTY境界へ移した。agent判定は二次層。
  3チャネル各単独の非TTYで発行POST前に拒否し、raw tokenが出力されないテストを追加。
- **再検証**(2026-08-27): `fixed`。stdout redirectを含む非TTYがHTTP発行前に
  fail-closedとなり、raw tokenを出力しないことを確認した。

### S10. env denylistにshell autoload / TLS trustの同型名が不足 — BUG(新規)

- 場所: `apps/cli/src/run.ts`(`DENIED_ENV_NAMES`)
- slug: `other-incomplete-denylist` / confidence medium
- 問題: 既に拒否する `BASH_ENV` / `ZDOTDIR` / `NODE_EXTRA_CA_CERTS` と同じクラスの
  `FPATH` / `KSH_ENV` / `SSL_CERT_FILE` / `SSL_CERT_DIR` / `CURL_CA_BUNDLE` /
  `REQUESTS_CA_BUNDLE` / `AWS_CA_BUNDLE` / `PYTHONUSERBASE` / `PYTHONWARNINGS` が
  未拒否。共同memberがautoload pathやTLS trust rootを差し替えられる。
- **対応済み**(2026-08-27): 上記9名を既知実行制御名として追加し、R3と同じ
  大文字小文字非区別の回帰テストへ含めた。変数名の暗号的束縛が根本策で、
  denylistがbest-effortである点は変わらない。`NPM_CONFIG_` は全体拒否せず、
  `USERCONFIG` / `GLOBALCONFIG` / `SCRIPT_SHELL` / `NODE_OPTIONS`等の実行制御キーだけを
  個別拒否する。registry credential用の `NPM_CONFIG__AUTH` / `_AUTHTOKEN` は許可する。
- **再検証**(2026-08-27): `fixed`。同じ再調査で追加の同型名がS13として出たため、
  そちらも同じdenylistに追補した。

### S11. セルフホストが任意GitHub accountを自動登録し、project作成に全体quotaがない — MEDIUM(新規)

- 場所: `apps/server/src/handlers-auth.ts`(`githubCallback` / `deviceExchange`) /
  project作成経路
- slug: `other-open-registration` / confidence medium
- 問題: GitHub検証後に無条件で `getOrCreateUser` を呼び、未知accountにもuser +
  personal orgを作る。device flowは`* × admin` PATも発行する。operator allowlist /
  signup invite / org制限がなく、登録userのproject数にも上限がないため、公開された
  self-hostへthrowaway GitHub accountで登録し、projectごとにDOとD1行を増やせる。
- 推奨: operator-controlled admission(`ALLOWED_GITHUB_USER_IDS`等、またはfirst-user後は
  signup invite必須)をauthのuser作成前にfail-closedで適用する。別途、user/org単位の
  project quotaとproject initのrate limitを設ける。
- 状態: **未実装**。セルフホストの初回owner作成・inviteeの認証前受入・既存deployの
  移行を同時に決めるproduct/auth方針であり、S2/S5〜S10の局所修正とは分ける。

### S12. invite listが未知idの発行pin照合を無言でスキップする — BUG(新規)

- 場所: `apps/cli/src/invite.ts`(`inviteListOp`)
- slug: `other-logic-bug` / confidence high
- 問題: serverがlocal issuance pinにないidを返すと `issuedPinOf` はundefinedとなり、
  role / token_hash照合を無言で飛ばす。別端末発行は正当なのでfailureにはできないが、
  「照合して成功」と「照合材料なし」が同じ表示になる。
- **対応・再検証済み**(2026-08-27): pinなしの各行に
  `The token_hash / role cross-check was not performed` と明示する。integrity failureには
  数えずexit 0を維持。最終revalidateで `fixed`。

### S13. denylistにfilesystem不要のruntime hookが不足 — MEDIUM(新規)

- 場所: `apps/cli/src/run.ts`(`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-injection-denylist-gap` / confidence medium
- 問題: `PYTHONBREAKPOINT` / `PYTHONEXECUTABLE` / `JDK_JAVA_OPTIONS` /
  `DOTNET_STARTUP_HOOKS` / `GEM_HOME` / `GEM_PATH` / `HOSTALIASES` と
  `CORECLR_*` / `COR_*` が未拒否。既に拒否する各runtime hookと同じクラス。
- **対応・再検証済み**(2026-08-27): 上記個別名と2prefixを追加し、
  case-insensitiveな回帰テストへ含めた。最終revalidateで `fixed`。

## 対象外(false-positive)

- `requestOrigin()` と Host header(3 回目の false-positive)
- `recoveryStatus` の `ensureKeyMaterialAccess` 欠落

## 推奨する着手順

1. ~~**S3**~~ — 対応済み(上記)。08-24 の R3 と同じクラスだったため同じ PR に含めた。
2. ~~**S1**~~ — 対応済み(上記)。R1 の名前空間検査を chain_seq の presence まで延長した。
3. ~~**S4**~~ — 対応済み(上記)。条件付き INSERT + changes() 監査に畳んだ。
4. ~~**S8**~~ — 対応済み。repo の所有条件 + 非所有 no-op テスト。
5. ~~**S7**~~ — 対応済み。条件付き発行 + 異名 token の並行テスト。
6. ~~**S6**~~ — 対応済み。子環境から `MARUHI_*` を除外。
7. ~~**S5 / S2**~~ — 対応済み。AUDIT_SPEC §3.1 / ADR-0016 決定 7 を改訂。
8. ~~**S9 / S10**~~ — 対応済み。invite linkのTTY境界 / denylist同型名を追加。
9. ~~**S12 / S13**~~ — 対応済み。pin照合なしの明示 / runtime hook denylist追補。
10. **S11**。operator admissionとproject quotaのproduct/auth方針を先に裁定する。

## 作業規律(継続)

1. 1 論点または密接な同型だけを 1 PR にする。着手前に現行コード・仕様・ADR を読み、
   scanner の提案をそのまま実装しない。
2. Drizzle を触る S7 / S8 はリポジトリサービス境界を守る。スキーマ変更が必要なら
   drizzle migration の手順に従う。
3. 平文 secret・鍵素材・外部 provider ID をログや append-only 監査 actor に追加しない。
4. ユーザー向け文言は英語。完了時は固定 Bun(`.bun-version`)で `bun run check` を通す。
5. deepsec の再検証はローカルの Claude Max 認証が要る。
