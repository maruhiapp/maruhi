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

変更のない 104 ファイルは 08-22 / 08-24 の分析結果を据え置いている(今回のモデル実行で
再確認したわけではない)。

## 残課題(true-positive 5 件)

新規 4 件のうち **S1 と S3 は 08-24 修正のすぐ隣**で、同じ回避が対策範囲の 1 歩外に
残っていた形。S2 と S4 は既知の申し送り(ADR-0016 決定 7 の 申し送り / B9 の
「invite counter にも同型がある」)に対応する。

> **対応状況(2026-08-25)**: S1 と S3 は実装済み。未解消は **S2 / S4 / S5 の
> 3 件**。S2 と S5 は仕様・ADR の裁定が先、S4 は独立した並行性修正として残す。

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
  M2 の裁定とは、名前空間の所有者が違うので矛盾しない)。親環境の本物の
  `MARUHI_TOKEN` は従来どおり子へ継承される(denylist が縛るのは**保存された変数**の
  名前だけで、`{ ...process.env, ...extraEnv }` の継承側には触らない)ため、
  入れ子の `maruhi` の正当な利用は壊れない。回帰テストつき(修正を戻すと落ちる
  ことを確認済み)。

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

## 対象外(false-positive)

- `requestOrigin()` と Host header(3 回目の false-positive)
- `recoveryStatus` の `ensureKeyMaterialAccess` 欠落
- `maruhi run` が子プロセスへ maruhi API トークンを渡すこと(意図した設計)

## 推奨する着手順

1. ~~**S3**~~ — 対応済み(上記)。08-24 の R3 と同じクラスだったため同じ PR に含めた。
2. ~~**S1**~~ — 対応済み(上記)。R1 の名前空間検査を chain_seq の presence まで延長した。
3. **S4**。`recordFetch` / `login_failed_windows` に既に 2 つ前例があるので、
   3 つ目として同型に畳む。workerd の並行テストを先に置く。
4. **S5**、**S2**。どちらも仕様・ADR の裁定が先(AUDIT_SPEC §3.1 のバケット次元 /
   ADR-0016 決定 7 のリダイレクト軸)。実装から入らない。

## 作業規律(継続)

1. 1 論点または密接な同型だけを 1 PR にする。着手前に現行コード・仕様・ADR を読み、
   scanner の提案をそのまま実装しない。
2. Drizzle を触る S4 はリポジトリサービス境界を守る。スキーマ変更(カウンタ行の追加を
   含む)は drizzle migration の手順に従う。
3. 平文 secret・鍵素材・外部 provider ID をログや append-only 監査 actor に追加しない。
4. ユーザー向け文言は英語。完了時は固定 Bun(`.bun-version`)で `bun run check` を通す。
5. deepsec の再検証はローカルの Claude Max 認証が要る。
