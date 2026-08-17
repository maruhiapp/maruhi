# セッション 25 メモ(Phase 2 Wave 2 A3 — CLI の CI モード + setup-maruhi action)

日付: 2026-08-17。前提: Wave 2 の A1(PR #63)/ A2(PR #65)/ リプレイ先着束縛
(PR #67)/ B1a(#68)/ B1b(#69)/ B2(#70)/ C1(#71)マージ済みの main。
スコープ: A3 = ワークロードリースの CI クライアント(`maruhi ci run`)+
リポジトリ内 setup-maruhi action。Wave 2 の最終ピースであり、ROADMAP Phase 2
「GitHub Actions 同期」の仕上げ。仕様は CRYPTO_SPEC §9.1 / AUTH_SPEC §14 /
session-24 §8 / セキュリティレビュー A-5 に従い、**本セッションで仕様変更はない**
(クライアント実装のみ。crypto 層・ワイヤ形・ベクターは不変)。

## 1. コマンド形: `maruhi ci run -- <cmd>`(新グループ `ci`)

検討した形と判断:

- **採用: `maruhi ci run`(グループ `ci` + サブコマンド `run`)**。CI モードは
  `run` の変種ではなく**前提構造がまるごと別**である: 認証 = OIDC のみ
  (maruhi トークン・キーチェーン・セッション文脈を一切使わない — AUTH_SPEC
  §14-1)、設定 = 明示フラグのみ(config ファイル非依存 — §2)、床・ピン =
  持たない(使い捨てランナー)、検証材料 = lease 応答に同梱(他 API を呼ばない
  — §14-2)。宣言(必須フラグの集合・`--audience` / `--anchor` の存在)も
  まるごと別になる
- **却下: `run --ci`**。1 つのフラグが「他のどのフラグが必須・禁止か」を反転
  させる形は、ADR-0016 決定 6 が入れ子サブコマンド化で廃止した「その操作に
  適用されないオプションの拒否機構」を引数層へ逆輸入する。宣言が分かれて
  いれば機構は要らない
- **却下: `lease run`**。「リース」はプロトコル語彙で、利用者の語彙は
  「CI で走らせる」。grant 側(管理者)の語彙に lease-policy が既に居るのとは
  対象ユーザーが違う
- グループにするのは、Phase 3 のエージェントリース(ROADMAP)や将来の
  ワークロード系コマンドが同じ前提構造(OIDC・非対話・キーチェーンなし)を
  共有する見込みのため。v1 の葉は `run` の 1 つだけ

## 2. 設定の運搬: すべて明示フラグ(env 変数・設定ファイルは使わない)

`--server <url>` / `--project <genesis>` / `--env <id>` は必須、
`--audience <value>`(既定 = server の正規化 origin — AUTH_SPEC §14-1 の推奨値)と
`--anchor <path>`(§4)は任意。

- **フラグを採る理由**: 4 値はすべて非機密で、置き場所はワークフロー YAML =
  **コードレビューを通るリポジトリ内容**である。§9.1 の検証義務 (1) は
  「genesis をワークロード設定に事前固定する」ことを要求しており、
  `--project`(プロジェクト ID = genesis ハッシュ — CRYPTO_SPEC §6.4)を
  YAML に書かせる形はこの「固定」を最も見えやすい場所(diff レビュー)に置く。
  フラグは grep 可能で、workflow の見た目 = 実行時の値
- **却下: 設定ファイル**。CI ランナーに永続 config は無く、ジョブ内で config を
  書くのは「ディスク上の状態」を 1 つ増やすだけで、genesis 固定をレビューから
  隠す。既存 config(`~/.config/maruhi`)への依存は「ログイン・キーチェーン
  非依存」の規律とも混線する(defaultProject へ黙ってフォールバックする事故面)
- **却下: MARUHI_* env 変数フォールバック**。env はワークフローの見た目から
  値の出所が消える(親ステップ・複合 action・runner 設定のどこからでも注入
  できる)。genesis 固定の意義が「レビューされた値であること」にある以上、
  既定経路にしない。将来 setup action が env を export する形を足す場合も、
  フラグ明示を既定に保つ
- **例外 = ランナー供給の env**: `ACTIONS_ID_TOKEN_REQUEST_URL` /
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN` は GitHub Actions ランナーが供給する
  OIDC 発行エンドポイントで、ユーザー設定ではない。読み出しは `CliIo.envVar`
  (Effect サービス境界)経由 — 計画時に見込んだ「CliServices の拡張」は
  不要だった: `CliIo` が既に envVar を提供しており(本番 = process.env、
  テスト = 差し替え Map)、`process.env` を直接読まない規律はそのまま満たせる

## 3. OIDC トークンと一時鍵の取り扱い

- **一時 X25519 鍵は起動ごとにメモリ内生成**(WebCrypto、秘密鍵は非抽出)。
  ディスクにも応答にも現れず、プロセス終了とともに消える(§9.1)
- **トークンは lease 要求の直前に発行**(session-24 §8 SHOULD — 先着窓の
  最小化)。`ACTIONS_ID_TOKEN_REQUEST_URL` に `&audience=` を付けて GET、
  Bearer は `ACTIONS_ID_TOKEN_REQUEST_TOKEN`。env 変数が無ければ
  「GitHub Actions 外か `permissions: id-token: write` の欠落」を名指しして
  通信前に落とす
- **トークンはベアラー資格情報として `Redacted` で包む**。剥がすのは
  (a) claims 読み出し(base64url decode + JSON.parse — 署名検証はサーバーの
  仕事でクライアントは自トークンの iss / sub / aud を読むだけ。JWT ライブラリは
  足さない)、(b) lease リクエストの payload 組み立て、の 2 か所のみ
  (redacted.test.ts の棚卸しに登録)。ログ・エラー・診断には出さない
- **claims_digest は `computeLeaseClaimsDigest`**(A-5-1 — builder 直接使用は
  空フィールドガードを迂回する)。`aud` が配列で要素数 ≠ 1 のトークンは
  クライアント側でも拒否する(サーバーの `ambiguous-audience` と同じ判定 —
  digest が一意に決まらない)
- **1 呼び出し = 1 トークン = 1 一時鍵**。lease エンドポイントは環境単位で、
  `ci run` も環境単位なので、§14-1 の MUST(1 トークンで複数環境をリースする
  なら全リクエストで同一鍵)は構成上満たされる。1 ジョブで複数環境を使う場合は
  `ci run` を環境ごとに実行する = 環境ごとに新規トークン + 新規鍵(GitHub は
  ランタイム発行型なのでこの形が許される)。トークンを跨いで使い回す経路は
  作らない
- **`token-replayed` は新規トークンで 1 回だけ自動再試行**(session-24 §8 MAY —
  上限 1 回)。一時鍵は同じものを提示する(新トークンは未束縛なので自鍵に
  束縛される。鍵を替える理由がなく、生成コストも無駄)。再試行後も
  `token-replayed` なら、トークン漏洩の兆候として案内を出して失敗する
- **429 は自動再試行しない**: 窓は固定 1 時間(§14-3)で、ジョブ内リトライは
  窓を消費するだけ。`retryAfterSeconds` を表示して失敗させ、リトライの判断は
  CI 側(re-run)に委ねる
- **503 は理由別の案内で失敗**(§14-3 の 2 理由 + server-wraps-missing):
  `oidc-jwks-unavailable` = 一過性(ジョブ再実行を案内)、
  `server-key-unconfigured` = デプロイ設定の欠落(SELF_HOSTING.md へ誘導)、
  `server-wraps-missing` = grant 済みだが再ラップ未了(管理者の rotate /
  バックフィルへ誘導)。いずれも資格情報の異常ではないことを文面で区別する
  (401 と混ぜない — §14-3 が区分を分けた意図の伝達)

## 4. 検証義務の実装(CRYPTO_SPEC §9.1 の (1)〜(4))

lease 応答は自己完結(AUTH_SPEC §14-2)— 検証材料を他のエンドポイントへ
取りに行かない。実装は既存のクライアント検証部品を再利用する:

- **(1) チェーン検証**: `sync.ts` から `verifyChainSnapshot`(全再検証 +
  genesis ハッシュ = `--project` の固定値との一致 + 申告ヘッドと導出ヘッドの
  整合)を切り出し、`syncProject`(取得 + 検証)と lease 応答(同梱チェーンの
  検証)の両方が同じ実装を通る。応答の `projectId` / `currentEpoch` 申告値も
  検証済み導出値との一致を検査する(申告値を信用しない — 既存の姿勢)
- **(2) リポジトリアンカー(SHOULD)**: **実装する**。生成側 =
  `maruhi project anchor`(メンバーが検証済みビューからアンカー JSON を
  stdout へ出力し、リポジトリへコミットする)、検査側 = `ci run --anchor
  <path>`(genesis 一致・ピン留めヘッドの包含・環境ごとのエポック非後退)。
  「rotate / push 成功時に更新を提案する」の SHOULD は今回見送る(検出の
  安全性はアンカーの鮮度に単調で、更新提案は UX 改善であって性質を変えない。
  運用は rotate 後に `project anchor` を再実行して commit — action の README に
  明記)。`--anchor` 自体も任意(SHOULD)だが、README のテンプレートには含める
- **(3) DEK コミットメント照合**: `unwrapLeaseDek` で開封した DEK は
  `verifyDekCommitment`(チェーン導出の (environment, epoch) コミットメント)を
  通るまで使わない(§5.2)。DEK 長の検査を開封層で二重に発明しない(A-5-2 —
  32 バイト以外を Seal した悪意サーバーはコミットメント照合で落ちる)。
  リースラップは §5.1 登録署名を**持たない**(サーバー生成・応答スコープ —
  ワイヤ型 `LeasedDek` が構造的に区別する)ため、deks.ts の署名検証段は
  適用されず、エポック上限(チェーン導出現エポック以下)・重複拒否・
  コミットメント存在の検査を lease 専用の開封層に置く
- **(4) 値署名・メタステートメント検証**: values.ts の検証骨格
  (`verifyAllCommon` — 環境ステートメント → アクティブ集合 → tombstone →
  名前検査)を lease 用入口 `verifyLeaseDistribution` として公開する。
  pull と違う点は 1 つだけ: **future head(宣言 seq > 同梱チェーンのヘッド)は
  再同期せず即時拒否**する。チェーンは同じ応答に同梱されており、「自分の
  チェーンが古いだけ」という正直な説明が存在しない(応答が自己矛盾している)
- **床は持たない**: ランナーは使い捨てで、床の永続化は意味を持たない
  (§14.3-3 の床なし初回同期クラス)。その主要な緩和が (2) のアンカーである

## 5. 実装配置

- `apps/cli/src/oidc-github.ts` — OIDC トークン取得(CliIo.envVar + fetch)と
  claims 読み出し(Redacted 剥がし 1 箇所)
- `apps/cli/src/lease-client.ts` — lease 応答の検証・開封・復号(§4 の
  (1)(3)(4) + アンカー検査)。産物は `DecryptedVariable[]`(run と同じ型)
- `apps/cli/src/ci-run.ts` — オーケストレーション(鍵生成 → トークン →
  issue〔token-replayed 1 回再試行〕→ 検証 → `runOp`)。注入境界は run と同じ
  `buildInjectionEnv` / `ProcessRunner`(ディスクレス不変条件)
- `apps/cli/src/anchor.ts` — アンカー形式(JSON)の生成・解釈・検査
- 引数層は ADR-0016 の様式(宣言 + GROUP_CONFIGS + COMMAND_SPECS +
  cli-formatter)。`ci run` は `run` と同じ `--` 規律(commandAfterTerminator)
- `failure.ts` に Lease 系 3 エラーの写像を追加(理由コードのみ — トークン値・
  外部識別子を運ばない)
- agent-gate には触れない: `ci run` は値の表示ではなく注入(run と同じ
  サンクションされた消費経路)。isAgent ゲートは 9 箇所のまま

## 6. setup-maruhi action

- 置き場所は `actions/setup-maruhi/`(composite)。`uses:
  maruhiapp/maruhi/actions/setup-maruhi@<ref>` で参照する(action の checkout は
  リポジトリ全体を含むため、`packaging/install.sh` の検証ロジック —
  checksums.txt の SHA-256 必須検証・検証前にインストール先へ書かない — を
  そのまま再利用する)。マーケットプレイス公開は Phase 2 の public 化と同時
  (現時点ではリポジトリ内 + README)
- inputs: `version`(タグ。プレリリース期間は必須 — install.sh と同じ理由で
  latest 解決が存在しない)。インストール先はランナーのツールディレクトリで、
  `$GITHUB_PATH` へ追記する
- README(英語)に `permissions: id-token: write` の必須を明記し、
  `maruhi ci run` のワークフロー例(アンカー込み)を載せる

## 7. テスト方針

lease エンドポイント = MockServer 偽装(実 crypto フィクスチャで応答を組み、
リクエストの `ephemeralPubHex` へ動的に `wrapLeaseDek` する)。OIDC 発行 =
MockServer の別パス(署名はダミー — クライアントは検証しない)、env 読み =
テスト層の `setEnvVar`。負例で固定するもの: 改竄チェーン / genesis 不一致 /
コミットメント不一致(毒ラップ)/ 値署名不正 / claims_digest 不一致(別ジョブ
文脈向けラップの転用)/ token-replayed(1 回で回復・2 回で打ち切り、一時鍵の
同一性と新規トークンの発行)/ 503 の 2 理由 / 429 / OIDC env 欠落 / アンカー
違反(ヘッド不包含・エポック後退)。サーバー側の判定は apps/server/test/
lease.test.ts が既に固定しており重複させない(クライアント挙動に集中する)。

## 8. 申し送り

- アンカー更新の提案(rotate / push 成功時 — CRYPTO_SPEC §6.3 (b) の SHOULD の
  後半)は未実装。運用は `maruhi project anchor` の手動再実行。UX 改善として
  独立 PR の候補
- setup-maruhi のマーケットプレイス公開・タグ運用(`v1` メジャータグ)は
  Phase 2 public 化と同時に判断する
- 事前発行型 issuer(GitLab / k8s)対応は、トークンの供給経路(env / file)を
  差し替えるだけで `ci run` の検証・開封層はそのまま使える構造にしてある
  (oidc-github.ts の分離が差し替え点)
