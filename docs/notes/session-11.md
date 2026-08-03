# セッション 11 メモ(CLI MVP: login / 鍵管理 / §6.3 同期検査 / §5.1 配布時検証 / pull / run / push / 環境管理)

日付: 2026-08-03。前提: PR #22(§6.2 メンバー鍵一意性 — マージ = 所有者承認)・
#23(ROADMAP)・#24(空 `deks: []` 400)マージ済みを確認して開始。
スコープ: タスク指定の 1〜7 全項目(基盤 / ログイン / 鍵管理 / 同期検査 /
pull + 配布時検証 / run / push + 環境管理)を単一 PR(#25)で実装。
コミットは層順(crypto → 基盤 → ログイン・鍵管理 → 同期・pull・run →
push・環境 → 配線 → テスト)。

## 1. やったこと

1. **crypto**: master 秘密鍵のシリアライズ API(`exportEncryptionPrivateKey` =
   hpke `SerializePrivateKey` / `exportSigningPrivateSeed` = WebCrypto JWK 経由、
   `KeyExportFailed` エラー種別、core の Effect マッピング追随)。
   新しい暗号操作の導入なし(既存部品による直列化のみ。CRYPTO_SPEC §3 の
   「CLI: OS キーチェーン」の実装前提)。**packages/crypto への変更のため
   人間レビュー必須(PR 説明に明記)**
2. **CLI 基盤**: gunshi 0.37.1 + @types/bun 1.3.14 を導入(選定理由はコミット
   メッセージ)。Keychain / ConfigStore / CliIo / ProcessRunner の Effect
   サービス境界、`HttpApiClient.make(maruhiApi)` による型付きクライアント、
   型付きエラー → ユーザー向けメッセージの一元写像(failure.ts。素の 413
   分岐を含む)
3. **コマンド**: login / logout / key (generate|show) / project (init|verify) /
   env create / pull [--show] / push <NAME> / run -- <cmd> / config (get|set)
4. **テスト**: CLI 53 件(全体 419 件)。ワイヤレベル HTTP モック + 実 crypto
   フィクスチャ。live E2E(実 bin.ts + モック)で §6.3 検証の実動作と
   キーチェーン不在時の挙動を実測
5. **docs**: 本メモ

## 2. 裁定事項の細部(複数案比較 → 推奨で仮進行。確定条件 = PR レビュー承認)

### 2-1. OS キーチェーン = Bun.secrets(依存ゼロ)

| 案 | 評価 |
|---|---|
| **Bun.secrets(採用)** | CLI は Bun ランタイム(ADR-0004)で Bun API 可。macOS Keychain / Linux libsecret(Secret Service)/ Windows Credential Manager を単一 API で覆い、**依存追加ゼロ**(供給網を増やさない)。v1 対応範囲 = Bun.secrets の対応範囲と一致させる |
| keytar | アーカイブ済み(メンテ終了)。却下 |
| @napi-rs/keyring | 機能は同等だがネイティブバイナリの依存が増える。Bun.secrets で足りる限り不要 |
| CLI 内で自前実装(security / secret-tool 呼び出し) | プラットフォーム分岐の自前保守。却下 |

- **キーチェーン不在環境**(headless Linux 等): 平文フォールバックは不変条件
  違反なので実装しない。書き込みは 30 秒タイムアウトで「キーチェーン不在」の
  案内エラーに落とす(§3 の実測知見)。トークンのみ **`MARUHI_TOKEN` 環境変数の
  読み取り専用経路**を用意(CI 用。userId は `GET /auth/me` で解決)。
  master 秘密鍵の環境変数経路は**作らない**(鍵素材をプロセス環境に置く経路を
  v1 で増やさない — 申し送り: CI での pull/run が必要になった時に設計)

### 2-2. master 秘密鍵の保存形式

JSON 1 エントリ(`{suite, encPubHex, encSkHex, sigPubHex, sigSkSeedHex}`、
hex 小文字)。キーチェーン名は `master::<origin>::<userId>`、トークンは
`token::<origin>`(サーバー origin でスコープ。セルフホスト複数サーバーの
併用が自然に成立する)。sig 秘密鍵は RFC 8032 seed(32B)— importSigningKeyPair
の既存契約と一致。使用時は非抽出(extractable=false)でインポートする。

### 2-3. チェーンのローカルキャッシュ = なし(毎回全取得・全再検証)

チェーンは署名付き公開データで v1 の規模(受理ポリシー上限 10,000 エントリ、
実運用は数十)では全再検証が最簡かつ最安全。差分検証を導入する場合は
session-10 §5 の鍵索引再構築の注意(検証済み members Map からの復元)に従う。

### 2-4. 非機密設定 = `~/.config/maruhi/config.json`

`MARUHI_CONFIG_DIR` → `XDG_CONFIG_HOME` → `~/.config` の順で解決(macOS も
XDG 系に統一。Windows の %APPDATA% 対応は配布 Phase 2 と同時)。キーは
server / githubClientId / defaultProject / defaultEnvironment のみ
(allowlist。シークレットを書く経路が構造的にない)。dir 0700 / file 0600。

### 2-5. pull のユーザー可視挙動 = メタデータ表示 + 明示 `--show`

既定は同期 + 検証 + メタデータ(変数名・version・epoch・バイト長)のみ。
`--show` の値表示は **AI エージェント検出(gunshi/agent)時に拒否**し、
`maruhi run` は許可する(検出機構だけ用意する案より、拒否対象が実在する方が
線引きをテストで固定できる)。ファイル出力の選択肢はディスクレス不変条件により
存在しない。

### 2-6. セルフホストの GitHub client_id = CLI 設定で与える(裁定済み)

v1 は `maruhi config set githubClientId <id>`(または `--github-client-id`)。
サーバー・仕様の変更なしで動く。**長期はサーバーの公開設定エンドポイント
(client_id は公開情報)が UX 上優位**だが AUTH_SPEC 改訂 + サーバー実装を
伴うため要裁定に回した(PR #25 の要裁定 1)。
**→ 2026-08-03 所有者裁定: 「今は A(CLI 設定)、次の独立 PR で B(公開設定
エンドポイント)」で確定**(§5 申し送り参照)。

### 2-7. テスト戦略 = ワイヤレベル HTTP モック + 実 crypto(spawn 比較で採用)

| 案 | 評価 |
|---|---|
| **HTTP モック(採用)** | (i) サーバーの fake-github は vitest-pool-workers の fetch 差し替えでありwrangler dev spawn では使えない(ログイン系は spawn だと検査不能)。(ii) CLI の本丸 = クライアント検証(§5.1 / §6.3)は「不正な応答を返すサーバー」を要し、実サーバーでは作れない(署名偽装・チェーン差し替え・暗号文差し替え等の negative)。(iii) 応答は実 crypto で組み立て、ワイヤ形は api-schema に一致させる |
| wrangler dev spawn(web e2e 先例) | 実サーバーとの契約整合は最強だが、D1 マイグレーション事前適用が必要で、ログイン系・敵対的応答系が検査できない。**実サーバー結合は将来の統合テスト(スモーク)として申し送り** |

- キーチェーンは Effect サービス境界で抽象化し、テストはインメモリ実装
  (CI に OS キーチェーンはない — タスク指示)。実キーチェーンの結合は
  ローカル手動確認まで
- 変数 ID はクライアント採番の乱数(`v` + 12 バイト hex)を採用: 表示名 = ID に
  すると改名・tombstone(ID 再利用禁止 — §12-1)と衝突するため。名前 → ID の
  解決は pull エンドポイントで行う(専用一覧 API がないため。PR 要裁定 3 =
  push のたびに var.read 監査行が出る監査ノイズ)

### 2-8. チェーン追記の CAS リトライ = 実装保留(申し送り)

v1 の CLI コマンドに genesis 以降のチェーン追記(add_member / rotate 等)は
存在しない。同期ライブラリの関数として先行実装すると実利用がなく、fallow の
unused-export 検出(テスト専用エクスポートも検出 — session-07 §3)に反する
ため、追記系コマンドを持つ将来セッションへ保留した(タスクの許容判断)。

## 3. ハマったこと・環境知見

- **Effect v4 beta の catch 系 API**: `catchAll` は存在せず `Effect.catch`
  (`catch_` の別名エクスポート)。HttpApiClient のメソッド戻り値の union は
  そのまま `.pipe` できないため、`Effect.Effect<A, unknown, R>` を受ける
  ヘルパ(push.ts の classifyAttempt)で共通化 + instanceof 分類にした
- **宣言外ステータス(素の 413)の観測点**: HttpApiClient は宣言にない
  ステータスを `HttpClientError`(reason DecodeError、`error.response.status`
  参照可)で返す。failure.ts の分岐はこれに依拠(テストで固定)
- **`Bun.secrets` は keyring デーモン不在の headless Linux で書き込みが
  応答なしブロックする**(この VM で実測。読み取りは null 即応)。30 秒
  タイムアウト + 案内エラーに落とし、さらに**中断後も pending なネイティブ
  呼び出しがイベントループを生かし続けてプロセスが終了しない**ため bin.ts は
  明示 `process.exit`
- **@types/bun を入れると DOM lib が必要**(crypto ソースの WebCrypto 型)。
  apps/cli の tsconfig は `lib: [ES2023, DOM]` + `types: [bun]`(core の先例)
- **gunshi のモック不要な統合点**: `runCli(argv, layer)` に Effect Layer を
  注入する形にすると、gunshi の実配線(positional / rest / フラグ)ごと
  テストできる。gunshi は既定レンダラーがヘッダー行を出す(実害なし)
- **fallow の unused-export はテスト専用エクスポートを検出する**(session-07
  §3 の再確認): テスト支援はすべて test/support/ に置き、src の export は
  src 内の消費者があるものだけにした
- fallow dupes ベースラインへ cli / server のテスト支援 3 クローン群を追加
  (§2-7 の独立判断。既存の data-store.ts 内部クローン 1 群は継承)。
  **→ 2026-08-03 所有者裁定: 本 PR はベースライン許容のまま、マージ後に
  共有フィクスチャ抽出(packages/crypto/test/ へ)を小さな独立 PR で行う**
  (§5 申し送り参照)

## 4. 既知の制約・v1 許容

- **実 OS キーチェーンの結合は未検証**(この環境に keyring デーモンがない)。
  macOS / デスクトップ Linux でのローカル手動確認が必要(手順: login →
  key generate → project init → env create → push → pull → run)
- push の変数解決に pull を使うため監査ログに var.read が出る(PR 要裁定 3)
- pull はサーバー申告の currentEpoch を検証に使わない(不要 — DEK 索引は
  変数ごとの申告 epoch で引き、真実源はチェーン導出値。push の CAS が最終防衛)
- 値表示(pull --show)の端末出力はシェルの履歴・スクロールバックに残りうる
  (端末表示自体はディスクレス不変条件の許容範囲。人間の明示操作に限定)
- `maruhi run` の環境変数はプロセス環境として子へ渡る(/proc/PID/environ は
  同一 uid から読める — 環境変数注入方式の本質的性質で、タスク指定の設計)

## 5. 次セッションへの申し送り

### 裁定済みの後続 PR 3 本(2026-08-03 所有者裁定。互いに独立・順序自由)

1. **サーバー公開設定エンドポイント(client_id 配布 — PR #25 要裁定 1 の
   裁定 = 「今は A、次の独立 PR で B」)**: 未認証の公開エンドポイント
   (例: `GET /auth/config`)が githubClientId を返し、login が自動解決する。
   AUTH_SPEC §4 の改訂 + サーバー実装を伴う。設計点: (i) 応答は client_id
   のみから始める(セットアップウィザードの要求は必要時に追加)、
   (ii) 未認証面の増加は client_id が公開情報のため許容、(iii) 導入後も
   config の githubClientId は上書き手段として残す(GHES・テスト用)
2. **テスト支援フィクスチャの共有抽出(PR #25 要裁定 2 の裁定 = 「本 PR は
   ベースライン許容のまま、マージ後に B を小さな独立 PR で」)**: cli / server
   のテスト支援クローン 3 群(チェーン組立・op ビルダー・unwrapResult 系
   約 75 行)を `packages/crypto/test/` 配下の共有モジュールへ抽出し、
   dupes ベースラインから当該 3 群を削除して縮める。注意: (i) 挙動変更ゼロの
   機械的抽出に徹する、(ii) サーバーテスト都合の `unwrapAndDecrypt`(申告
   AAD をそのまま使う)は共有側に持ち込まない、(iii) packages/crypto 配下の
   変更のため人間レビュー必須
3. **pull のメタデータのみモード(PR #25 要裁定 3 の裁定 = 「今は A、次の
   独立 PR で G」)**: 一括 pull にメタデータのみのモード(値・DEK を返さない)
   を追加し、`var.read` を記録しないことを AUTH_SPEC §12-7 / AUDIT_SPEC の
   意味論として明文化する(「読んでいないものを読んだと記録しない」)。
   認可は pull と同水準(read × reader)。CLI 側は push の名前解決を
   このモードへ切り替える(レビュー指摘の「push が DEK 集合を pull と
   listMine で二重取得する」無駄も同時に解消)

### その他の申し送り

- **チェーン追記系コマンド(add_member / remove_member / rotate_epoch /
  change_role)**: 追記 + ChainHeadConflict(409 CAS)リトライループを
  コマンドと同時に実装する(§2-8)。remove_member は §7 の全環境 rotate +
  再ラップ + 再暗号化を伴う大物
- **CI・キーチェーン不在環境での pull / run**: master 秘密鍵の供給経路が
  ない(MARUHI_TOKEN はトークンのみ)。リカバリーコード(§8)実装か
  専用のマシン鍵設計とセットで検討
- **実サーバーとの統合スモーク**(wrangler dev spawn + D1 適用): モックの
  契約乖離への保険。web e2e の先例 + D1 マイグレーション適用が必要
- **§6.3 ヘッドゴシップは Phase 2**(未着手のまま)。書き込み系リクエストへの
  申告ヘッド同梱はワイヤ改訂を伴う
- Windows の設定パス(%APPDATA%)と CLI 配布(npm / brew)は Phase 2
- session-07 §5 の未着手分(リカバリーブロブのレート制限等)は継続
- **クライアント検証ロジックの置き場所**: sync.ts / deks.ts / pull.ts の
  §5.1・§6.3 照合は Web ダッシュボード実装時に共有したくなる。その時点で
  packages/core への昇格を検討(暗号プリミティブではないので core で可)
- **仕様側の検討事項(レビューループ 3 の記録から)**: (1) 値 / DEK の
  チェーン束縛 — §5.1 署名は帰属であって値の真正性ではなく、チェーン履歴上の
  鍵保持者と共謀するサーバーは実在エポックへ偽 DEK・偽値を注入できる(v1 の
  既知限界)。(2) 変数名の暗号学的束縛 — 名前は AAD に入らない平文メタデータで、
  サーバーが名前↔暗号文の対応を付け替えられる(CLI は実行制御系変数名の
  denylist で緩和)。どちらも CRYPTO_SPEC の改訂を伴うため未決事項として起票を
  検討
- **エポック超過エラーの自動再同期**: 正直サーバーでも「同期と pull の間に
  ローテーションが挟まる」競合でエポック超過エラーになりうる(再実行で解消。
  文言で案内済み)。一度だけ自動再同期して再試行する UX 改善は将来検討

## 6. レビュー→修正ループ(PR #25 内。3 観点の並行レビュー → 修正)

レビュー観点に「平文・鍵素材がディスク・ログ・エラーに漏れる経路がないこと」を
明示して 3 観点(セキュリティ・暗号 / 正しさ・並行性 / テスト・契約)を並行実行。

### ループ 1 の主要指摘と対応(コミット 6cc97e6)

1. **ファントムエポック(セキュリティ [中]・正しさ [中]・テスト [高] が同根を
   独立検出)**: 配布ラップ・申告 AAD の epoch に「チェーン導出現エポック以下」の
   クライアント検査がなく、共謀サーバー + チェーン履歴上の鍵保持者(削除済み
   元メンバー含む)が、チェーンに rotate_epoch のないエポックの自作 DEK で
   偽値を注入できた。→ deks.ts / pull.ts に上限検査を追加し、テストは
   epoch 3(チェーンは 2)のラップ / 変数の拒否 +「サーバーが currentEpoch=5 と
   虚偽申告しても push の再試行はチェーン導出値(2)」で固定
2. **defect が usage エラー(exit 2)に化ける(正しさ [中]。実測)**: execute に
   catchDefect を追加(内部エラー = exit 1)。テストで固定
3. セキュリティ [低] 5 件: http は loopback のみ / deks・master 鍵レコードの
   suite 明示固定 / 実行制御系環境変数名(PATH・LD_*・NODE_OPTIONS 等)への
   注入拒否 / MARUHI_TOKEN の origin 非スコープは文書化
4. 正しさ [低] 群: push の create 競合再解決・最終試行後の無駄な遷移廃止・
   エポック矛盾の即時報告、keygen の保存前自己検証、login の保存失敗時
   トークン失効(孤児化防止)、config の原子的書き込み・破損復旧、
   device flow の RFC 準拠 400 対応、ID 検証のネットワーク前移動
5. テスト [中]〜[低] 群: §5.1 の FP 不一致・重複エポック・クロス環境暗号文・
   削除→再追加メンバーの旧鍵署名検証(鍵履歴 2 束縛)、logout 401、
   MARUHI_TOKEN 優先順位、平文値・トークン・秘密鍵素材の非出力 assert、
   crypto エクスポートの機能検証化(HPKE open / sign-verify)+ ベクター固定

### ループ 2(修正の再検証)

3 観点とも **[高]・[中] の残指摘ゼロ**を確認(セキュリティ = ファントム
エポック検査は受理区間を [1, chainEpoch] に厳密束縛・抜けなし / 正しさ =
遷移網羅・catchDefect 位置・原子的書き込みまで実測込みで検証 / テスト =
追加テストが指摘した変異を実際に落とすことをトレースで確認)。残った [低] も
対応: denylist の拡充(JAVA_TOOL_OPTIONS・RUBYOPT・GIT_* 等 + 大文字化比較 =
Windows の大文字小文字非区別対策)、エポック超過エラーの文言(正直サーバーの
ローテーション競合の可能性を明記 — 自動再同期は申し送り)、login の失効後
メッセージ明確化、create への VersionConflict 再解決テスト、未知スイート
レコード拒否テスト、フィクスチャのトークン実形式化。

### ループ 3(最終確認)

3 観点ともブロッキング指摘ゼロ。記録に留めた事項(採用せず):
- **[情報] 実在エポックへの偽 DEK 注入の残余**(セキュリティ): 悪意サーバー +
  チェーン履歴上の鍵保持者の共謀で、実在エポック e ≤ chainEpoch に自作 DEK を
  自鍵で §5.1 署名して偽値を注入できる。値が無署名である v1 設計の既知限界
  (§5.1 は帰属であって値の真正性ではない)。根本策は値 / DEK のチェーン束縛で
  仕様レベルの検討事項 → §5 申し送り
- **[情報] 変数名と variableId の束縛が非認証**: 名前は平文メタデータで AAD に
  入らないため、サーバーは名前↔暗号文の対応を付け替えられる(denylist は
  緩和策)。名前の暗号学的束縛(または push 時の名前スナップショット照合)を
  仕様側検討として申し送り
- ヘッドゴシップ未実装(Phase 2)= split view は v1 未防御であることの明示
- keygen の並行実行 TOCTOU(対話コマンドのため実害僅少)、config save
  クラッシュ時の .tmp 孤児、interval=0 の下限クランプ(deadline で有界)、
  一時ディレクトリ掃除、device flow の不整合鍵ペア import(処理系依存)

経過: ループ 1 = 高 1・中 3・低多数 → ループ 2 = 低 6 → ループ 3 = ゼロ
(ブロッキング)。`bun run check`(447 件)+ live E2E green。以降は ready 化 →
所有者指示によるマージ。
