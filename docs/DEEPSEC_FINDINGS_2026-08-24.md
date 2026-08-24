# deepsec 再チェック(2026-08-24 実行)

`DEEPSEC_FINDINGS_2026-08-22.md` の 17 論点(18 レコード)を、修正後のコードに対して
再検証した結果。前回文書は本文書で置き換える(前回分は履歴として残す)。

> **対応済み(2026-08-24)**: 残課題 8 論点(9 レコード)はすべて実装した。各節の
> 末尾に「対応」を追記してある。仕様側の変更は AUDIT_SPEC §3.1(R4/R5/R6)と
> §7(R1)、`docs/SELF_HOSTING.md`(R7)。固定 Bun で `bun run check` が通る
> 状態(テスト 1798 件)。
>
> 意図的に**やらなかった**ことが 2 点ある。どちらも「実装できるが、その対処は
> 目的を達しない」と判断したもの:
>
> - **R7 の state 単回使用化**: 失敗パスでも state cookie を expire する案は、
>   攻撃者が cookie と query の**両方を自分で用意できる**(サーバー側状態が無い
>   二重送信方式)ため、指摘された攻撃を 1 リクエストも減らさない。加えて Effect
>   HttpApi の型付きエラーは `Set-Cookie` を運べず、エンドポイントの契約変更が
>   要る。頻度の上限はレート制限で担保した(そちらが実効的な対処)
> - **R2 の窓の完全な閉塞**: `Bun.secrets` に compare-and-swap も
>   create-if-absent も無く、OS キーチェーン側に原子的な条件付き書き込みが無い。
>   advisory lockfile はクラッシュ後の stale lock で「他のプロセスが実行中」の
>   誤検出を生み、鍵生成という唯一の入口を塞ぐ危険がある。代わりに窓を
>   極小化し、後勝ちを**検出して失敗させる**形にした(下記 R2 の対応)

## 位置づけ

- 対象: 追跡 117 ファイル。うち `process` は前回 run 以降に変更された候補
  **28 ファイル**を再調査(`--reinvestigate 1 --manifest`)
- `revalidate` は `--force` で全 36 finding を再判定(前回 23 + 新規 13)
- モデル: `claude-opus-5`、thinking `medium`、Claude Agent SDK(ローカル Claude Max 認証)
- run: `scan` `20260824210853-11619b9ebaa8d28c` /
  `process` `20260824211944-bd46bee94341b7ef` /
  `revalidate` `20260824212808-ef2f7b748c056ad0`
- 費用: process $12.13、revalidate $7.61(合計 $19.74)

### 再判定の集計

| 判定 | 件数 |
|---|---|
| fixed | 16 |
| false-positive | 8 |
| duplicate | 3 |
| **true-positive(残課題)** | **9 レコード / 8 論点** |

`process` の範囲は「前回 run 以降に変更のあった候補ファイル」に絞ってある。
変更のない 89 ファイルは 2026-08-22 の分析結果を据え置いており、今回のモデル実行で
再確認したわけではない。全ファイルの再調査(前回 full pass は $39.61)は別途。

## 前回 17 論点の帰結

`fixed` = 再検証で修正を確認。`FP` = 修正により指摘が成立しなくなった、または元から
偽陽性。

| 前回 ID | 帰結 |
|---|---|
| F0 空 `claimConstraints`(2 レコード) | fixed |
| M1 OIDC 発行 URL 検証 | fixed |
| M2 `maruhi run` env denylist | **部分修正**。残る名前あり → 下の R3 |
| M3 / B11 device exchange のレート制限 | FP(`DEVICE_EXCHANGE_RATE_LIMIT` で解消) |
| M4 `auth.login_failed` の global cap | **未解消**(設計トレードオフ)→ 下の R4 |
| M5 lease の DO 生成 | fixed |
| B1 / B4 / B5 タイムスタンプ RangeError | fixed |
| B2 config 読み取り失敗 | fixed |
| B3 device flow の上限 | fixed |
| B6 keychain write timeout | fixed(ただし別種の TOCTOU が新規 → R2) |
| B7 push 表示のローカル値化 | fixed |
| B8 audit read の write amplification | fixed(ただし計数クエリの走査コスト → R5) |
| B9 recovery fetch counter の race | fixed |
| B10 wrap 期待数の衝突 | fixed |
| B12 未知 chain `op` | fixed |
| B13 value-sign の空 `variableId` | fixed |

前回の false-positive 3 件(`requestOrigin()` の Host header、`invalidValueMessage`、
`computeVariablesDigest`)は今回も false-positive のまま。

## 残課題(true-positive 9 レコード / 8 論点)

新規 6 論点のうち 3 件(R5、R7、R9)は、8/22 の修正で追加されたコードに対する指摘。

### R1. `maruhi audit verify` が未知の `chain.*` 偽造行を検出できない — MEDIUM(新規)

- 場所: `apps/cli/src/audit.ts`(`auditVerifyOp`)
- slug: `other-incomplete-tamper-detection` / confidence medium
- 問題: `CHAIN_MIRROR_EVENTS`(`MIRROR_EVENT_NAME` の 8 名)を server 側 `event=`
  フィルタで 1 つずつ取得する。集合外の `chain.*`(例 `chain.role_granted`)を server が
  捏造しても取得されず、`problems` にも `aheadRows` にも入らない。結果、
  「Mirror bijection verification OK」を出して exit 0 になる。
- 影響: 鍵素材・平文は無関係。ただし「untrusted な audit log を chain で裏取りする」
  という AUDIT_SPEC §6 の緩和策そのものの被覆漏れ。`list` の per-row 表示なら
  `startsWith("chain.")` で拾えるが、網羅を謳うのは `verify` 側。
- 推奨: event フィルタを外す(または `event_prefix=chain.` を server に足す)。
  `chain.` で始まり `CHAIN_MIRROR_EVENTS` に無い行は検証失敗として扱う。
- **対応**: 読み取り API に `eventPrefix`(前置一致)を足し(AUDIT_SPEC §7 改訂)、
  verify は既知名の反復ではなく `chain.` 名前空間を 1 回のページングで全取得する。
  写像に無いイベント名の行は「unknown chain op」として検証失敗にする。前置一致は
  LIKE ではなく `substr(event, 1, ?) = ?` で実装し、ワイルドカード意味論を持たせ
  ない(`%` や `_hain.` が全一致にならないことをテストで固定)。
  `CHAIN_MIRROR_EVENT_PREFIX` を `@maruhi/core` から出し、CLI 側の
  `startsWith("chain.")` の直書きも置き換えた。

### R2. master key の上書きガードと keychain write の間に TOCTOU — BUG(新規)

- 場所: `apps/cli/src/keygen.ts`(`keyGenerateOp`。L53 チェック → L118 書き込み)
- slug: `other-race-condition` / confidence medium
- 問題: `ensureNoStoredMasterKey` は read のみでロックを取らない。その後 WebCrypto
  6 回と `importMasterKeys` の自己検証を挟むため窓が数十 ms 開く。`keychain.set`
  (`Bun.secrets.set`)は無条件 put で CAS が無く、entry 名は
  `masterKeyEntryName(origin, userId)` で決定的。同一アカウントで
  `maruhi key generate` が並行すると両方が `existing === null` を観測し、後勝ちで
  片方の鍵が消える。ファイル冒頭が宣言する「既存鍵の上書きは拒否する」は事実上
  advisory。
- 影響の範囲(再検証で縮小): どちらの run も鍵未使用状態から始まるため値の復号不能化は
  起きない。実害は `issueRecoveryAfterKeygen`(write の**後**に走り、これも race)が
  破棄された鍵の recovery blob を登録し得ること。`key show` が「registered」と出るのに
  その code が復元する鍵は keychain の生存鍵と別物になり、復元は同じ上書きガードで
  弾かれる。リモート攻撃者からは到達不能(鍵所有者権限が前提)。
- 推奨: `KeychainShape` に create-if-absent / CAS を足す、または entry 名を鍵にした
  advisory lockfile(秘密値を含めない)を `keyGenerateOp` 全体に張る。write 直前の
  再チェックだけでは窓を狭めるにとどまる。
- **対応**: `storeMasterKeyGuarded`(`session.ts`)を追加し、keygen と recover の
  両方の保存経路をこれに通した。書き込みの**直前に不在を再確認**し、**直後に
  読み戻して自分のレコードであることを検証**する。窓は「再確認 → 書き込み」の
  隣接 2 呼び出しに縮み(元は WebCrypto 6 回 + 再インポート自己検証を挟む)、
  後勝ちで上書きされた側は**黙って続行せず失敗する** — リカバリーコード発行
  (`issueRecoveryAfterKeygen`)より前に落ちるので、「破棄された鍵のリカバリー
  ブロブが登録される」不整合が起きない。CAS が無いため窓自体は残る(上記の
  冒頭注記)。残る窓に他プロセスの書き込みが丸ごと入った場合も、生き残る鍵と
  そのリカバリーブロブが一致する側に倒れる。

### R3. `maruhi run` の実行制御 denylist になお抜けがある — MEDIUM(M2 の残り)

- 場所: `apps/cli/src/run.ts`(`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-injection-denylist-gap` / confidence medium
- 問題: 8/22 の拡充後も次が未拒否。`LESSOPEN` / `LESSCLOSE`(`|cmd %s` で実行)、
  `PAGER` / `MANPAGER` / `EDITOR` / `VISUAL` / `BROWSER`、`SSH_ASKPASS` /
  `SUDO_ASKPASS`、`LUA_INIT`、`GLIBC_TUNABLES`、`LOCPATH`、`NLSPATH`、`TERMINFO`、
  `MALLOC_CONF`。write 権限を持つメンバーが変数**名**を上記にして値を仕込めば、
  `maruhi run -- <cmd>` を叩いた別メンバーの環境で実行され得る。
- 補足: 変数名は AAD に束縛されない平文メタデータ(ファイル内コメントの通り)なので、
  悪意ある server が既存 ciphertext を別名に貼り替えることも可能。
- 推奨: 上記を `DENIED_ENV_NAMES` に追加。denylist ではこのクラスを閉じられないため、
  変数名の暗号的束縛(session-11 の申し送り)を本筋として進める。親環境に無い名前の
  注入に `--allow-name` を要求する案も検討対象。
- **対応**: 指摘の全名 + 近縁の実行制御名を追加した(`LESSOPEN` / `LESSCLOSE` /
  `PAGER` / `MANPAGER` / `EDITOR` / `VISUAL` / `BROWSER` / `SSH_ASKPASS` /
  `SUDO_ASKPASS` / `LUA_INIT` / `LUA_PATH` / `LUA_CPATH` / `PSMODULEPATH` /
  `GLIBC_TUNABLES` / `MALLOC_CONF` / `LOCPATH` / `NLSPATH` / `TERMINFO` /
  `TERMCAP`)。大文字化比較(Windows の非区別)を含む回帰テストつき。包括 prefix
  拒否を採らない M2 の裁定は据え置き。名前の暗号的束縛が本筋であることも据え置き
  (denylist はこのクラスを閉じられない)。

### R4. `auth.login_failed` の global cap がなお監査を失明させる — MEDIUM(M4 未解消)

- 場所: `apps/server/src/db.package/audit.ts`(`appendLoginFailed`)
- slug: `other-audit-evasion` / confidence medium
- 問題: 1 時間 100 件の上限が actor / IP / tenant のどの次元も持たない単一 global
  bucket。攻撃者は形式上妥当な bogus token で安価に窓を埋められ(R7 の callback は
  そもそも無制限)、以後デプロイ全体の認証失敗が黙って捨てられる。
  `auth.login_failed_suppressed` は抑制の発生のみを残し、件数も内訳も残さないため、
  狙われた credential stuffing の帰属も計数も失われる。
- 補足: 8/22 で `auth.login_failed_suppressed` は入ったが、次元付けは入っていない。
  write amplification 防止と監査完全性の対立を、現状は前者に全振りしている。
- 推奨: 粗い鍵で bucket を切る(`authMethod` + `CF-Connecting-IP` の /24・/64 ハッシュ、
  または対象 user が判る場合はその単位)。少なくとも
  `auth.login_failed_suppressed` に抑制件数と理由別内訳を載せ、marker を
  「窓ごと bucket ごと 1 回」にする。外部 provider ID や生 IP を append-only actor に
  書く案は採らない(前回同様)。
- **対応**: 上限を **`auth_method` 単位のバケット**で数える形にした(AUDIT_SPEC §3.1
  改訂)。device flow 側を使い切っても Web OAuth の失敗は記録され続けることをテストで
  固定。抑制マーカーは「窓あたり 1 行」から「抑制件数が 10 の冪(1・10・100…)に
  達した時点で 1 行」に変え、payload に `authMethod` と `suppressedCount` を載せた —
  書き込みは件数に対して対数的に有界で、行の密度と最後の件数から抑制の規模が読める。
  **発信元単位**(IP / その前置ハッシュ)の別枠計数は採らなかった: AUDIT_SPEC §3.1 が
  「limiter 用の追加状態に発信元識別子を持つことになる」として明示的に否定している
  既存の裁定で、これを覆す理由は今回の finding には無い。同一 `auth_method` 内での
  被覆は残る限界(抑制件数で可視化する、が消えはしない)。

### R5. `appendLoginFailed` が login_failed の全履歴行を走査する — BUG(新規)

- 場所: `apps/server/src/db.package/audit.ts`(計数クエリ)
- slug: `other-unbounded-scan` / confidence medium
- 問題: `event IN (...) AND server_ts >= now - 1h` に対し、使える索引は
  `uae_event`(`(event, seq)`。`schema.ts:236`)だけで `(event, server_ts)` が無い。
  SQLite は event までシークした後、その event の全行を走査して `server_ts` を
  filter として適用する。audit 行は append-only で削除されず(`schema.ts:204-206`)、
  上限的に年 ~876k 行。認証失敗ごとに走査コストが無制限に増える。
- 影響: これは flood を抑えるための経路なので、緩和策が増幅器になる。持続的な
  無効資格情報 flood で 1 リクエストあたりのコストが上がり、共有 D1 の全 tenant が
  劣化する。
- 推奨: `user_audit_events` に `(event, server_ts)` の複合索引を足して range seek に
  する。あるいは窓カウンタを append-only ログから導出せず、
  `recovery_wraps.fetch_window_start` / `fetch_count` と同じく専用カウンタ行に持つ。
- **対応**: 後者(専用カウンタ行)を採った。`login_failed_windows` テーブル
  (バケットごと 1 行。migration `20260824214725_simple_legion`)を足し、監査ログの
  走査を**完全に無くした**。索引追加だと走査は range seek になるが、上限まで伸びる
  窓内行を毎回なめる形は残る — カウンタ行なら主キー 1 行の seek で済み、R4 の
  バケット化も同じ 1 文に載る。窓のリセット・加算・上限判定は条件付き UPSERT +
  `RETURNING` の 1 文(recovery 取得計数 = B9 の修正と同じ形)。判定は
  「recorded が上限に達していて suppressed ≥ 1」= 抑制、で導く(窓内では recorded が
  先に伸びきってから suppressed が伸びるため、上限ちょうどの最後の許可を誤判定しない)。

### R6. token rotation が旧 token を無言で破棄し revocation を残さない — BUG(新規)

- 場所: `apps/server/src/db.package/repos.ts`(`replaceForUserAndName`)
- slug: `other-audit-gap` / confidence medium
- 問題: `(user_id, name)` 一致行を delete して新行を insert する 1 batch で、
  記録は `auth.token_created` のみ。暗黙の revocation に対応する
  `auth.token_revoked` が無く、`GET /auth/audit/events` では「動かなくなった資格情報」の
  終了記録が欠ける。
- 影響: `deviceExchange` は当該アカウントの有効な GitHub OAuth token を持つ者なら
  到達でき、`tokenName` は攻撃者が選べる(`auth-api.ts:171-173`)。GitHub identity を
  奪った攻撃者が既存 CLI token 名(既定 `device-flow`)を指定すると、被害者の
  資格情報を無効化しつつ、その理由が監査ログに残らない。
- 補足: 旧 token id を知るには先行 SELECT が要るため意図的、とコメントにある。
  乗っ取りの可視化という監査の目的に対して不完全なので挙げてある。
- 推奨: `revokeById`(L435-447)と同じ `.delete(...).returning({ id })` を使って
  `auth.token_revoked` を積む。または `auth.token_created` の payload に
  `rotated: true` と displaced token id を載せて再構成可能にする。
- **対応**: 後者(発行行に載せる)を採った。`auth.token_revoked` を積む案は
  AUDIT_SPEC §3.1 の既存裁定(「ローテーションは置換であり明示失効と区別する」)を
  覆すことになるため採らない。`auth.token_created` の payload に `replacedTokenId` を
  足し(新規発行ではキー自体が現れない)、AUDIT_SPEC §3.1 を改訂した。id は
  **削除文より前に置いた監査追記の SQL 内から**拾う(`json_patch` は値 NULL のキーを
  削除する RFC 7386 のマージ意味論なので、新規発行では payload の形が従来どおりに
  なる)— 先行 SELECT を足すと、読みと batch の間の並行ローテーションで実際に消えた
  行と食い違う。delete + insert + 監査の atomic batch はそのまま維持している。

### R7. OAuth callback が無制限に GitHub token exchange を起こす / state が再利用可 — MEDIUM(新規)

- 場所: `apps/server/src/handlers-auth.ts`(`githubCallback`)
- 同一論点の別レコード: `packages/api-schema/src/auth-api.ts`(`githubCallback` の
  error set が `[AuthFlowError]` のみ。confidence high)
- slug: `expensive-api-abuse`
- 問題: `ipRateLimitAllowed` の呼び出し箇所は `handlers-auth.ts:206`(deviceExchange)と
  `handlers-lease.ts:114` の 2 つだけで、`githubCallback` には無い。`wrangler.jsonc` の
  limiter binding も `DEVICE_EXCHANGE_RATE_LIMIT` と `LEASE_RATE_LIMIT` のみ。
  唯一のゲートである state 比較は cookie と query の両方を攻撃者が握れるため
  throttle にならない(`curl -H 'Cookie: __Host-maruhi_oauth_state=X'
  '.../callback?state=X&code=junk'`)。加えて state cookie を expire するのは成功パス
  (L189-193)だけなので、1 つの state が Max-Age 10 分ぶん再利用できる。各反復が
  `github.exchangeCode` → GitHub token endpoint への outbound を 1 回消費する。
- 影響: 8/22 で device exchange 側は塞いだが、同じ「OAuth App 共有 quota 枯渇で
  全ユーザーの login が止まる」経路が callback に残っている。可用性のみ。
  512 文字の長さ上限(`auth-api.ts:143-146`)は payload サイズを縛るだけで頻度は縛らない。
- 推奨: `OAUTH_CALLBACK_RATE_LIMIT` binding を足し、`github.exchangeCode` の前に
  `ipRateLimitAllowed` を置く。endpoint の error set に `AuthRateLimitedError` を宣言する。
  併せて失敗パスでも state cookie を expire し、state を単回使用にする。
- **対応**: `OAUTH_CALLBACK_RATE_LIMIT`(30/min/IP — `docs/SELF_HOSTING.md` が
  callback に推奨していた値と同一)を `wrangler.jsonc` と `Env` に足し、
  `githubCallback` の**最初**に `ipRateLimitAllowed` を置いた(state 比較より前 —
  state 不一致時の `recordLoginFailed` による監査書き込み増幅ごと有界にする)。
  error set に `AuthRateLimitedError` を宣言。`SELF_HOSTING.md` の「callback は WAF が
  唯一の手段」という記述を訂正した。state の単回使用化は採らなかった(理由は冒頭注記)。

### R8. (R7 と同一論点。`packages/api-schema/src/auth-api.ts` 側のレコード)

R7 と同じ変更で閉じた(2 レコードを重複として扱う)。

### R9. 埋め込み IPv4 の octet 解析が `Number()` で緩い — BUG(新規)

- 場所: `apps/server/src/worker-env.ts`(`groupsOfPiece`)
- slug: `other-lenient-parsing` / confidence medium
- 問題: `piece.split(".").map(Number)` の後に
  `Number.isInteger(o) && 0 <= o <= 255` を見るだけなので、強制変換が先に通る。
  `""` → 0、`0x10` → 16、`1e2` → 100、前後空白も通り、`1.2.3.` が 1.2.3.0 に正規化され
  `::ffff:0x1.2.3.4` が受理される。hex group 側(L103)は厳格なので、緩いのは
  IPv4 埋め込み経路だけ。
- 影響: 呼び出し元は `rateLimitKeyOf` ← `ipRateLimitAllowed` のみで、入力は
  Cloudflare edge が必ず上書きする `cf-connecting-ip`(wrangler dev / テストでは不在で
  fail-open)。よって攻撃者到達経路は無く、レート制限バイパスにはならない。実害は
  異なる不正表記が同一 bucket に落ちる、または raw string への fallback にならないこと。
- 推奨: 強制変換の前に厳格な 10 進正規表現(`/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/`)で
  各 octet を検証し、IPv4 埋め込み片はアドレス末尾のみに許す。
- 注: scanner が同ファイル L37 / L102 を `insecure-crypto` と出したのは偽陽性
  (IPv6 判定と hex group 検証で、暗号は無関係)。
- **対応**: `Number()` の前に厳密な 10 進正規表現(先頭ゼロ・空・16 進・指数表記・
  空白を拒否)を通し、IPv4 埋め込みは**アドレス末尾のピースのみ**許すようにした
  (RFC 4291 §2.2 (3)。`1.2.3.4::` や `::ffff:1.2.3.4:0` を弾く)。不正表記は従来
  どおり素の文字列キーへフォールバックする(別バケットに化けない)。

## 対象外(false-positive)

今回 false-positive と判定され残課題に数えないもの。

- 前回からの 3 件: `requestOrigin()` と Host header、`invalidValueMessage` の substring
  判定、`computeVariablesDigest` の UTF-16 / UTF-8 duplicate 判定
- device flow の token POST が redirect を追う(`untrusted-redirect-following`)
- `commandAfterTerminator` の stray count 負値(`effect-cli.ts`)
- `recoveryStatus` が `ensureKeyMaterialAccess` で守られていない(`auth-api.ts`)

## 着手順(実施済み)

R7+R8 → R5 → R4 → R6 → R9 → R3 → R1 → R2 の順で実装した(当初の推奨順から、
R4 を R5 と同じカウンタ行の変更に合流させた点だけ変えている — 同じ 1 文に
バケット化と上限判定が載るため、分けると同じコードを 2 度書き換えることになる)。

## 次の deepsec 実行時の注意

本文書の 8 論点は実装済みだが、deepsec の再検証は**まだ通していない**。次回は
`scan` → `process --reinvestigate` → `revalidate --force` で、これらが `fixed`
判定になることを確認してから close すること。今回変更したファイルは:

- `apps/server/src/`: `handlers-auth.ts` / `handlers-audit.ts` / `worker-env.ts` /
  `chain-do.ts` / `programs-audit.ts` / `audit-store.ts` /
  `db.package/{audit,repos,schema}.ts` / `wrangler.jsonc` / drizzle migration
- `apps/cli/src/`: `audit.ts` / `run.ts` / `keygen.ts` / `recovery.ts` / `session.ts`
- `packages/`: `api-schema/src/{audit,auth}-api.ts` / `core/src/audit.ts`
- docs: `AUDIT_SPEC.md`(§3.1 / §7)/ `SELF_HOSTING.md`

## 作業規律(前回から継続)

1. 1 論点または密接な同型だけを 1 PR にする。着手前に現行コード、仕様、ADR を読み、
   scanner の提案をそのまま実装しない。
2. Drizzle を触る R5、R6 はリポジトリサービス境界を守る。スキーマ変更(索引追加を
   含む)は drizzle migration の手順に従う。
3. 平文 secret、鍵素材、外部 provider ID をログや append-only 監査 actor に追加しない。
   攻撃 PoC をリポジトリへ置かない。
4. ユーザー向け文言は英語。完了時は固定 Bun(`.bun-version`)で `bun run check` を通す。
5. deepsec の再検証はローカルの Claude Max 認証が要る。Cloud 環境では修正と通常テストまで。
