# maruhi セルフホストガイド

自分の Cloudflare アカウントに maruhi サーバーを立てる手順。素の wrangler のみで完結する
(ADR-0012 のセルフホスト経路。Alchemy は不要)。所要はおよそ 10 分、うち maruhi 固有の
作業は GitHub OAuth App の作成だけ。

このガイドが初回セットアップウィザードの正である(AUTH_SPEC §3。ADR-0014:
セルフホストは上級者経路であり、検証済みのコピー&ペースト可能な手順書を最小の形とする)。
手順は 2026-08-10(セッション 19)に wrangler 4.120 で実デプロイ検証済み。
2026-08-11 改訂(手順 3 のマイグレーション統合・client_id の Workers Secret 化 —
AUTH_SPEC §3-2)は実デプロイでの再検証待ち。

## 立つもの

- **Workers**: `maruhi-server`(API サーバー。Effect HttpApi)
- **Durable Objects**: `ProjectChainDO`(プロジェクトごとのメンバーシップチェーン・
  暗号化データ・監査ログ。SQLite バック — Workers 無料プランで利用可)
- **D1**: `maruhi`(ユーザー・セッション・トークン等の認証系メタデータ)
- **cron**: 期限切れセッション行の日次掃除

シークレットの平文はどこにも置かれない(E2EE — サーバーは暗号文しか保存しない)。

## 前提

- Cloudflare アカウント(無料プランで可)
- GitHub アカウント(認証は GitHub OAuth のみ — AUTH_SPEC)
- Bun 1.3.14(リポジトリの `engines` にピン留め。wrangler は依存に含まれる)

## 手順

### 1. リポジトリ取得と Cloudflare 認証

```sh
git clone <このリポジトリ> && cd maruhi
bun install
cd apps/server
bunx wrangler login   # ブラウザで認可(CI では CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID)
```

テレメトリを送りたくない場合は `WRANGLER_SEND_METRICS=false` を環境に設定する
(maruhi 自身は一切のテレメトリを実装しない — CLAUDE.md「言わざる」)。

### 2. D1 データベース作成

```sh
bunx wrangler d1 create maruhi
```

出力される `database_id`(UUID)を `wrangler.jsonc` の `d1_databases[0].database_id`
(プレースホルダ `00000000-…`)に記入する。

### 3. 初回デプロイ(マイグレーション適用 + URL の確定)

```sh
bun run deploy   # = bun run db:migrate && wrangler deploy
```

deploy スクリプトは D1 マイグレーションの適用(バインディング名 `DB` を参照 —
DB 名を変えていても動く)とデプロイを常にこの順で行う。drizzle のフォルダ形式
(`drizzle/<name>/migration.sql`)は `wrangler.jsonc` の `migrations_pattern` で
wrangler にそのまま認識される。

出力の `https://maruhi-server.<あなたのサブドメイン>.workers.dev` を控える
(以下「`<デプロイ URL>`」はこの `https://` を含む URL 全体を指す)。
GitHub OAuth のコールバック URL はこのデプロイ URL から決まるため、**OAuth App の
作成より先にデプロイする**(この時点ではまだ OAuth 未設定なので、認証系エンドポイントは
503 `SetupIncomplete` を返す — 正常)。

### 4. GitHub OAuth App 作成

https://github.com/settings/applications/new で作成する:

| 項目 | 値 |
|---|---|
| Application name | 任意(例: `maruhi (self-hosted)`) |
| Homepage URL | 手順 3 のデプロイ URL |
| Authorization callback URL | `<デプロイ URL>/auth/github/callback` |
| **Enable Device Flow** | **必ずチェックする**(CLI ログインが device flow — チェック漏れが最頻の詰まりどころ) |

作成後、client_id を控え、"Generate a new client secret" で client_secret を発行する。

### 5. client_id / client_secret の登録

両方とも Workers Secret として登録する(**リポジトリ・設定ファイルに書かない**。
client_id は公開情報だが、登録経路を secret に統一することで `wrangler.jsonc` の
編集と再デプロイを不要にしている — AUTH_SPEC §3-2):

```sh
bunx wrangler secret put GITHUB_CLIENT_ID       # プロンプトに貼り付け
bunx wrangler secret put GITHUB_CLIENT_SECRET   # 同上
```

`secret put` は即時反映される(再デプロイ不要)。

### 6. 動作確認

```sh
curl <デプロイ URL>/auth/config
# → {"githubClientId":"<あなたの client_id>"} なら設定完了
#   (200 は client_id / client_secret の両方が登録済みであることを意味する)
# → 503 {"_tag":"SetupIncomplete",...} なら手順 5 の secret put 漏れ
#   (登録済み一覧は `bunx wrangler secret list` で確認できる — 値は表示されない)
```

### 7. CLI から接続

```sh
maruhi config set server <デプロイ URL>
maruhi login          # client_id はサーバーから自動解決(GET /auth/config)
maruhi key generate   # 初回のみ: master 鍵の生成 + リカバリーコード発行(人間の端末で)
```

以降は `maruhi project init` → `maruhi env create` → `maruhi push` / `maruhi run` へ。

## サーバー鍵の設定(オプション — `maruhi server grant` の前提)

サーバー宛の鍵ラップ(CRYPTO_SPEC §9 — プロジェクト owner が明示的に
`maruhi server grant` した環境の DEK をサーバーへ開示する機能)を使う場合のみ
必要。使わない限りこの節は丸ごと飛ばしてよい(未設定でも他の全機能は動き、
サーバーは暗号文の保管庫のまま)。

### 鍵素材(IKM)の登録

32 バイトの乱数を hex(64 文字)で生成し、Workers Secret として登録する:

```sh
openssl rand -hex 32 | bunx wrangler secret put SERVER_ENC_KEY_IKM
```

サーバーはこの IKM から X25519 鍵ペアを決定論的に導出する(RFC 9180
DeriveKeyPair)。IKM は秘密鍵素材そのものなので**手元に控えを残さない**
(パイプで直接登録し、シェル履歴・ファイルに残さない)。

### フィンガープリントの控え(照合の基準づくり)

登録後、サーバー鍵のフィンガープリント(FP)を確認して安全な場所に控える:

```sh
curl <デプロイ URL>/auth/config
# → {"githubClientId":"...","serverKeyFingerprintHex":"<hex 32 文字>","serverEncPubHex":"<hex 64 文字>"}
```

`maruhi server grant` は開示に先立ち、サーバーが配布する鍵の FP を 12 語の
ワード列で表示して所有者に確認を求める(CRYPTO_SPEC §9 の確認の儀式)。その
照合基準がこの控えである(非対話実行では `--expect-fingerprint <hex 32 文字>` に
渡す)。デプロイ直後の、経路の確かなうちに控えるのがこの手順の要点。

### IKM の変更 = サーバー鍵の変更

`SERVER_ENC_KEY_IKM` を put し直すとサーバー鍵そのものが変わる(旧鍵宛の
ラップは新鍵では開封できず、FP も変わる)。既に grant 済みのプロジェクトが
ある状態で変更した場合は、各プロジェクトで `maruhi server revoke` →
`maruhi server grant` をやり直すこと(revoke は全環境の強制ローテーションを
伴う — CRYPTO_SPEC §7)。

## 推奨する堅牢化(オプション): 未認証エンドポイントのレート制限

maruhi の未認証エンドポイントは次の 2 つで、いずれもサーバー側の防御
(形式事前検査・プロジェクト単位の固定窓)を持つが、**送信元 IP 単位**の
制限は Cloudflare 側でしか掛けられない。ダッシュボードの
Security → WAF → Rate limiting rules で以下の追加を推奨する
(Free プランでも 1 ルール作成できる):

| パス | 推奨制限 | 理由 |
|---|---|---|
| `/auth/device/exchange` | 10 リクエスト / 分 / IP | リクエストごとに GitHub check-token API へのアウトバウンド呼び出しを伴い、その枠は OAuth App 単位。形式を満たすトークンの洪水で枠が枯れると正規ユーザーのログインが失敗する(形式不正はサーバー側で 400 即応済み) |
| `/projects/*/environments/*/lease` | 60 リクエスト / 分 / IP | サーバー側の窓(300 発/時)はプロジェクト単位で、送信元を選ばない。CI の正常リトライを妨げない程度の per-IP 上限を足すと、単一送信元の暴走・嫌がらせを手前で吸収できる |

正規の CI(GitHub Actions)は送信元 IP が分散しているため、per-IP 制限が
正常運用を妨げることは実際上ない。

## 更新(バージョンアップ)

```sh
git pull
bun install
cd apps/server
bun run deploy   # マイグレーション適用 → デプロイ(常にこの順で自動実行)
```

手順 2 で行った `wrangler.jsonc` のローカル編集(`database_id`)は自分のフォークに
コミットしておくこと(upstream 側でこのファイルが更新されると `git pull` が
未コミットの編集と衝突する。コミットしない運用なら pull 後に再適用する)。
client_id / client_secret は Workers Secret 側に保存されているため更新の影響を受けない。

**2026-08-11 改訂をまたぐ更新(1 回だけの移行作業)**: 旧手順では client_id を
`wrangler.jsonc` の `vars.GITHUB_CLIENT_ID` に記入していた。旧手順で立てた
インスタンスは、この改訂以降のコードへ更新してデプロイする**前に**
`bunx wrangler secret put GITHUB_CLIENT_ID` で client_id を Workers Secret として
登録すること(新しい `wrangler.jsonc` には vars がないため、未登録のままデプロイ
すると認証系エンドポイントが 503 `SetupIncomplete` になる。その場合も secret put
すれば即時復旧する — 再デプロイ不要)。あわせて、`git pull` のマージ衝突を解消する
際は自分のフォークの `vars.GITHUB_CLIENT_ID` ブロックを**残さず削除**(upstream 側を
採用)すること — vars が残っていると、デプロイのたびに登録済みの同名 secret が
vars の値で置き換えられて移行が無効になる(対話デプロイでは wrangler が確認を
求めるが、非対話デプロイでは**警告のみで続行する** — `--strict` 指定時を除き
エラーにはならないため、警告の見落としに注意)。

## トラブルシューティング

- **`/auth/config` / `/auth/github/start` / `/auth/device/exchange` が 503
  `SetupIncomplete`**: `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` のどちらかが
  未登録(`wrangler secret put` 漏れ — 手順 5。旧手順で立てたインスタンスの
  更新後に起きた場合は「更新」節の移行作業を参照)。登録済みシークレットの一覧は
  `bunx wrangler secret list` で確認できる(値は表示されない)
- **CLI ログインで GitHub が `device_flow_disabled` を返す**: OAuth App の
  "Enable Device Flow" が未チェック(手順 4)
- **ブラウザログインで GitHub のエラーページに飛ぶ**: コールバック URL の不一致。
  OAuth App の Authorization callback URL が `<デプロイ URL>/auth/github/callback` と
  一致しているか確認する(http/https・末尾スラッシュ・サブドメインまで完全一致)
- **`bun run deploy` のマイグレーション適用が `couldn't find DB` を返す**:
  `database_id` の記入漏れ(手順 2)
- **`/auth/config` に `serverKeyFingerprintHex` が出ない /
  `maruhi server grant` が「デプロイメント keypair が設定されていません」**:
  `SERVER_ENC_KEY_IKM` が未登録、または値が hex 64 文字になっていない
  (形式不正は「未設定」として扱われる — 503 にはならない)。
  `openssl rand -hex 32` の出力をそのまま `wrangler secret put` すること
  (改行や引用符の混入に注意)

## 備考

- **client_secret のローテーション**: GitHub 側で新 secret を発行 →
  `wrangler secret put GITHUB_CLIENT_SECRET`(put は即時反映。再デプロイ不要)→
  GitHub 側で旧 secret を削除
- **独自ドメイン**: `wrangler.jsonc` に `routes` を追加してよい。OAuth コールバックは
  リクエスト origin から導出されるため、**GitHub OAuth App のコールバック URL も
  同じドメインへ更新する**こと
- **Deploy to Cloudflare ボタン**: リポジトリ公開(Phase 2)後に README へ設置予定。
  ボタン対応の前提工事(マイグレーションの deploy 統合・バインディング名参照・
  client_id の secret 化 = デプロイ後の設定が secret put ×2 だけで完結)は済んでいる。
  未検証点は 3 つあり、公開リポジトリでしか検証できないため公開時に実検証する:
  ① ボタンのモノレポ対応(リポジトリルート URL で `apps/server/wrangler.jsonc` が
  検出され D1 が自動プロビジョニングされるか)。② ボタンのビルドパイプラインが
  `apps/server` の `deploy` スクリプト(マイグレーション込み)を実行するか —
  既定の素の `wrangler deploy` に落ちるとマイグレーション未適用のまま公開され、
  DB を触る全エンドポイントが 500 になる。セットアップページで deploy コマンドの
  上書き指定が必要になる可能性が高い。③ コミット済みのプレースホルダ
  `database_id`(`00000000-…`)をボタンのプロビジョニングが実 ID へ差し替えるか —
  Cloudflare のドキュメントは既定値の記載を推奨し「新規作成リソースの ID で
  構成を更新する」とあるが、wrangler 単体の自動プロビジョニングは database_id が
  埋まっているとその UUID をそのまま参照するため、ボタン側が差し替えない場合は
  存在しない UUID への API エラーで失敗する(その場合プレースホルダの削除が必要)
- 認証以外も含む API 仕様は `docs/AUTH_SPEC.md`、暗号仕様は `docs/CRYPTO_SPEC.md` を参照
