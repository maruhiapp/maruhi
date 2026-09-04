# 競合比較 — maruhi vs Phase / Infisical / Doppler / Shelve / Keyway

Status: 2026-09-04 起草(内部メモ。ADR-0014 Context の競合整理〔2026-08-07〕を、各社の公開情報で裏取りして更新したもの)。
競合側の事実は各社の公式サイト・docs・GitHub を 2026-09-04 時点で確認した。**[未確認]** と付けた項目は公開情報から確定できなかったもの。
maruhi 側の事実は CRYPTO_SPEC / AUTH_SPEC / ADR / ROADMAP / SELF_HOSTING の現状に基づく(pre-release。招待制ベータ前)。

> **訂正**: 依頼で挙がった `keyway.ai` は商業不動産向け AI 企業(KeyDocs / KeyComps 等)で、シークレット管理の Keyway ではない。
> シークレット管理の Keyway は **`keyway.sh`**(GitHub org `keywaysh`)。本書はそちらを扱う。

---

## 0. 結論(先に全体像)

maruhi の差は「機能の数」ではなく **信頼モデルの既定値** にある。5 社を「誰が平文を見られるか」で並べると次のようになる。

| | 既定の暗号モデル | 運営(サーバー)は値を読めるか | 復号器を配る Web があるか |
|---|---|---|---|
| **maruhi** | **E2EE(ゼロ知識)が既定**。サーバーはプロジェクト単位・owner 署名のオプトイン(`grant_server`)でのみ「メンバー N+1」になる | **読めない**(grant した環境の DEK のみ例外。grant 中は常時明示) | **ない**(ADR-0018: hosted Web は鍵・平文を持たない。復号は各人の CLI のみ) |
| Phase | E2EE が既定。ただし同期・REST API・外部 ID には SSE(環境ルート鍵のサーバー保存)の有効化が必要 | 既定は読めない。SSE 有効化で読める | ある(Web コンソールがブラウザ内で復号) |
| Infisical | **サーバー側暗号化**(2023-06 に E2EE を廃止) | 読める | ある(ダッシュボードは平文を受け取る) |
| Doppler | **サーバー側暗号化**(GCP KMS/HSM でラップ) | 読める(Enterprise の EKM で顧客 KMS 経由に限定可) | ある |
| Shelve | **サーバー側暗号化**(プロジェクト DEK + プラットフォーム KEK) | 読める | ある |
| Keyway (.sh) | **サーバー側暗号化**(分離した Go 暗号サービス。「ゼロ知識ではない」と自ら明記) | 読める(「運営を信頼することになる」と threat model に明記) | ある |

これに **ディスクレスの不変条件**(`.env` を生成する機能を製品として持たない)、**サーバーレス一発セルフホスト**(Cloudflare 無料枠で `wrangler deploy`)、**テレメトリゼロ**、**エージェント隔離の fail-closed 既定** が重なる。この 5 点の「同時成立」が maruhi だけの組み合わせであり、個々の要素は競合にも部分的にある(ADR-0014 の補正「ディスクレス run 単体では差別化にならない」は今回の調査でも変わらない)。

一方で、機能の広さ(同期先・SDK・ローテーション・動的シークレット・PKI)、実績(★数・顧客・SOC 2)、非 GitHub 認証、Windows、値を扱える GUI では明確に劣後する。§4 に正直に列挙する。

---

## 1. 各社の要約(2026-09-04 時点)

### Phase(phase.dev — Phi Security Inc.)
- 位置づけ: "Secrets management for teams and AI agents"。GitHub ★913(2023-05 創設)。SOC 2 Type II(2025-11)。Pre-seed(2025-07)。ホスティングは AWS eu-central-1 のみ
- 暗号: **E2EE 既定**。libsodium(XChaCha20-Poly1305 / X25519 / Ed25519 / Argon2id / BLAKE2b)。リカバリーは BIP39 24 語。環境ごとの鍵ペアにユーザー公開鍵へラップ。**ただし** Secret Syncs(GitHub Actions / Vercel / AWS SM…)・公開 REST API・External Identities(AWS IAM / Azure)は **SSE(サーバー側暗号化)を有効化**しないと使えず、その環境のルート鍵の複製がサーバーに保存される。"Sealed" 型(write-once・読み戻し不可)あり
- セルフホスト: Docker Compose / Helm / 各クラウド。**PostgreSQL + Redis(Valkey)+ Django backend + worker + frontend + nginx**。サーバーレス選択肢なし。EE 機能はライセンスキー
- CLI(2026-03 に Go へ書き換え): `phase run -- <cmd>`(メモリ注入)、`phase shell`、**`phase secrets export`(dotenv / json / yaml / toml … 10 形式)**、オフラインモード(API 応答の暗号化キャッシュをローカル保存)
- ライセンス: MIT + `ee/` は独自 Enterprise ライセンス(open-core)
- エージェント: `phase ai enable` が SKILL.md を配置(Claude Code / Cursor / Copilot)。CLI がエージェントを検出し、既定で値を `[REDACTED]` マスク、`phase shell` と `printenv` 等を `phase run` 内でブロック。**MCP サーバーなし**。ホームページの「AI egress proxy(デコイ値を渡し通信境界で実値に差し替え)」は **docs・changelog・コードに見当たらない [未確認 — マーケティング先行]**
- 価格: Free(5 ユーザー/SA・3 apps・3 環境)/ Pro $10/user/月(年払い)/ Enterprise $25
- テレメトリ: セルフホストは「外部送信なし」と明記。CLI にも telemetry の痕跡なし

### Infisical(infisical.com)
- 位置づけ: "Security infrastructure for developers and AI agents"。secrets + PKI + SSH + KMS + PAM の統合基盤。GitHub ★29,102(2022-08)。Series A $16M(2025-06、Elad Gil)。SOC 2 Type II / HIPAA / FIPS 140-3。US / EU リージョン
- 暗号: **サーバー側エンベロープ暗号化**(`ENCRYPTION_KEY` → KMS root → org / project データ鍵 → AES-256-GCM)。外部 KMS(AWS KMS / CloudHSM / GCP KMS)対応。**2023-06 に E2EE をオプトアウト可能にし、現行の security docs はサーバー側モデルのみ**を記述("E2EE は must-have ではなく nice-to-have と受け取られた")
- セルフホスト: Docker 単体 / Compose / Helm / ECS Fargate / GKE。**PostgreSQL 14+ と Redis が必須**(Redis なしでは起動拒否)。推奨 2〜4 vCPU / 4〜8 GB。EE は license server へ疎通(オフラインライセンスあり)
- CLI: `infisical run -- <cmd>`(`--watch` で再起動)、**`infisical export --output-file`(dotenv 等をディスクへ)**、**Infisical Agent(サイドカーがテンプレートでシークレットをファイルに描画)**
- 統合: 最も広い。マシン ID 認証(Universal / K8s / AWS / Azure / GCP / **OIDC〔GitHub Actions 文書化〕** / SPIFFE)、K8s Operator、Secret Syncs 多数、SDK 9 言語、Terraform / Pulumi / Ansible
- チーム: RBAC・承認ワークフロー・一時アクセス・SAML / LDAP / SCIM・監査ログ・PITR・**ローテーション・動的シークレット**・PKI(ACME)・SSH 証明書・KMS・PAM(セッション録画)
- エージェント: **MCP サーバー**(`get-secret` は平文を返す)、**Agent Vault**(OSS・HTTPS_PROXY 型の MITM credential proxy、2026-04)、**Agent Proxy**(GA 2026-07-30。ダミー資格を通信境界で実値に差し替える broker。全プランで利用可)
- ライセンス: MIT + `ee/` は独自 Enterprise ライセンス(open-core)。CLI MIT・MCP Apache-2.0
- 価格: Free(5 identities・3 環境)/ Pro $20/identity/月 / Advanced $40 / Enterprise
- テレメトリ: サーバー `TELEMETRY_ENABLED` **既定 true**(opt-out)。CLI は PostHog 組み込み(`--telemetry` フラグ。既定値は未確認)

### Doppler(doppler.com)
- 位置づけ: "Secrets management for humans and AI agents" / "Per-Seat Secrets Management. No Agent Fees."(旧 SecretOps から AI エージェント / 非人間 ID 訴求へ)。76,000+ orgs(自称)。Series A $20M(2022)。SOC 2 / ISO 27001(2025-09)。GCP us-central1 のみ(EU リージョンなし)
- 暗号: **サーバー側暗号化**。AES-256-GCM、ワークスペース鍵を GCP KMS(HSM)でラップ、トークナイゼーションサービスで Web 層から鍵を分離。バックエンドが復号し、ダッシュボード・API・CLI・全同期先が平文を受け取る。Enterprise の EKM で顧客 KMS を挟める。Doppler Share(単発共有)だけはブラウザ E2EE
- セルフホスト: 歴史的にクラウド専用。**2026-06-08 に「Doppler On-prem」を Enterprise 限定で発表**(パッケージ形態は未公開)
- CLI(Apache-2.0): `doppler run -- <cmd>`、`--mount`(名前付きパイプ)。**`doppler secrets download --format=env|json|yaml`(ディスクへの `.env` 出力)**。**`doppler run` は既定で `~/.doppler/fallback` に暗号化スナップショットを書く**(PBKDF2 + AES-256-GCM。パスフレーズ既定はトークン等から導出)
- 統合: 最多クラス(GitHub Actions / GitLab / CircleCI、AWS / GCP / Azure、Vercel / Netlify / Heroku / Railway / Render / Fly / Cloudflare Pages、K8s Operator、Terraform〔OIDC 認証 2026-06〕)。OIDC Service Account Identities(GitHub Actions / K8s / GitLab / AWS)
- チーム: RBAC(カスタムロールは Enterprise)、Change Requests(差分レビュー・承認)、ローテーション(Lambda 経由)、動的シークレット(Enterprise)、活動ログ + ロールバック、SIEM 転送
- エージェント: 公式 MCP サーバー(experimental。平文の読み書き可。MCP 操作を監査にタグ付け)。`/agents` ページ(ブランチ config + 読み取り専用の期限付きトークン)。**エージェント検出 / 拒否モードなし**
- 価格: Developer(3 ユーザーまで無料、以後 $8)/ Team $21/user/月 / Enterprise
- テレメトリ: CLI の `analytics` フラグは **既定 on**(`doppler configure flags disable analytics` で無効化。収集内容は未文書化)

### Shelve(shelve.cloud — HugoRCD、Apache-2.0)
- 位置づけ: "Open-source secret & environment management"。Nuxt / Vue エコシステムの個人・小チーム向け。v3 から「AI エージェントを first-class citizen」に。★452(2024-02 創設)。単独メンテナ中心(Hugo Richard)。企業・資金調達の開示なし。v3.1〜3.4 を 2026-05〜08 にリリース、活発
- 暗号: **サーバー側 2 層エンベロープ**(プロジェクト DEK を `iron-webcrypto` AES-256-GCM、DEK は `NUXT_PRIVATE_ENCRYPTION_KEY` の KEK で封印)。サーバーが復号。E2EE / ゼロ知識の主張はない。リカバリーは DB バックアップのみ
- セルフホスト: **Vercel が公式推奨**。Nuxt / Nitro + PostgreSQL(Neon 推奨)+ Resend または GitHub / Google OAuth。Docker イメージは landing に記載があるが Dockerfile・docs が見当たらない **[未確認]**。サーバーレス Edge(Workers)選択肢なし
- CLI(`@shelve/cli`): `shelve run -- <cmd>`(メモリ注入。ただし **`~/.shelve/cache/` に AES-256-GCM 暗号化キャッシュを 24h 保存**)、**`shelve pull` は平文 `.env` をディスクへ書く**(monorepo は package ごとに展開)、`push` はローカル `.env` を送信、`diff` / `sync` / `generate`(`.env.example`)
- 統合: GitHub App → GitHub Actions secrets への push のみ
- チーム: Owner / Admin / Member、スコープ付き API トークン(IP CIDR 制限・期限)、監査ログ(actor・IP・UA)。**バージョン履歴 / ロールバックは未文書化**
- エージェント: std-env でエージェント検出(Cursor / Claude / Codex)。**エージェント下の `shelve pull` は `--yes` なしで `AGENT_BLOCKED`**(maruhi の ADR-0016 決定 7 と同系の発想)。`shelve init` が `.cursorignore` 等 5 種を生成。Agent Skill を `/.well-known/skills/` で配布。MCP なし。JSON 出力に値を含めない
- 価格: 価格ページなし。hosted は「現在無料」
- テレメトリ: コード・docs に痕跡なし(「文書化された保証」ではなく「見当たらない」)

### Keyway(keyway.sh — Nicolas Ritouet 個人)
- 位置づけ: "Your secrets don't belong in AI context." / "GitHub-native secrets management. Repo access = secret access."。創業者が Claude に `.env` の DB パスワードを補完されたのが起点(2025-12 記事)。★8(monorepo 2025-11 創設、2026-02 統合)。単独開発(ほぼ全コミットが Claude 共著)。資金調達なし。Keyway Cloud は Railway・EU
- 暗号: **サーバー側 AES-256-GCM**。暗号化は分離した Go gRPC「crypto service」(約 300 行・private network)で行い「鍵は API サーバー・DB・公開面に触れない」と主張。ただし API サーバーは平文を一時的に扱い、API / ダッシュボードは平文を返す。**threat model が「Keyway Cloud を使うことは運営を信頼すること」と明記(ゼロ知識ではない)**。セルフホストの `ENCRYPTION_KEY` は「デプロイ後ローテ不可」(SELF-HOSTING.md)と「無停止ローテ可」(threat model)で記述が矛盾
- セルフホスト: Docker Compose 5 サービス(postgres / Go crypto / Fastify / Next.js / Caddy)+ GitHub App 必須。サーバーレスなし
- CLI(Go): `init` / `push`(`.env` を送信)/ **`pull`(既定で `.env` をディスクへ)**/ `run -- <cmd>` / `set` / `diff --show-values` / `scan`(リーク検知)。`KEYWAY_DISABLE_TELEMETRY`
- 統合: Vercel / Netlify / Railway 双方向同期、GitHub Actions(`keyway-action`。`.env` 書き出しも可)
- チーム: 独立したユーザー管理なし。**権限 = GitHub リポジトリロールのミラー**(production は既定 admin のみ write)。活動ログ(Free 7 日 → Team 90 日)、バージョン履歴 / ロールバック
- エージェント: MCP サーバー(`@keywaysh/mcp`。**`keyway_get_secret` は平文をモデルに返す**)。エージェント検出なし。threat model 自身が「`keyway run` の中でエージェントを動かせば秘密はそのプロセス環境にある」と認める。訴求(AI-Proof)と実装の間に乖離
- ライセンス: **monorepo に LICENSE ファイルなし**(GitHub API `license: null`)。アーカイブ済み旧リポは MIT。サイトは「MIT」「BSD-3」と記述が割れる **[未確認 — 法的には未定]**
- 価格: 3 系統の記述が併存(トップ €0/€9/€19/€39、docs $4/$15/$39、2026-07 コミットで「Pro 廃止・フラット化」)**[未確認]**
- テレメトリ: CLI に PostHog **既定 on**(opt-out)。ダッシュボードも PostHog(セルフホストでは任意)

---

## 2. 比較表

凡例: ● = あり / 既定、◐ = 条件付き・部分的、○ = なし、— = 該当なし・不明。maruhi 列は **実装済み** を基準にし、ROADMAP のみの項目は「予定」と書く。

### 2-1. 信頼モデル・暗号

| 観点 | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| 既定でゼロ知識(運営が値を読めない) | ● | ● | ○ | ○ | ○ | ○ |
| サーバー側復号の範囲 | プロジェクト × 環境単位の owner 署名オプトイン(`grant_server`)。チェーンに記録・全メンバー検証可・常時表示 | アプリ / SA 単位で SSE 有効化(同期・API・外部 ID に必須) | 全体 | 全体(EKM で顧客 KMS を挟める) | 全体 | 全体 |
| 復号器を運営が配る Web | ○(ADR-0018。Web は読み取り + 失効のみ。バンドルに復号コードパスを含めない) | ●(ブラウザ内復号) | ●(平文受信) | ● | ● | ● |
| 公開された暗号仕様 | ● CRYPTO_SPEC(唯一の正・テストベクター付き・保証 / 非保証を §14 で明示) | ◐ architecture / cryptography docs | ◐ security internals | ◐ Security Fact Sheet | ◐ encryption.md | ◐ security / threat-model |
| 独自プリミティブの不使用 | ● WebCrypto + HPKE(RFC 9180) | ● libsodium | ● | ● | ● iron-webcrypto | ● Go stdlib |
| メンバーシップの暗号的束縛 | ● 署名付きハッシュチェーン(role・招待受諾・server grant が append-only で全メンバー検証可) | ◐ 「cryptographic enforcement」の RBAC(詳細は未公開) | ○(DB 上の RBAC) | ○ | ○ | ○(GitHub ロールをミラー) |
| 値・メタデータの真正性(サーバー単独で偽造不能) | ● 値署名・DEK コミットメント・マニフェスト・チェックポイント(CRYPTO_SPEC §14.2) | ◐ | ○ | ○ | ○ | ○ |
| 巻き戻し / 欠落 / split view の検出 | ◐ ローカル床 + 帯域外アンカー + チェックポイント(限界は §14.3 に明示) | — | — | — | — | — |
| リカバリー | ● リカバリーコード(運営は復元不能。ADR-0014 決定 4) | ● BIP39 24 語 | —(サーバーが鍵を持つ) | —(アカウント MFA のみ) | —(DB バックアップ) | —(trash / 履歴) |
| 監査ログのアクター | 内部 user_id + 鍵 FP のみ(プロバイダ ID を書かない) | ユーザー | ユーザー | ユーザー | ユーザー + IP + UA | ユーザー |
| 監査ログの事後改竄検出 | ◐ チェックポイントに監査累積ハッシュを公証 | ○ | ○ | ○ | ○ | ○ |

### 2-2. ディスクレス・CLI

| 観点 | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| `run -- <cmd>` メモリ注入 | ● | ● | ● | ● | ● | ● |
| **`.env` 生成 / export 機能を製品として持たない** | **●(不変条件。将来も SOPS 互換の明示操作のみ)** | ○ `secrets export` 10 形式 | ○ `export --output-file` + Agent がファイル描画 | ○ `secrets download` | ○ `pull` が平文 `.env` を書く | ○ `pull` が既定で `.env` を書く |
| 平文 / 暗号化キャッシュをディスクに置かない | ●(永続化はトークン・master 鍵〔OS キーチェーン〕・非機密設定のみ) | ○ オフラインモードで暗号化キャッシュ | ◐(CLI にバックアップ削除関数あり [未確認]) | ○ 既定で `~/.doppler/fallback` に暗号化スナップショット | ○ `~/.shelve/cache/` に 24h | ● [未確認] |
| 値表示の既定 | `pull` はメタのみ。`pull --show` は TTY 一次境界 + エージェント検出の 2 層 fail-closed | マスク既定(エージェント検出時) | 表示 | 表示 | JSON 出力は値なし | `diff --show-values` |
| 値なしで動く「契約」機能 | ● 値なしスキーマ(`maruhi schema` / `schema export`〔JSON Schema〕/ `verify-snapshot` / `lint`)。required 充足は署名から検証可 | ○ | ○ | ○ | ◐ `generate`(`.env.example`) | ○ |
| CLI 実装 / 配布 | Bun コンパイル済み単一バイナリ(linux / darwin。Windows 実験的)+ npm(Bun 必須)。Homebrew は v0.1.0 から | Go | Go | Go | Node(Citty) | Go + npm + brew |
| CLI テレメトリ | **なし(「言わざる」)** | なし | PostHog 組み込み(既定値未確認) | **既定 on**(opt-out) | 痕跡なし | **既定 on**(opt-out) |

### 2-3. セルフホスト・運用

| 観点 | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| セルフホスト | ● | ● | ● | ◐ Enterprise 限定 On-prem(2026-06) | ● | ● |
| 必要な基盤 | **Cloudflare アカウントのみ**(Workers + DO SQLite + D1。**無料枠で可**) | Postgres + Redis + Django + worker + frontend + nginx | Postgres + **Redis 必須** + Infisical(2〜4 vCPU) | 非公開 | Vercel + Postgres(Neon)+ Resend / OAuth | Docker Compose 5 サービス + GitHub App |
| サーバーレス / Edge | ● | ○ | ○ | ○ | ◐(Vercel 上の Nuxt。Postgres は別) | ○ |
| デプロイ手順 | `wrangler deploy` 中心。約 10 分(SELF_HOSTING.md、実デプロイ検証済み) | Compose / Helm | Compose / Helm / ECS | — | Vercel + DB 設定 | Compose |
| 常設プロセスの運用(パッチ・DB 保守) | なし(マネージド) | あり | あり | — | DB はマネージド可 | あり |
| サーバーの外部送信 | なし(EE ライセンス検証も存在しない) | なし(offline license 可) | **`TELEMETRY_ENABLED` 既定 true** + EE は license server へ疎通 | — | 痕跡なし | PostHog(任意) |
| ホステッド版 | 準備中(招待制ベータ前。`my.maruhi.app`。無料 → GA で課金) | ● eu-central-1 | ● US / EU | ● us-central1 | ● 無料 | ● Railway EU |
| 認証 IdP | **GitHub OAuth のみ**(ADR-0009。WorkOS 挿入点は確保) | Google / GitHub / GitLab / Okta / Entra / Authentik + SCIM | SAML / LDAP / SCIM / OIDC | SSO(Team+)/ SCIM | Email OTP / GitHub / Google | GitHub のみ |
| コンプライアンス | なし(pre-release) | SOC 2 Type II | SOC 2 Type II / HIPAA / FIPS | SOC 2 / ISO 27001 | なし | なし |

### 2-4. チーム・統合・エージェント

| 観点 | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| ロール | チェーン上の 4 role(owner / admin / member / reader) | RBAC + 環境 / パススコープ | RBAC + カスタムロール + 承認 | RBAC + Change Requests | Owner / Admin / Member | GitHub ロールのミラー |
| 退職時の鍵ローテ | ● エポックローテーション(remove / 降格で全環境 rotate が義務)+ 要ローテーション検出 | ◐ | —(サーバー鍵) | — | — | — |
| CI 連携 | GitHub Actions のみ。**OIDC + 応答スコープの一時鍵ラップ(リース)**。サーバーは「DEK の仲介者」で値を復号しない・CI へ偽値を注入できない(§9.1)。リポジトリアンカーで CI 側も検証 | サービストークン(OIDC なし)。同期は SSE 必須 | OIDC(GitHub Actions 文書化)・K8s・AWS…・K8s Operator | OIDC Service Account Identities・K8s Operator | GitHub App が Actions secrets に push | `keyway-action`(`.env` 書き出しも可) |
| クラウド / PaaS 同期 | ○(予定なし。書き込み方向の攻撃面を持たない設計) | ● 多数(SSE 必須) | ● 最多 | ● 最多 | ○ | ◐ Vercel / Netlify / Railway |
| SDK | ○(HttpApi 導出クライアントのみ) | Node / Python / Go | 9 言語 | Node / Python | ○ | ○ |
| バージョン履歴 / ロールバック | ◐ version 単調・prev 連鎖(表示 UI は未) | ● + PITR | ● + PITR | ● | ○ | ● |
| ローテーション / 動的シークレット | ○(将来: 上流自動ローテ) | ● / ◐ AWS IAM のみ | ● / ● | ● / ● Enterprise | ○ | ○ |
| PKI / SSH / KMS / PAM | ○ | ○ | ● | ○ | ○ | ○ |
| 値ありの GUI | ○(ADR-0018。TUI → 値なし `maruhi ui` → 値ありは独立 ADR) | ● Web コンソール | ● | ● | ● | ● |
| Web ダッシュボード(鍵なし) | ● 読み取り + 失効のみ(W 系列実装済み。デザインパス DP 進行中) | ● | ● | ● | ● | ● |
| エージェント検出時の値表示拒否 | ● fail-closed 2 層(TTY 一次 + std-env) | ● マスク + `shell` / `printenv` ブロック | ○ | ○ | ● `pull` を `AGENT_BLOCKED` | ○ |
| MCP サーバー | ○(需要実測後に `maruhi schema` の薄いラッパとして。**値は配らない方針**) | ○(SKILL.md 方式) | ● 平文を返す | ● 平文を返す(experimental) | ○(Agent Skill 配布) | ● 平文を返す |
| credential brokering(エージェントに実値を渡さない) | ○ 予定(Phase 3 `maruhi proxy run`。E2EE と合成し「サーバーもエージェントも平文を持たない」) | ◐ 「AI egress proxy」を訴求するが実装未確認 | ● Agent Proxy(GA 2026-07)+ Agent Vault | ○ | ○ | ○ |
| 値なしスキーマのエージェント開示 | ● `maruhi schema`(名前・型・必須・説明のみ) | ○ | ○ | ○ | ○ | ○ |

### 2-5. ライセンス・価格・成熟度

| 観点 | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| ライセンス | サーバー / web = **FSL-1.1-MIT**(競合 SaaS 化のみ禁止・2 年後 MIT)。**CLI / crypto / core / api-schema = MIT**(復号器は OSI ライセンス) | MIT + `ee/` 独自(open-core) | MIT + `ee/` 独自(open-core) | 本体プロプライエタリ。CLI Apache-2.0 | Apache-2.0(全体) | **LICENSE なし**(記述が割れる)[未確認] |
| 無料枠 | セルフホスト無制限(CF 無料枠)。ホステッドはベータ期間無料 | 5 ユーザー / 3 apps | 5 identities / 3 環境 | 3 ユーザー | hosted 無料 | 1 private repo |
| 有料 | 未設計(GA 時) | $10〜25 / user | $20〜40 / identity | $8〜21 / user | なし | €9〜39(記述不一致) |
| 成熟度 | pre-release(v0.1.0-rc)。個人開発。実デプロイ検証・ドッグフーディング中 | ★913・SOC 2・Pre-seed | ★29k・Series A・cash-flow positive | 76k orgs・Series A | ★452・個人 | ★8・個人 |

---

## 3. maruhi の優位性(競合に対する差)

以下は「競合にない」または「競合が既定にしていない」性質。訴求はいずれも「絶対最安全」ではなく **「信じなくてよい相手の範囲が広い」**(ADR-0014 決定 1)で語る。

1. **ゼロ知識が既定で、例外が暗号的に可視**
   - Infisical / Doppler / Shelve / Keyway はサーバー側暗号化で、運営(またはサーバーを握った攻撃者)が値を読める。Phase は E2EE 既定だが、同期・REST API・外部 ID を使うと環境ルート鍵の複製がサーバーに保存される(SSE)。
   - maruhi の `grant_server` は Phase の SSE と同じ「サーバーをメンバーにする」操作だが、**owner 署名で append-only チェーンに載り、全メンバーが検証でき、grant 中は UI / CLI が常時明示し、`revoke_server + rotate_epoch` で取り消せる**。しかも CI リース経路ではサーバーは DEK の仲介のみで値を復号しない(CRYPTO_SPEC §9.1)。「どこまで開示したか」が監査ログでなく暗号で縛られる点は 5 社になし。

2. **運営が復号器を配らない(Web は TCB に入らない)**
   - 5 社すべてが「Web で値を見る」を提供する。E2EE の Phase も含め、運営が配信する JS が復号器である以上、配信側の悪意・XSS が全シークレット漏洩になる。maruhi は ADR-0018 でこれを構造的に断ち(hosted Web バンドルに復号コードパスを含めない・セッション主体の API を読み取り + 失効系に限定)、復号は MIT ライセンスの CLI(ソース検証・自己ビルド可)だけで行う。**「運営は読めない」の主張をコードで検証できる**のは maruhi だけ。

3. **ディスクレスが「機能」でなく「不変条件」**
   - ADR-0014 の補正どおり `run` 注入は全社にある。差は **`.env` を書く機能を製品として持たない**こと(Phase `export`、Infisical `export` / Agent、Doppler `download` + 既定の fallback ファイル、Shelve / Keyway の `pull` はいずれも平文または暗号化キャッシュをディスクへ置く)。maruhi は暗号化キャッシュも置かず、`pull` の既定はメタのみ、値表示は TTY 一次境界 + エージェント検出の 2 層 fail-closed。
   - 「`.env` から移行する」入口は `schema import`(明示引数の `.env` をクライアント側だけで読み、変数ごとに対話承認し、全宣言後に元ファイル削除を提案)として、**`.env` を正にしない方向の一方通行**で用意している。

4. **サーバーレス一発セルフホスト(運用ゼロ・無料枠)**
   - Phase / Infisical / Keyway は Postgres(+ Redis)+ 複数コンテナの常設運用、Shelve は Vercel + Postgres、Doppler は Enterprise 限定 On-prem。maruhi は **Cloudflare 無料枠に `wrangler deploy` で約 10 分**、パッチ・DB 保守・スケール運用が要らない。「セルフホストしたいが VM を面倒見たくない」層への回答は maruhi だけ。
   - サーバーのライセンス検証・license server 疎通も存在しない(Infisical EE は疎通あり)。

5. **テレメトリゼロ(「言わざる」)を保証として言える**
   - Doppler CLI・Keyway CLI は既定 on の分析、Infisical はサーバー telemetry 既定 on + CLI に PostHog。Phase はセルフホストの非送信を明記、Shelve は「痕跡なし」。maruhi はクライアント → 外部送信ゼロを絶対規則とし、install script も github.com 以外へ通信しない。運用観測(自サーバーのメトリクス)との線引きは hosted-design.md §5-1 で明文化済み。

6. **エージェント隔離が fail-closed で既定**
   - 現状の競合は 2 系統。(a) MCP で平文を渡す(Infisical / Doppler / Keyway。Keyway は「AI-Proof」と訴求しつつ MCP が平文を返す)。(b) 検出してマスク / ブロック(Phase・Shelve)。maruhi は (b) を **TTY 一次 + 既知エージェント二次の 2 層**で持ち、加えて **値なしスキーマ**(名前・型・必須・説明だけをエージェントに開示。required 充足は署名から検証可・`schema lint` でコードとの乖離検査)という「値を渡さずに契約だけ渡す」第 3 の形を実装済み。MCP は値を配らない薄いラッパとして後回し。
   - credential brokering(実値を通信境界で差し替え)は Infisical が先行(Agent Proxy GA)。maruhi は Phase 3 で `maruhi proxy run` を予定し、E2EE と合成して「サーバーもエージェントも平文を持たない」まで一貫させる点が差になる(Infisical の broker はサーバーが平文を持つ前提)。

7. **真正性・鮮度まで暗号で扱い、非保証を明示する**
   - 値署名・DEK コミットメント・メタステートメント・環境マニフェスト・チェックポイント・ヘッド申告により、サーバー単独では値・名前・DEK を偽造できず、巻き戻し・欠落・split view を(限界つきで)検出する。CI ワークロードもリポジトリアンカーで検証する。競合の docs にこの層はない。
   - 同時に CRYPTO_SPEC §14.3 が可用性・平文の正しさ・初回同期クライアントの鮮度・共謀の残余を**非保証として列挙**しており、脅威モデル文書(H5)の土台になる。競合の security ページは保証の列挙が中心で、非保証の明示はほぼない。

8. **監査ログにプロバイダ ID を書かない・退職時ローテが義務**
   - アクターは内部 user_id + 鍵 FP のみ(GitHub ID を append-only 構造に焼かない)。remove / 降格は全環境ローテーションを伴い、「要ローテーション検出」で実効性を補う。Keyway の「GitHub ロール = 権限」とは対極。

9. **ライセンス構成が信頼モデルと整合**
   - 復号を行う側(CLI / crypto / core / api-schema)は MIT、サーバーは FSL(競合 SaaS 化のみ禁止・2 年で MIT)。Phase / Infisical の open-core(`ee/` は本番利用に契約必須)、Doppler のプロプライエタリ、Keyway のライセンス未定と比べ、**「検証したい部分が OSI ライセンス」「セルフホストに制限なし」**が明快。

---

## 4. maruhi の劣後点(正直に)

訴求で隠すべきでない差(ADR-0014 決定 5「正直に切り分ける」)。

- **成熟度・実績**: pre-release、個人開発、ユーザー 0、SOC 2 等なし。Infisical(★29k・Series A)・Doppler(76k orgs)とは桁が違う。Phase も SOC 2 済み
- **統合の幅**: クラウド / PaaS 同期なし(設計上、書き込み方向の攻撃面を持たない選択でもある)、SDK なし、K8s Operator なし、CI は GitHub Actions のみ。Infisical / Doppler は数十の同期先
- **認証**: GitHub OAuth のみ。SSO / SAML / SCIM なし(WorkOS 挿入点は確保 — ADR-0009)
- **値を扱う GUI がない**: Web は読み取り + 失効のみ。値の投入・閲覧・招待受諾・鍵操作はすべて CLI。「ダッシュボードで値を見たい」層には不向き(ADR-0018 の意図的な選択だが、採用の障壁になる)
- **ゼロ知識の儀式**: 初回の鍵生成・リカバリーコード保管、招待時の指紋相互確認、端末移行。競合(特にサーバー側暗号化の 4 社)にはない手間。「初回と招待だけ」と切り分けて示す
- **鍵とリカバリーコードを失えば運営は復元できない**(約束の対価)
- **エンタープライズ機能**: ローテーション・動的シークレット・承認ワークフロー・PKI / SSH / KMS / PAM なし。Infisical は統合基盤、Doppler は Change Requests、Phase もローテ・動的シークレット済み
- **credential brokering / MCP は未実装**(Infisical は Agent Proxy GA、Doppler / Keyway は MCP 済み)。エージェント訴求の「今すぐ試せる」面では値なしスキーマ + agent-gate のみ
- **プラットフォーム依存**: Cloudflare 専用(Workers / DO / D1)。オンプレ・他クラウドで動かせない。競合は Docker があればどこでも
- **Windows 実験的**、Homebrew 未公開、macOS 公証未、checksums 未署名
- **ホステッド版が未開放**(HP1 の「最初の 5 分」はまだ提供できない)。競合 5 社はすべて hosted を提供中
- **FSL は OSI オープンソースではない**(サーバー側)。「open source」を名乗る Phase / Infisical / Shelve と並べると注記が要る

---

## 5. 競合別の一言(誰に対して何を言うか)

| 相手 | 体験の近さ | maruhi が言うべき差 |
|---|---|---|
| **Phase** | 最も近い(E2EE 既定・エージェント検出・Ed25519 / X25519)。**本命の比較対象** | 「同期や API を使う瞬間に SSE で鍵の複製がサーバーに載る」に対し、maruhi は grant がチェーンに署名付きで残り、CI リースではサーバーが値を復号しない。Web で復号しない。Postgres + Redis 不要。テレメトリは両者ゼロ |
| **Infisical** | 本命競合(vault + diskless run + agent proxy) | 2023 年に E2EE を捨てた(運営・MCP・ダッシュボードが平文)。Redis 必須の常設運用。telemetry 既定 on。maruhi は「運営にも見せない」を既定に戻し、`.env` を書く機能を持たない |
| **Doppler** | 体験は洗練・統合最多 | 完全サーバー側 + クラウド専用(On-prem は Enterprise)。`run` が既定で fallback ファイルを書く。CLI analytics 既定 on。EU リージョンなし。maruhi は自分の CF アカウントに立つ |
| **Shelve** | OSS・個人開発・軽さの点で近い。エージェント下 `pull` ブロックも同系 | サーバー側暗号化で運営が読める。`pull` が平文 `.env` を書き、`run` も暗号化キャッシュを置く。Vercel + Postgres。maruhi はゼロ知識 + ディスクレス不変条件 + Workers 一発 |
| **Keyway (.sh)** | 「AI に秘密を渡さない」訴求が同じ | 訴求と実装が乖離(MCP が平文を返す・エージェント検出なし・「ゼロ知識ではない」と自認)。LICENSE 未定・価格記述不一致・★8。maruhi は同じ訴求を fail-closed + 値なしスキーマ + E2EE で実装済み |

---

## 6. 位置づけの一文(ADR-0014 の売り文句の現行形)

> **maruhi は、運営にも・配られた Web にも・エージェントにも平文を渡さないことを既定にした、`.env` を書かない secrets 管理。自分の Cloudflare アカウントに `wrangler deploy` 一発で立ち、何も外へ送らない。**

段階: 「運営に平文を見せない」(現在)→「運営にもエージェントにも平文を渡さない」(Phase 3: `maruhi proxy run`)→「人間が間違えても、秘密がそこにない」(no-reveal 方針化)。

---

## 6-1. LP / docs での使い方(2026-09-04 追記 — 所有者との対話の記録)

**訴求点(優先順)** — いずれも「仕組みを淡々と書く」(web-design-pass.md §2)・「絶対最安全」と言わない(ADR-0014 ガードレール):

1. 運営は値を読めない。それをコードで確かめられる(E2EE 既定 + 復号は MIT の CLI のみ + Web は復号器を持たない)
2. `.env` を書かない(`maruhi run` のメモリ注入のみ。生成・出力する機能そのものがない — 「ディスクレス run がある」ではなく「書く機能がない」が差)
3. 自分の Cloudflare アカウントに一発(`wrangler deploy` 約 10 分・無料枠・Postgres / Redis / 常設 VM なし)
4. 何も送らない(CLI もインストーラも github.com 以外へ通信しない。「言わざる」は直訳せず仕組みで書く)
5. エージェントには契約だけ渡す(`maruhi schema` = 名前・型・必須のみ。値表示はエージェント環境で fail-closed)
6. 保証しないことも書く(CRYPTO_SPEC §14.3 → 脅威モデル文書へリンク)

英語コピー案: "Secrets your vendor can't read. Not even us." / "Secrets that never touch disk. `maruhi run` and nothing else." / "One `wrangler deploy`. Your Cloudflare account. Zero telemetry."

**星取表の扱い** — 広い機能比較表は置かない(同期先・SDK・SSO・ローテーション・動的シークレット・GUI・SOC 2 で全滅に近く、行数で薄まる。ADR-0014「機能数でセキュリティを語らない」)。競合名を書いた表は陳腐化と紛争のリスク(Phase の egress proxy は近く実装されうる・Doppler On-prem は形態未公開・Keyway は価格もライセンスも記述が割れる)。

推奨する 2 段構え:
- **LP**: 競合名を出さず、列を「サーバー側暗号化の vault」「E2EE だが Web で復号する vault」「maruhi」の 3 型にした信頼モデル表 5 行(既定でゼロ知識か / 復号器を配る Web があるか / `.env` を書く機能があるか / 常設 DB が要るか / 外部送信があるか)。型で語れば陳腐化しない
- **docs**: 競合名付きの詳細比較は日付と出典つきの比較ページとして後で用意(Keyway の /vs/ ページの形)。本書 §2〜§4 が素材。§4 の劣後点も同じページに載せ、訴求点 6 と一貫させる

表示規律: LP でも「verified」の語は署名検証を実際に行う CLI の文脈以外で使わない(CRYPTO_SPEC §14.3-7)。「運営が読めない」は言えるが「安全性が証明された」は言えない。「On-prem」とは言わず "Runs in your own Cloudflare account" と正確に言う(狭義の On-prem = 自社 DC / air-gap は ADR-0001 の帰結として不可)。

## 7. 申し送り(この比較から出る示唆。決定ではない)

- Phase が「AI egress proxy」を訴求し Infisical が Agent Proxy を GA したことで、**credential brokering は 2026 年内に「あるのが普通」になる**見込み。`maruhi proxy run`(Phase 3 ②)の優先度を再確認する材料
- Keyway の「訴求と実装の乖離」は maruhi の脅威モデル文書(H5)で **「何を保証しないか」を先に書く**ことの価値を裏付ける
- Doppler の「Per-Seat, No Agent Fees」、Phase の「SA は無料」、Infisical の「per identity」— GA の課金設計(L9)では **マシン / エージェント ID の課金単位**が論点になる
- 5 社中 4 社が hosted を「無料枠あり」で提供。招待制ベータの「最初の 5 分」(H6)は競合の hosted 体験が比較基準になる
- 比較の再確認時期: Phase の egress proxy 実装、Doppler On-prem のパッケージ形態、Keyway の LICENSE が確定した時点

---

## 出典(2026-09-04 確認)

- Phase: https://phase.dev · https://phase.dev/security · https://phase.dev/pricing · https://phase.dev/changelog/ · https://docs.phase.dev/security/architecture · https://docs.phase.dev/security/cryptography · https://docs.phase.dev/console/apps · https://docs.phase.dev/cli/commands · https://docs.phase.dev/self-hosting · https://docs.phase.dev/self-hosting/configuration/envars · https://docs.phase.dev/integrations/agents/claude-code · https://docs.phase.dev/access-control/external-identities · https://github.com/phasehq/console(LICENSE, backend/ee/LICENSE)
- Infisical: https://infisical.com · https://infisical.com/pricing · https://infisical.com/docs/internals/security · https://infisical.com/docs/self-hosting/overview · https://infisical.com/docs/self-hosting/configuration/requirements · https://infisical.com/docs/self-hosting/configuration/envars · https://infisical.com/docs/self-hosting/ee · https://infisical.com/docs/cli/commands/run · https://infisical.com/docs/cli/commands/export · https://infisical.com/docs/integrations/platforms/infisical-agent · https://infisical.com/docs/documentation/platform/agent-proxy/overview · https://infisical.com/blog/infisical-update-june-2023 · https://infisical.com/blog/series-a · https://github.com/Infisical/infisical · https://github.com/Infisical/infisical-mcp-server · https://github.com/Infisical/agent-vault · https://github.com/Infisical/cli
- Doppler: https://www.doppler.com · https://www.doppler.com/pricing · https://www.doppler.com/security · https://www.doppler.com/agents · https://docs.doppler.com/docs/security-fact-sheet · https://docs.doppler.com/docs/enterprise-key-management · https://docs.doppler.com/docs/accessing-secrets · https://docs.doppler.com/docs/automatic-fallbacks · https://docs.doppler.com/docs/cli · https://docs.doppler.com/docs/environment-based-configuration · https://docs.doppler.com/docs/mcp · https://docs.doppler.com/docs/share-security · https://docs.doppler.com/changelog · https://github.com/DopplerHQ/cli
- Shelve: https://www.shelve.cloud/ · https://github.com/HugoRCD/shelve · https://shelve.cloud/raw/docs/core-features/encryption.md · https://shelve.cloud/raw/docs/cli/run.md · https://shelve.cloud/raw/docs/cli/agents-automation.md · https://shelve.cloud/raw/docs/cli/init.md · https://shelve.cloud/raw/docs/core-features/tokens.md · https://shelve.cloud/raw/docs/core-features/audit-logs.md · https://shelve.cloud/raw/docs/core-features/teams.md · https://www.shelve.cloud/docs/self-hosting/vercel · https://shelve.cloud/raw/docs/self-hosting/environment-variables.md · https://shelve.cloud/raw/docs/integrations/github.md
- Keyway: https://keyway.sh/ · https://keyway.sh/security · https://keyway.sh/threat-model · https://keyway.sh/articles/ai-coding-agents-secrets-security · https://docs.keyway.sh/cli · https://docs.keyway.sh/api · https://docs.keyway.sh/mcp · https://docs.keyway.sh/security · https://docs.keyway.sh/organizations · https://docs.keyway.sh/integrations · https://github.com/keywaysh/keyway(SELF-HOSTING.md, docker-compose.yml)· 参考(無関係の同名企業): https://www.keyway.ai/
- maruhi: docs/CRYPTO_SPEC.md(§1 / §9 / §14)· docs/AUTH_SPEC.md · docs/AUDIT_SPEC.md · docs/SELF_HOSTING.md · docs/adr/0002 / 0003 / 0009 / 0014 / 0016 / 0018 · docs/notes/hosted-design.md(§1 / §5-1)· ROADMAP.md
