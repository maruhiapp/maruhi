# maruhi セキュリティレビュー(2026-08-14)

- 対象リビジョン: 本編 = `9e30a56c4efa0c46435e15e4d53a7ff20d3567c8`、追補 = `de8f3af03291a33fa3c5634652040399ded37278`(差 = PR #63 の 67 ファイル / +8,596 行)、追補 2 = `6b839cc`(差 = PR #65 の 46 ファイル / +4,415 行)
- **時点の注意**: 本編のレビュー中に PR #63(Phase 2 Wave 2 A1 — grant_server 0.5 実装)が main へマージされた。本編の記述(特に指摘 M-1 と「検査済み」リスト)は **`9e30a56` 時点のツリー**に対するものであり、PR #63 の差分は文末の**追補(2026-08-15)**が対象とする。追補で状態が変わった箇所には本文中に注記を入れた
- 手法: 全レイヤーの静的レビュー(コード実行なし)。仕様書(`docs/CRYPTO_SPEC.md` v0.5-draft / `docs/AUTH_SPEC.md` v0.9-draft / `docs/AUDIT_SPEC.md`)と CLAUDE.md の絶対規則を判定基準とし、実装との乖離・一般的な脆弱性クラス(認証・認可・注入・CSRF・秘密漏洩・DoS・サプライチェーン)を検査した
- 対象範囲: `packages/crypto` / `packages/core` / `packages/api-schema` / `apps/server` / `apps/cli` / `apps/web` / `packaging` / `.github/workflows` / `.claude`
- 本レビューは指摘の記録のみを行う。修正は別途実施する(このファイルの「推奨対応」参照)

## 総評

**クリティカル(即時悪用可能)な脆弱性は発見されなかった。** 仕様と実装の整合性は極めて高く、暗号境界(E2EE)、認可(チェーン導出 role)、存在秘匿(404 統一)、DO の直列化(TOCTOU 対策)、CLI のディスクレス不変条件、Web の CSP、CI の最小権限・SHA ピン留めのいずれも仕様どおり丁寧に実装されている。SQL は全経路パラメタライズ済みで、サーバー・crypto パッケージにログ出力は一切ない。

指摘の中心は次の 2 点:

1. ~~承認済み仕様(0.5-draft)と実装の乖離の「危険な窓」(M-1)~~ — **PR #63 のマージで解決済み**(追補 §A-0 で実装を検証した。本編 M-1 は経緯の記録として残す)
2. **防御規律の一貫性の穴**: 特権 CI ワークフローのピン留め漏れ(M-2)、監査を伴う GET への CSRF ヘッダー未適用(L-1)など、他所では守られている自らの規律が一部に届いていない箇所

---

## 指摘一覧

| ID | 深刻度 | 対象 | 状態 | 要約 |
|---|---|---|---|---|
| M-1 | ~~Medium~~ | server / crypto | **解決済み(PR #63)** | 承認済み 0.5-draft 合意規則が未実装のまま `grant_server` を旧形式で受理できた(追補 §A-0 で解消を検証) |
| M-2 | Medium | CI | **修正済み(2026-08-15)** | `pullfrog.yml` が可変タグ参照のまま多数の AI プロバイダ API キーを保持(SHA ピン留め規律の例外) |
| L-1 | Low | server | **修正済み(2026-08-15)** | セッション認証の `GET …/pull`(var.read 監査を記録)に CSRF ヘッダー要求がなく、クロスサイトから監査記録を強制発火できる |
| L-2 | Low | server | **修正済み(2026-08-30 W3a)** | API トークンに有効期限がない(`expires_at` 常に NULL) |
| L-3 | Low | server | **緩和済み(2026-08-15)** | `/auth/device/exchange`(未認証)にレート制限がなく、GitHub check-token API の枠を第三者が消費できる(ログイン可用性) |
| L-4 | Low | server | 現 main でも有効 | `auth.login_failed` の記録上限がグローバル固定窓のため、洪水で標的型失敗の記録を抑制できる(設計文書化済み) |
| L-5 | Low | web / server | **修正済み(2026-08-15)** | HSTS 未設定(custom domain 時)・API 応答にセキュリティヘッダーなし |
| A-1 | Low | server / crypto | **是正済み(2026-08-15)** | 受信者クラスを跨ぐ識別子衝突(member の user_id = サーバー鍵 FP)でラップ完全集合の初回登録が defect(500)になり、当該環境のローテーション・作成が塞がる |
| I-1 | Info | packaging | — | `checksums.txt` が未署名(TLS のみ)— 文書化・ROADMAP 済みの追認 |
| I-2 | Info | server | — | チェーン追記ごとの全チェーン再検証(最大 10,000 × Ed25519)の DO CPU 上限内の実測未確認 |
| I-3 | Info | .claude | — | リモート開発環境の SessionStart フックが `curl \| bash` で Bun を導入(開発環境限定) |
| A-2 | Info | api-schema / docs | **解決済み(PR #65)** | `/auth/config` が返す `serverEncPubHex` が AUTH_SPEC §4 の応答定義に明記されていない(仕様先行規律の追随漏れ)→ PR #65 の `50452f6` が §4 へ明記 |
| A-3 | Info | cli | **修正済み(2026-08-15)** | `server grant --expect-fingerprint` は帯域外の控えを渡す前提であり、`/auth/config` から取った値を渡すと照合が自己言及になる(運用ドキュメントで明示すべき) |
| A-4 | Info | server | 新規(追補 2)・申し送り追記済み | 有効な OIDC トークン 1 枚で任意プロジェクト ID の DO(空テーブル群)を実体化できる(監査行は残らないがストレージを消費)— コード内申し送りに DO 生成の側面を追記すべき |
| A-5 | Info | crypto / cli | 新規(追補 2) | A3(ワークロード実装)への申し送り: claims digest は `computeLeaseClaimsDigest` を使うこと(builder 直接使用は空フィールドガードを迂回)・DEK 長の検証は §5.2 コミットメント照合が担う層であること・リプレイ非保証(§9.1)が裁定待ちであること |
| A-6 | Low | server | **緩和済み(追補 3)** | `/auth/github/callback` も L-3 と同型の未認証アウトバウンド増幅(state 自己束縛のため 1 リクエストごとに code 交換を誘発可能)で、クエリに入力上限がなかった — 上限追加 + 運用レート制限の対象化 |

---

## 指摘の詳細

### M-1. 承認済み 0.5-draft 合意規則の未実装と `grant_server` の旧形式受理(~~Medium~~ → 解決済み)

> **状態(2026-08-15 追記)**: PR #63(`de8f3af`)が 0.5-draft を実装し、本指摘は**解消済み**。旧 3 フィールド形式の `grant_server` は合意規則(`invalid-payload`)で受理されなくなり、「受理済みチェーンに旧形式エントリが存在しない」前提は保たれたままウィンドウが閉じた。検証の詳細は追補 §A-0。以下は `9e30a56` 時点の記録として残す。

**場所**(`9e30a56` 時点):
- `packages/crypto/src/internal.package/chain-canonical.ts`(grant_server の正規化 payload が 3 フィールド — `lease_policy_lp_hex` なし)
- `packages/crypto/src/internal.package/chain-verify.ts`(`shapeGrantServer` / `applyGrantServer` に `duplicate-server-key` 検査なし)
- `apps/server/src/authz.ts` + `apps/server/src/chain-do.ts`(汎用 append が `grant_server` / `revoke_server` を受理する)
- `apps/server/src/dek-wraps.ts` / `apps/server/src/composite-programs.ts`(ラップ完全集合の判定が現メンバー集合のみ — サーバー鍵宛を含まない)

**内容**: CRYPTO_SPEC 0.5-draft(§6.2 の grant_server payload リースポリシー拡張・サーバー鍵の一意性、§9.1 ワークロードリース)と AUTH_SPEC 0.9-draft(§12-4/§12-6 のサーバー鍵宛ラップ、§14 リース API、§15 招待 API)は「本改訂 PR のマージをもって所有者承認」とされ、仕様書はすでに 0.5 形式だった。一方 `9e30a56` の実装は 0.4 形式のままで、かつ現行 API が 0.4 形式の `grant_server` エントリを受理できた。0.5 の形式変更は「grant_server エントリを含む受理済みチェーンが公開前に存在しない」ことを根拠に後方互換条項を持たないため、0.5 実装前に運用が始まるとこの前提が崩れ、(a) 旧エントリを含むチェーンの全無効化、(b) grandfathering 条項の後付け、(c) `duplicate-server-key` 未検査のエントリ混入、が起こり得た。なお当時の実装でもサーバー鍵宛ラップの登録経路が存在しなかったため機密性への直接の実害はなかった(危険は前提の侵食)。

**当時の推奨対応**(実施不要): 0.5 実装まで `grant_server` / `revoke_server` を受理ポリシーとして両層で拒否する。→ **0.5 実装そのものが本レビュー中にマージされたため不要になった。**

### M-2. `pullfrog.yml` のピン留め漏れ + 多数のシークレット(Medium)

> **状態(2026-08-15 追記)**: **修正済み** — 両 action を commit SHA でピン留めした(`actions/checkout` = `d23441a4`〔v6.1.0〕、`pullfrog/pullfrog` = `0657d542`〔v0.1.57〕。`git ls-remote` でタグ → commit を解決し、いずれも軽量タグ = commit SHA そのものであることを確認)。未使用プロバイダキー行の削除は見送り(未設定シークレットは空のまま渡り実害がない。削るかは運用判断)。**残余 2 点**(追補 3): (1) ファイル冒頭の「DO NOT EDIT」が示すとおり、pullfrog のテンプレート再生成でピンが `@v0` へ静かに戻りうる。`uses:` の SHA 形式を検査する CI ステップは未導入(将来の改善候補)。(2) checkout のピンはベンダーテンプレートの major(v6)を維持したため、他ワークフローの v4.4.0 と 2 系統になる(意図的 — テンプレートの想定 major を変えない)。

**場所**: `.github/workflows/pullfrog.yml:24-42`(`6b839cc` 時点)

**内容**: `actions/checkout@v6`・`pullfrog/pullfrog@v0` が**可変タグ参照**のまま、`ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` ほか多数のプロバイダ API キーを env で渡している。`release.yml` 自身が「外部 action は commit SHA でピン留めする(特権経路のため。可変タグ経由の上流侵害を排除)」という規律を明文化しており(`ci.yml` / `installer.yml` も遵守)、シークレットを最も多く保持するこのワークフローだけが例外になっている。上流タグの差し替え(アカウント侵害・リポジトリ移譲)でシークレットの持ち出しが成立する。`workflow_dispatch` 限定(起動には write 権限が必要)・`contents: read` である点は緩和要素。

**推奨対応**: 両 action を commit SHA でピン留めする(ファイル冒頭の「DO NOT EDIT」はベンダーテンプレートの注意書きであり、ピン留めは編集許容箇所として扱ってよいか pullfrog 側のドキュメントで確認する)。未使用のプロバイダキー行の削除(設定されていないシークレットは空になるが、行を消せば将来設定されても渡らない)も検討。

### L-1. セッション認証の `GET …/pull` に CSRF ヘッダー要求がない(Low)

> **状態(2026-08-15 追記)**: **修正済み** — 推奨対応どおり、セッション主体の値付き pull に `x-maruhi-csrf: 1` を要求(検査述語は `auth.package` の `statefulGetCsrfViolated` に一本化し、リカバリーブロブ GET と共有。Bearer・メタデータのみモードは対象外)。AUTH_SPEC §12-7 に規定を追記し、§11-4 の CSRF 記述を「状態を持つ GET」の明示規定一覧を含む形へ改めた(「状態」= 監査行・計数への書き込み。DO 実体化などインフラ面は A-4 のプローブレート設計判断に属することも明記)。テストで 403 + `var.read` 不記録と、成功時に `var.read` が記録されること(positive control)の両方を固定。

**場所**(`6b839cc` 時点):
- `packages/api-schema/src/data-api.ts`(`GET /projects/:projectId/environments/:environmentId/pull`)
- `apps/server/src/programs-environment.ts`(pull が変数ごとに `var.read` 監査を記録)
- `apps/server/src/auth.package/middleware.ts`(CSRF 検査は GET/HEAD/OPTIONS を免除)
- 先例: `apps/server/src/handlers-auth.ts`(`GET /auth/recovery` は「GET だが状態を持つ」ためセッション主体に `x-maruhi-csrf` を要求)

**内容**: 一括 pull は GET だが `var.read` 監査行の記録という状態変化を持つ。セッションクッキーは `SameSite=Lax` のためクロスサイトの**トップレベル遷移**(リンク・`window.open`)でも同送され、第三者サイトが被害者のセッションで pull を発火できる。応答(暗号文・ラップ)は攻撃者に読めない(CORS なし)ため**データ漏洩はない**が、次の影響がある:

- 監査証跡の汚染: 「user X が変数 Y を読んだ」という偽の `var.read` を第三者が被害者アカウントに刻める(退職者を後から exfiltration したように見せる等、フォレンジクスへの毒入れ)。要ローテーション検出(AUDIT_SPEC §4.1)の「確実に取得した」ランクにも混入する(過剰ローテーション側に倒れるため危険方向ではない)
- リカバリーブロブ GET に同じ理由で CSRF ヘッダーを課した自らの規律(「取得計数という状態を持つ GET」)と非対称

緩和要素: project_id = genesis ハッシュは実質 capability であり(AUTH_SPEC §11-2)、攻撃者は対象プロジェクト ID を知る必要がある。また現時点で Web ダッシュボード(セッションで pull を呼ぶクライアント)は存在しない。

**推奨対応**: `recoveryGet` と同じく、**セッション主体の pull(値付き)に `x-maruhi-csrf: 1` を要求**する(Bearer は対象外)。メタデータのみモードは監査を記録しないため対象外でよい。将来 Web ダッシュボードを別 origin に置いて CORS を導入する場合は、この前提(「カスタムヘッダーはクロスサイトから送れない」)が崩れないよう `Access-Control-Allow-Origin` を固定 origin + ヘッダー allowlist で最小に保つこと。

### L-2. API トークンに有効期限がない(Low)

> **状態(2026-08-28 追記)**: **仕様改訂起草済み** — 申し送り(推奨対応順序 5「トークン管理 UI 設計・仕様改訂と同時に」)どおり、W0(Web ダッシュボード画面設計 — ADR-0018 改訂 2)のトークン境界裁定と同時に AUTH_SPEC §6 へ既定 TTL(起草値 90 日・再ログイン更新)を起草した。実装は Wave 3 W3a(docs/notes/web-dashboard-design.md §7)のため「修正済み」とはしない。
>
> **状態(2026-08-30 追記)**: **修正済み(W3a)** — 既定 TTL 90 日を発行時に `expires_at` へ固定し、期限切れは検証時 401(失効と同一扱い)。既存の無期限行は移行(`token_ttl_reanchor`)が「適用時点 + 90 日」へ再アンカーし、検証側も NULL を期限切れとして扱う(fail-closed — 移行未適用でも無期限は復活しない)。リース非対応実行環境の無人 PAT には発行時の明示 TTL 指定(`expiresInDays` 1..365 — 上限つき)を用意し、無期限の既定へは戻していない。裁定の比較・棄却案は docs/notes/session-44.md(裁定 CE / CF)。

**場所**: `apps/server/src/db.package/repos.ts`(`expiresAt: null` 固定)、`apps/server/src/auth.package/token.ts`(**現 main でも同様**)

**内容**: device flow で発行されるトークンは無期限。失効手段(自己失効・同名再発行によるローテーション)はあるが、漏洩に気づかない限り漏洩トークンが永続する。AUTH_SPEC §6 はデータモデルに `expires_at` を持つが TTL を義務付けていないため仕様違反ではない。CLI トークンはキーチェーン保存かつスコープ実効権限が min(スコープ, チェーン role) で束縛される点は緩和要素。

**推奨対応**: 既定 TTL(例: 90 日)+ 再ログインによる更新を検討する(AUTH_SPEC §6 への追記を伴う)。少なくとも `last_used_at` を使った長期未使用トークンの失効ポリシーを Phase 2 のトークン管理 UI と同時に設計することを推奨。

### L-3. `/auth/device/exchange` のレート制限なし(未認証アウトバウンド増幅)(Low)

> **状態(2026-08-15 追記)**: **緩和済み** — 推奨対応の両方を実施した。(1) トークン形式の事前検査(`gh[a-z]_` プレフィックス + Base62/`_` 本体)をワイヤ Schema(`api-schema/src/auth-api.ts`)で強制し、形式不正は GitHub へ問い合わせず 400。AUTH_SPEC §4 に追記。(2) `SELF_HOSTING.md` に未認証アウトバウンド誘発面(device/exchange・callback・lease)への Cloudflare per-IP レート制限ルールの推奨設定を記載。**「修正済み」としないのは**(追補 3): 形式検査が遮断するのは無差別・形式不明の洪水までで、形式適合トークンの標的型洪水にはサーバー側の対抗がなく、per-IP 制限は運用側の任意設定のため(サーバー内 per-IP 窓の見送り判断は本指摘の推奨対応に記載のとおり)。なお形式は共有 Schema なので導出クライアント(CLI)の送信側でも同時に強制される(意図どおりの対称性)。

**場所**: `apps/server/src/handlers-auth.ts`、`apps/server/src/auth.package/github.ts`(`6b839cc` 時点)

**内容**: 未認証で叩ける POST であり、リクエストごとにサーバーが GitHub の check-token API(Basic 認証 = client_id:client_secret)へアウトバウンド呼び出しを行う。この API の呼び出し枠は OAuth App 単位でレート制限されるため、第三者がゴミトークンを流し込むとデプロイメントの枠が枯渇し、**正規ユーザーのログイン(device 交換)が失敗する**可用性攻撃が成立する。ボディのトークンフィールドは 512 文字上限(api-schema)で肥大は防いでいるが、リクエストレートの制限がない。`auth.login_failed` の記録上限(L-4)は D1 書き込みを守るだけで、アウトバウンド呼び出しは毎回発生する。

**推奨対応**: (1) GitHub トークンの形式事前検査(`gh[a-z]_` プレフィックス。不一致は GitHub へ問い合わせず即 400)で無差別洪水の大半を遮断する。(2) セルフホスト手順(`docs/SELF_HOSTING.md`)に Cloudflare のレート制限ルール(`/auth/device/exchange` への per-IP 制限)の推奨設定を記載する。サーバー内の per-IP 固定窓(D1 or DO)は書き込み増幅と天秤にかけて検討。

### L-4. `auth.login_failed` 記録上限のグローバル固定窓(Low / 設計文書化済み)

**場所**: `apps/server/src/db.package/audit.ts:69-113`(**現 main でも同様**)

**内容**: 記録上限(100 件/時)がデプロイメント全体のグローバル窓のため、攻撃者が無害な失敗を 100 件流して窓を飽和させると、その後の(標的型の)失敗が記録されない。「洪水そのものは窓内の上限到達として観測できる」と実装コメントで文書化された意図的なベストエフォートであり、上限到達自体がシグナルになる点は妥当。

**推奨対応**: 現状維持でも許容範囲。改善するなら理由種別(`authMethod` × `reason`)ごとの窓に分割するか、上限到達時に「以後 N 件を記録しなかった」ことを示す集約イベントを 1 行残す(抑制の可視化)。

### L-5. HSTS・セキュリティヘッダーの不足(Low)

> **状態(2026-08-15 追記)**: **修正済み** — web の `_headers` と API worker の全応答の両方に `Strict-Transport-Security: max-age=31536000` を追加(API 側も routes で custom domain を割り当てうる、セッションクッキー・OAuth フローを持つオリジンのため — 追補 3 で web のみだった非対称を解消)。API worker の全応答に `X-Content-Type-Options: nosniff` + `Cache-Control: no-store` を付与(`index.ts` の `withSecurityHeaders`。リース応答〔チェーン + 暗号文を含む未認証応答〕・ルーター前の 413 経路にも効く)。302 + 複数 Set-Cookie がラッパを跨いで保全されることはテストで固定。**推奨からの逸脱 1 点**: HSTS の `includeSubDomains` は付けなかった — セルフホストで apex にマウントされた場合、無関係なサブドメインへ 1 年間ブラウザ側に固着する副作用があり、配布物の既定としては過剰なため(必要なゾーンでは運用側で付加できる)。

**場所**: `apps/web/scripts/write-headers.ts:41-45`、`apps/server/src/index.ts`(API 応答)(`6b839cc` 時点)

**内容**: web の `_headers` に `Strict-Transport-Security` がない。`workers.dev` は HSTS プリロード済みのため既定 URL では実害がないが、**custom domain を routes で割り当てた場合**は初回接続のダウングレードが理論上可能。API worker の応答には `X-Content-Type-Options: nosniff` 等が一切付かない(JSON API のみで HTML を返さないため実害は小さい)。

**推奨対応**: `_headers` に `Strict-Transport-Security: max-age=31536000; includeSubDomains` を追加。API 側は共通レスポンスヘッダー(`nosniff` + `Cache-Control: no-store`(トークン・暗号文応答のキャッシュ抑止))の付与を検討。

### I-1. `checksums.txt` 未署名(Info・追認)

`packaging/install.sh:12-13` に「署名検証は書かない(無いものを検証したように見せない)」と明記され、完全性の根拠が github.com への TLS のみであることは正直に文書化されている。ROADMAP の署名導入(minisign / Sigstore 等)を追認する。スクリプト自体は模範的(全体を `main()` に包む・checksum 検証前にインストール先へ書かない・sudo なし・rc ファイル無編集)。

### I-2. チェーン追記ごとの全チェーン再検証コスト(Info)

`apps/server/src/chain-accept.ts` は追記受理のたびに `verifyChainEffect([...entries, entry])` で全チェーンを再検証する(最大 10,000 エントリ × Ed25519 検証)。AUTH_SPEC §12-8 が受理済みのコスト水準だが、workerd の CPU 時間上限内に収まるかは上限付近の実測がまだない。member 権限での追記連打は 1 追記あたり O(n) の CPU を消費させられる(直列化されるため DO 単位の遅延)。上限付近のベンチマーク(または導出状態キャッシュを使った増分検証への最適化)を Phase 2 で検討。

### I-3. SessionStart フックの `curl | bash`(Info・開発環境限定)

`.claude/hooks/session-start.sh:17-19` がリモート開発環境で `curl -fsSL https://bun.sh/install | bash` を実行する。バージョンはピン留め済みだがインストーラ自体の検証はない。ユーザー向け成果物ではなく開発環境のみのため Info。気にするなら公式 GitHub Releases からの checksum 付き取得へ置き換え。

---

## 検査済み・問題なしと確認した項目(対象: `9e30a56` 時点のツリー)

> **適用範囲の注意**: 本リストは対象リビジョン **`9e30a56` 時点**のツリーに対するものであり、それ以降のコミット(特に PR #63 = `de8f3af`)には及ばない。PR #63 が追加・変更した面(受信者クラス server、grant_server 0.5 形式、`server grant` / `server revoke` CLI、デプロイメント鍵、`/auth/config` の拡張)は**追補(下記)**が対象とする。★印 = PR #63 で挙動が変わった項目(現状は追補側の記述が正)。

修正チャットでの再確認を省けるよう、検査して問題がなかった項目を記録する。

### 認証(AUTH_SPEC §3〜§6)
- OAuth state: 128-bit 乱数 + `__Host-` クッキー(HttpOnly/Secure/Lax/10 分)+ 定数時間比較(`handlers-auth.ts`)。ログイン CSRF はクッキー束縛で遮断
- `redirect_uri` は Host ヘッダーではなく実リクエスト URL の origin から導出(`handlers-auth.ts`)。オープンリダイレクトなし
- device flow の audience 検証(check-token API)実装済み — 他 App 向けトークンの流用(confused deputy)遮断(`auth.package/github.ts`)
- GitHub アクセストークンは非永続・非ログ(全経路確認)
- セッション: 256-bit 乱数 → SHA-256 ハッシュのみ DB 保存、スライディング 30 日、DB バック失効、期限切れ行の cron 掃除。トークン: `maruhi_pat_` + Base62(256-bit)、ハッシュ照合 + 定数時間比較、同名ローテーション原子化(atomic batch + UNIQUE)、発行上限 100
- CSRF: カスタムヘッダー `x-maruhi-csrf` + SameSite=Lax + **CORS 不在**(プリフライトが通らないためクロスサイトからカスタムヘッダーを送れない)+ Authorization ヘッダー優先でクッキーへフォールバックしない設計
- 未設定サーバーの fail-closed(503 SetupIncomplete)、プレースホルダ検出 ★(`/auth/config` の応答は PR #63 でサーバー鍵公開面が加わった — 追補 §A-0 / A-2)
- リカバリーブロブ API(§13): `*`×admin スコープ条件・GET の CSRF ヘッダー・固定窓 5 回/時・404 非計数・suite 検査 — すべて仕様どおり
- メールによる自動リンク・メール検索のコードパスは存在しない。`getOrCreateUser` は (provider, provider_user_id) のみで解決

### 認可・存在秘匿(AUTH_SPEC §9-2 / §11 / §12-3)
- 実効権限 = min(トークンスコープ, チェーン role) の両半分が実装済み(`authz.ts` + DO 側 `requireRole`)。スコープ外 404 / 水準不足 403 / 非メンバー 404 の使い分けが仕様の判定順どおり
- org ロールはプロジェクトアクセスに一切関与しない(真実源はチェーンのみ)
- DO の Semaphore(1) による全操作(読み取り含む)直列化 — メンバーシップ判定とデータ配布の TOCTOU(削除直後メンバーへの配布)を遮断。defect 時のキャッシュ無効化(phantom 状態の防止)も実装済み

### チェーン(CRYPTO_SPEC §6)
- 検証段順(フレーミング → payload 構造 → actor 解決 → 署名 → 認可 + 状態遷移)・全理由コードがテストベクター駆動で固定。不信入力で throw しない設計(`unknown` 受けの実行時検査)
- 合意規則: エポック +1 厳密、`create_environment` 先行要求、環境 ID の履歴全体一意、メンバー鍵一意性(enc/sig 個別)、admin/owner 操作の owner 限定、最後の owner 保護、フィールド 1024 バイト上限、再 grant のスコープ拡大のみ — すべて実装確認 ★(grant_server は PR #63 で 0.5 形式へ — 追補 §A-0)
- 正規化(LP エンコーディング)は §2.1 の単一実装を全用途で共有。長さプレフィックスにより連結曖昧性なし
- プロジェクト ID = genesis ハッシュの DO ルーティング束縛(worker 計算 + DO 側再検証)
- 受理ポリシー(1 MiB / 10,000 / 32 MiB)+ HTTP 生ボディ 8 MiB の前段(Content-Length 偽装に依存しない実測強制)
- チェーンミラー監査はチェーン挿入と同一同期タスクで原子コミット。監査 seq の欠番防止(失敗時キャッシュ破棄)

### データプレーン(AUTH_SPEC §12 / CRYPTO_SPEC §4〜§5)
- 値署名・メタステートメントのサーバー検証(§12-5 の 1〜5): 呼び出し主体 = 署名者、宣言ヘッド実在、ヘッド時点の role・鍵束縛(tenure 跨ぎ拒否)、エポック整合(環境作成前ヘッド拒否・既定値フォールバック禁止)、prev 連鎖(CAS 通過後の保存済みアンカー照合)、削除後の再 active 化拒否 — crypto 層 `verifyDistributedValue` / `verifyDistributedMetaStatement` に一元化され、server はそれを呼ぶだけ
- 署名対象の座標はサーバー側の値(genesis ハッシュ・URL・保存先)から再構成し、ワイヤ申告値から組まない(§12-5 の不変条件)。AAD 座標一致検査(422)は認可先行の例外規定どおり自己整合検査のみ
- CAS: version(+1 厳密)・現エポックのみ受理・metaVersion CAS・409 に勝者のハッシュを含めない(証拠連鎖の汚染防止)
- DEK ラップ受理(§12-6): 受信者 = user_id + enc 公開鍵の両方一致、★初回登録の完全一致(`9e30a56` では個数 = 現メンバー数。**PR #63 で「現メンバー + 開示スコープ内の有効 grant のサーバー鍵」へ変更** — 追補 §A-0)、追記のみ・上書き禁止(409)、修復経路は admin、登録署名(§5.1)を全経路で検証、配布は本人宛のみ(SQL で recipient 束縛確認)、複合同梱ラップの epoch 等値検査
- 複合受理(§12-4): チェーンエントリ + ステートメント + ラップ完全集合の単一同期タスク原子コミット、宣言ヘッド = 追記前ヘッドの厳密一致、URL / payload 座標の突合
- 数量ポリシー(§12-8)は全上限を実装。判定は保存済み状態基準
- 監査(AUDIT_SPEC): actor は内部 user_id + 鍵 FP のみ。プロバイダ ID・login・メールが D1/DO 監査・チェーンに入る経路がないことを確認(org 名 = providerLogin 由来は organizations テーブルのみで、監査 payload へは写していない)

### crypto パッケージ
- AES-256-GCM: nonce は常に内部生成(呼び出し側から渡せない構造)、AAD は共有 LP エンコーダ、復号失敗は詳細なし
- HPKE: panva `hpke` の単一構築点、Base mode 単発 Seal/Open、info の文脈束縛、Open は KeyPair 渡しのみ(非抽出鍵と両立)
- 鍵: 秘密鍵は既定 extractable=false、FP 計算は仕様どおり(user = SHA-256(enc‖sig)[:16]、server = SHA-256(enc)[:16])
- リカバリー: HKDF(salt 空 = RFC 5869 §3.1 準拠の前提明記)+ AAD の user_id 束縛
- hex は小文字のみ受理(複数正規形の排除)、巨大入力の fail-fast(長さ検査 → decodeHex)
- エラー値に秘密・入力断片を載せない規律が全域で遵守
- テストベクター(正例 + 改竄・移植・付け替え・分岐等の負例)が全署名系に存在し、ブラウザ / Bun / workerd の 3 環境 CI

### CLI
- ディスクレス不変条件: 平文値・鍵素材のディスク書き込み経路なし。永続化はキーチェーン(トークン・master 鍵)と非機密 config / floor のみ。平文ファイルへのフォールバック不在(キーチェーン不可時は型付きエラー)
- `maruhi run`: 子プロセス env へのメモリ注入のみ。**実行制御系環境変数の denylist(PATH / LD_* / DYLD_* / GIT_* / NODE_OPTIONS 等)+ POSIX 識別子制限(shellshock 系関数注入の遮断)+ Windows 大文字小文字衝突検査 + NUL / 不正 UTF-8 拒否** — 悪意メンバー・名前付け替え攻撃への多層防御
- エージェント検出(gunshi/agent)で値表示系を拒否し、拒否メッセージで `run -- printenv` 等の迂回レシピを案内しない
- 端末インジェクション対策: サーバー配布メタデータの制御文字を可視置換、値表示も \t\n 以外の制御文字を中和
- サーバー URL は https 強制(loopback のみ http 可)、`MARUHI_TOKEN` は `MARUHI_TOKEN_ORIGIN` による origin 束縛(別オリジンへのトークン送出防止)、エラーメッセージに URL 生値(資格情報が埋まる形)を返さない
- クライアント検証(§6.3): 値署名 → ラップ登録署名 → DEK コミットメント照合 → 復号、の順序。復号 AAD は申告値でなく検証済み座標から構築。future head の有界再同期、ローカル床(hash/連番のみ・平文なし)、非エコー入力(raw mode)
- device flow: トークンはローカル変数のみ、ポーリング間隔の下限固定(ビジースピン防止)

### Web / パッケージング / CI
- CSP: `default-src 'none'` 基調 + ブートストラップ 1 本のみ SHA-256 ハッシュ許可(`'unsafe-inline'` なし)、インラインスクリプトが 1 本でなければビルド失敗。`frame-ancestors 'none'` / `base-uri 'none'` / `Referrer-Policy: no-referrer`。`dangerouslySetInnerHTML` / eval / 外部リソース読み込みは存在しない
- install.sh: `main()` ラップ(途中切断対策)、checksum 検証必須(検証不能なら入れない)、部分ファイル残置なし、sudo なし、rc ファイル無編集、版とバイナリの一致検査
- CI: `permissions` 最小明示、`persist-credentials: false`、外部 action の SHA ピン(pullfrog.yml を除く — M-2)、タグの main 系譜検査(レビュー未経由コミットへの publish 遮断)、`bun audit` 常時実行、テレメトリ一括無効(言わざる)
- `.dev.vars.example` はダミー値のみ。リポジトリ・テストに本物のシークレットなし(test-vectors は設計上の固定ダミー鍵)

---

## 追補(2026-08-15): PR #63(`9e30a56...de8f3af`)の追加レビュー

本編のレビュー中に PR #63(Phase 2 Wave 2 A1)が main へマージされたため、その差分(67 ファイル / +8,596 行)を追加でレビューした。対象は grant_server 0.5 実装の全面: crypto(リースポリシー正規化・`duplicate-server-key`・FP ワード表示)、server(デプロイメント鍵・`/auth/config` 公開面・受信者クラス server)、CLI(`maruhi server grant` / `server revoke`)、ワイヤ(api-schema)、テストベクター再生成。

### A-0. M-1 の解消の検証(結論: 解消済み)

以下を一次情報(main のソース)で確認した:

- **正規化**: `chain-canonical.ts` の `grant_server` payload は `[serverEncPubHex, serverKeyFingerprintHex, scopeLpHex, leasePolicyLpHex]` の 4 フィールド。lease_policy は仕様どおり 3 段入れ子 LP(constraint = LP(name, value) → element = LP(issuer, audience, LP(constraints)) → policy = LP(elements))で、空ポリシー = 空バイト列
- **旧形式の遮断**: `shapeGrantServer` が `leasePolicy` 欠落(旧 3 フィールド形式)を `invalid-payload` で拒否する。合意規則レベルで旧形式は受理不能 = 「危険な窓」は閉じた
- **サイズ上限**: 要素 8 / 制約 8 / 各文字列 1024 バイト(§6.2 の合意規則)を形状検査で強制
- **`duplicate-server-key`**: `applyGrantServer` に実装され、検査順序(role → FP 自己整合 → 再 grant 規則 → 鍵重複)はテストベクターで固定。逆方向(有効 grant のサーバー鍵を add_member に流用)は仕様の明示的な対象外のまま(§6.2 の注記どおり)
- **再 grant の二層判定**: 開示スコープは拡大のみ(`grant-scope-narrowed`)、lease_policy は自由改訂 — §6.3 どおり
- **ラップ完全集合**: `expectedWrapRecipientCount` = 現メンバー数 + 開示スコープ内の有効 grant 数を単一定義とし、独立登録・複合の両経路が共有(§12-4 / §12-6 の 2026-08-12 改訂に一致)
- **受信者クラス server**: 同定 = サーバー鍵 FP + enc 公開鍵の両方が有効 grant の payload と厳密一致、スコープ外は `scope-out-of-range`(422)。HPKE info / §5.1 署名対象の recipient 位置にはサーバー鍵 FP(CRYPTO_SPEC §9)。配布クエリは `recipient_class = 'member'` を明示条件に持ち、サーバー宛ラップがメンバー配布経路へ漏れない
- **監査のアイデンティティ規則**: server 受信者は `target_key_fingerprint` 列に FP を載せ、user_id 列に混ぜない。`chain.server_granted` ミラーは lease_policy(外部識別子を含む)を**意図的に写さない**(AUDIT_SPEC §1-2 遵守)
- **削除経路のクラス突合**: `dek.deleted` の監査列の書き分けは、保存行の `recipient_class` とリクエスト申告の一致を検証してから行う(ワイヤ入力に監査列の意味論を委ねない)
- **デプロイメント鍵**: `SERVER_ENC_KEY_IKM`(32 バイト hex の Workers Secret)から RFC 9180 `DeriveKeyPair`(標準 API。RFC 9180 公式ベクターで検証済み)で導出。A1 では復号経路を作らず公開面のみ保持。未設定 = 純粋 E2EE の正常系として fail-open にしない設計(grant CLI 側が明示エラー)
- **CLI `server grant`**: owner 検査・スコープ存在・`duplicate-server-key` / 再 grant 規則の早期検査 → `/auth/config` の enc 公開鍵から FP を再計算して自己整合検査 → **確認の儀式**(BIP39 12 語表示 + 最終語の再入力。非対話は `--expect-fingerprint`。**AI エージェント環境では儀式を代行させず拒否**)→ CAS リトライ(延長検査付き再同期 — 短縮・分岐チェーンへの再署名を遮断)→ 受理後の再同期で grant の掲載を検証(サーバー申告を真実源にしない)→ バックフィル(409 = 登録済みとして収束する冪等な再実行)
- **CLI `server revoke`**: revoke_server 追記 + **全環境の強制ローテーション**(§7 の義務)。中断復旧はチェーン導出(最後の revoke seq とエポック開始 seq の比較)で進捗ファイルなし。削除済み環境のスキップは**検証済みの署名付き削除ステートメントがある場合のみ**(サーバーの 404 申告だけで黙ってスキップしない — §7 どおり)。環境ごとの失敗は握り潰さず集約報告
- **旧 interim ガードの撤去**: `9e30a56` に存在した「grant 有効時は複合操作を拒否」ガード(`ensureNoServerGrant`)は、完全集合がサーバー鍵宛を含むようになったことで正当に廃止

### A-1. 受信者クラスを跨ぐ識別子衝突でラップ完全集合の初回登録が defect になる(Low・新規)

> **状態(2026-08-15 追記)**: **是正済み(defect の解消)** — 推奨対応どおり、登録経路の重複検出キーを保存行の一意性単位(epoch × recipient、クラス無視)へ変更し、受理前の 422(`duplicate-recipient`)で拒否(`dek-wraps.ts`。修正を外すとテストが 500 で失敗することを変異検証済み)。削除経路は従来どおり(クラス込みキー + 保存行とのクラス突合)。**「修正済み」ではなく「是正済み」とするのは**(追補 3): 衝突が存在する限り完全集合は本質的に充足不能(member と server は別鍵なので 1 行が両者を兼ねられない)であり、**新エポックの閉塞そのものは 422 化では解けない**ため。既存エポックへの衝突メンバー宛バックフィルも同根で 409 に固定される。是正の意味は「不透明な defect → 診断可能な型付き拒否」への転換であり、復旧は「影響と緩和要素」記載の運用手段(衝突メンバーの remove_member または revoke_server)による — **remove_member 後にローテーションが通ることまでテストで固定した**。根本(add_member 対象 user_id の受理ポリシー形式検査)は仕様側の判断を要するため未着手のまま。なお A2(PR #65)のリース経路の本稼働により、本指摘の影響には「§7 の失効ローテーション・リース可用性の閉塞」が加わっていた(対応の優先度を繰り上げた理由)。

**場所**: `apps/server/src/dek-wraps.ts`(`checkWrapSets` の初回登録分岐・`wrapRefKey`)、`apps/server/src/do-schema.ts`(dek_wraps の主キーは `(environment_id, epoch, recipient_user_id)` のまま — `recipient_class` は主キー外)

**内容**: 保存行の一意性はクラスを含まない `(環境, エポック, recipient_user_id)` であり、member の user_id と server のサーバー鍵 FP は「実際上形式が交わらない」(ULID 26 文字 vs hex 32 文字)ことを前提にしている(do-schema のコメントも明記)。しかし **add_member の対象 user_id は意図的に存在検証されない自由文字列**(AUTH_SPEC §11-1)なので、admin は「user_id = 有効 grant のサーバー鍵 FP(hex 小文字 32 文字)」というメンバーをチェーンに追加できる。すると:

- ラップ完全集合(環境作成・ローテーション・初回登録)は、この member 宛と server 宛の**両方**のラップを要求する(完全一致要件)
- リクエスト内重複検査(`wrapRefKey`)はクラス込みのキーなので両方が通過する
- 初回登録分岐(`existing === 0`)は個数検査のみで per-wrap の保存衝突検査をしない
- 書き込みフェーズで 2 行目の INSERT が主キー違反 → defect(500)→ タスクロールバック

結果、**衝突が存在する限り当該環境の新エポックのラップ登録(= ローテーション・環境作成の複合)が常に 500 で失敗**する。§7 の失効ローテーションもこの環境で塞がれる。既存エポックへの追記経路はクラス無視の 409 検査があるため defect にならない(意図どおり)。

**影響と緩和要素**: 可用性のみ(機密性・完全性への影響なし。ロールバックにより不整合も残らない)。成立には admin 権限(add_member)+ owner が発行済みの grant が必要で、admin は他にも妨害手段を持つ。復旧は衝突メンバーの remove_member(チェーン追記自体はローテーション不要)または revoke_server で可能。

**推奨対応**: `checkWrapRecipients` にクラス横断の識別子重複検査を足し、型付きエラー(`duplicate-recipient` 相当の 422)で受理前に拒否する(500 にしない)。あわせて、より根本的には add_member の対象 user_id 形式(内部 ULID 形)を**受理ポリシー**として検査する選択肢もある(§11-1 は合意規則にしないことを求めるだけで、受理ポリシーの形式検査は禁じていない)— ただし後者はチェーン形式の運用前提に関わるため仕様側の判断を要する。

### A-2. `/auth/config` の `serverEncPubHex` が AUTH_SPEC §4 に明記されていない(Info・新規)

> **状態(2026-08-15 追記)**: **解決済み(PR #65)** — コミット `50452f6` が AUTH_SPEC §4 へ `serverEncPubHex` を明記し、仕様と実装が一致した(追補 2 で検証)。

実装(`packages/api-schema/src/auth-api.ts` / `apps/server/src/handlers-auth.ts`)は `serverKeyFingerprintHex` に加えて `serverEncPubHex` を返す。CRYPTO_SPEC §9 の「サーバーが配布する enc 公開鍵」の配布チャネルとして必要であり公開情報でもある(CLI は FP との自己整合を再計算検証する)ので**実装は妥当**だが、AUTH_SPEC §4 の応答定義には `serverKeyFingerprintHex` しか書かれていない。「仕様が唯一の正」の規律に合わせ、AUTH_SPEC §4 へ 1 行追記して仕様と実装を一致させることを推奨。

### A-3. `--expect-fingerprint` の自己言及照合の注意(Info・新規)

> **状態(2026-08-15 追記)**: **修正済み** — `SELF_HOSTING.md` の "Record the fingerprint (the comparison baseline)" 節に、grant 実行時の `/auth/config` 再取得値を渡すと照合が自己言及になる旨の注意書きを追加した。

`server grant` の確認の儀式は AI エージェント環境で拒否され、非対話では `--expect-fingerprint` に**帯域外で控えた FP** を渡す設計になっている。「デプロイ直後に FP を控え、それを照合基準にする(非対話は `--expect-fingerprint` に渡す)」ことは `docs/SELF_HOSTING.md` の "Record the fingerprint (the comparison baseline)" 節と CLI ヘルプ(「帯域外で控えたサーバー鍵 FP」)が**既に記載済み**である。残る差分は 1 点のみ: **grant 実行時に `/auth/config` から機械取得した値をそのまま渡すと照合が自己言及になり儀式が無意味化する**(デプロイ直後の取得は trust-on-first-use のアンカーとして意図された手順であり、grant 時の再取得とは意味が異なる)ことの明示。`SELF_HOSTING.md` の同節に注意書きを 1 行足すことを推奨。

### 追補で検査して問題なしと確認した項目

- lease_policy の CLI ファイル入力: サイズ上限(8/8/1024)を入力段でも検査、claim 名の昇順正規化、`claimValue` は空文字列許容(OIDC claim の実態に一致)— 合意規則の形状検査(crypto 層)と二重化
- `server grant` の儀式は追記スキップ時(バックフィルのみの再実行)でも省略されない
- バックフィルの 409 吸収は「サーバー宛ラップの一覧 API が存在しない(配布は本人宛のみ)」制約下で唯一の収束手段であり、上書きを許さない受理規則と両立
- grant/revoke の CAS リトライは延長検査付き再同期(`resyncExtended`)を経由し、短縮・分岐したチェーンへの再署名を拒否する
- FP ワード表示(BIP39 12 語)は表示符号化のみ(SHA-256 + 固定辞書)で新規プリミティブなし。英語リスト固定・切り詰めなし(§3 どおり)
- DO スキーマ移行(`recipient_class` 列の ALTER TABLE + DEFAULT 'member')は既存行を member として正しく扱う
- テストベクター: grant_server 系の全再生成 + `duplicate-server-key` / 検査順序 / 旧形式拒否(`grant-server-lease-policy-dropped`)/ 受信者クラス server の正負例が追加済み(仕様 §11 の「実装より先にベクター」の規律を維持)

---

## 追補 2(2026-08-15): PR #65(`3cfc205...6b839cc`)の追加レビュー

PR #64(本文書の追加)の後にマージされた PR #65(Phase 2 Wave 2 A2 — OIDC 検証 + lease エンドポイント + リースラップ。46 ファイル / +4,415 行)を、本編と同じ方法論(仕様突合 + 一次情報の確認)でレビューした。判定基準は CRYPTO_SPEC §9.1 / AUTH_SPEC §14 / AUDIT_SPEC §3.5(§14 の `crit` 拒否・JWKS 猶予窓・レート制限位置・503 の 2 理由は PR #65 自身が起草し、マージをもって所有者承認)。**新しい未認証面(lease)・自前 JWT 検証・サーバー鍵による開封という追加面に対し、仕様乖離・認可の退行・注入・監査への外部識別子混入は発見されなかった。** 新規指摘は Info 2 件(A-4 / A-5)と裁定待ち 1 件(下記)。

### A-2 の解消の検証(結論: 解消済み)

コミット `50452f6` が AUTH_SPEC §4 へ `serverEncPubHex` を明記し、実装(`packages/api-schema/src/auth-api.ts` / `apps/server/src/handlers-auth.ts`)と一致した。

### 検査して問題なしと確認した項目

**OIDC 検証(`apps/server/src/oidc.package/` — AUTH_SPEC §14-1)**
- alg 混同の構造的遮断: 検証アルゴリズムは常に JWK 側の kty / crv から導出し、ヘッダー `alg` は導出された期待値との一致検査にのみ使う(`jwk.ts`)。許可は RS256 / ES256 のみ、対称鍵 alg・`none` は対応する kty がなく到達しない
- `crit` ヘッダーは存在するだけで拒否(§14-1 (2b)。Authlib / PyJWT / fast-jwt の 2025〜2026 CVE と同型の穴を先回りで閉鎖)。`typ` 不検査は意図的で論拠がコメントに明記(maruhi 自身が JWT を発行しないため cross-JWT 混同の相手方が存在しない)
- issuer 許可リスト照合は**外部 fetch より前**(`verifier.ts` — 未認証面からの任意 URL fetch 誘発 = 増幅攻撃の遮断)。discovery は自己申告を検査(`issuer` 一致 + `jwks_uri` が同一オリジン https — SSRF・鍵出所の付け替え遮断)、`redirect: "manual"`・5 秒タイムアウト・実測 256 KiB 打ち切り
- JWKS キャッシュ(`jwks.ts`): 「最後に成功した値」と「取得中の Promise」を分離し失敗が good 値に決して触れない構造。未知 kid の強制リフレッシュ(60 秒クールダウン)・失敗側の独立クールダウン(60 秒)・猶予窓 6 時間の stale-while-revalidate — §14-1 の要求をすべて実装。kid なしトークンは使用可能鍵が一意のときだけ受理(総当たり検証の排除)
- base64url は厳格デコード(文字集合・長さ mod 4 検査、寛容デコードによる別バイト列通過の排除)。署名対象は受信 segment 文字列そのもの(再直列化しない)
- 時刻検証: `exp` / `iat` 必須・±60 秒 skew・`nbf` 対応。`aud` は文字列/配列の両形を正規化し、**複数 audience は `ambiguous-audience` で 401**(claims_digest の一意性が崩れるため — `handlers-lease.ts`)

**lease 認可・応答(`programs-lease.ts` / `handlers-lease.ts` — AUTH_SPEC §14-3)**
- 判定順が仕様どおり: サーバー鍵未設定はチェーンを読む前に一様 503(鍵なしデプロイで存在が漏れない)→ 未初期化 404(監査を残さない — 未認証経路の監査肥大 DoS 遮断)→ grant / lease_policy(存在量化)/ スコープの不一致は一律 404 → 環境存在 → レート制限(認可の後 — 429 による存在漏洩の遮断)→ サーバー宛ラップ存在(503)。5 つの 404 分岐がボディまで同一であることと、監査 reason 列で各分岐を別々に踏んだことの両方をテストが固定(`lease.test.ts`)
- レート制限窓の消費は発行成功時のみ(503 経路・未認可はテストで不消費を固定)。窓はプロジェクト単位 300 発/時で、ノイジーネイバーの影響半径が `policy.ts` に明記
- claim 制約は文字列の完全一致のみ・型強制なし(`lease-policy.ts`。`claims["__proto__"]` 等もオブジェクトであり文字列一致しない)。空 lease_policy は常に不認可
- 開封 + 再ラップは `ServerKey` のクロージャ内で一体(`server-key.ts`)。平文 DEK を返す口は存在せず、使用後ゼロ埋め(限界もコメントで明記)。失敗は固定語彙の理由コードのみ(鍵素材・暗号文の断片を運ばない)
- `LeasedDek` は `RecipientDek` と別型(登録署名を持たない応答スコープの材料を配布可能なラップと取り違えない)。応答のワイヤ形は §12-7 一括 pull と共有(`toWireVariable` の移動は関数バイト同一の純粋な共有化)

**監査(AUDIT_SPEC §3.5)**
- `server.dek_unwrapped` / `server.lease_issued` は actor = server + 鍵 FP、`server.lease_denied` は actor = system。payload は理由コード + claims_digest + grant_chain_seq のみで、**外部識別子(リポジトリ名・ref・issuer URL 生値)は 3 種のどこにも現れない**(`facts.claims` の使用先は認可判定のみ)。denied は署名検証通過後のみ・固定窓 100 行/時、記録と窓消費が同一同期ブロック
- `var.read` はリース応答で記録されない(§14-4)

**ワイヤ・スキーマ(`packages/api-schema`)**
- `oidcToken` ≤16 KiB + compact JWS 文字集合、`ephemeralPubHex` 32 バイト hex 厳密。エラー契約は 404 を `ProjectNotFoundError` の 1 種に限定(`EnvironmentNotFoundError` を意図的に宣言せず、404 の分岐可能性を型レベルで排除)。lease グループは `.middleware(AuthMiddleware)` を宣言しない唯一のグループで、未認証分離は api-schema の契約側で成立(index.ts 側の誤結線が構造的に起きない)
- 点として不正な X25519 公開鍵は Schema 通過後も `importEncryptionPublicKey` 失敗で拒否(多層)

**crypto リースラップ(`packages/crypto/src/internal.package/lease-wrap.ts` — CRYPTO_SPEC §9.1)**
- info / claims_digest の構成が仕様と完全一致(独立実装で LP + SHA-256 を再計算しベクターと全一致を確認)。ドメイン `maruhi/v1/lease-wrap` は §5 の `maruhi/v1/dek-wrap` と LP 先頭バイトから分岐し構造的に相互移植不能
- 新しい暗号プリミティブ・独自構成なし: HPKE は既存の単一構築点(`hpke.ts`)経由、LP は §2.1 の共有エンコーダ、ハッシュは WebCrypto SHA-256 のみ。Open は KeyPair 渡し(非抽出鍵と両立)
- 入力検査: `claimsDigestHex` は 64 文字 hex 小文字のみ(wrap / unwrap の両側)、issuer / sub / aud の空文字列拒否、dek 32 バイト固定。エラー値は静的リテラルの field 名のみ(秘密・入力断片なし)、HPKE 例外はバインドなし catch で無情報エラーに畳む(oracle 化なし)
- ベクター: 正例 2(basic / prior-epoch)+ 負例 5(座標 4 種 + ドメイン差し替え)が実在し、`basic` の座標・DEK は dek-wrap.json の `server-basic` と同一(開封 → 再ラップの受け渡しがベクター上で追跡可能)。`chain-entries.json` の diff は導出状態への `grant_seq` 追加のみ(エントリ・署名・ハッシュ連鎖のバイト変更ゼロ、非空の全 server_grants に漏れなく追加、照合コードも追加済み)

**server 側の副次変更**
- 追加 SQL(`data-store.ts` の 3 クエリ)は全て `?` バインド。唯一の文字列連結は列名でソース内リテラルのみ到達
- `lease_windows` テーブルは `kind TEXT PRIMARY KEY`(最大 2 行)、マイグレーションは末尾追記 + transactionSync 適用 + 旧コード拒否の既存規律に適合。テストリセット宣言も漏れなし
- `chain-do.ts` の新 RPC `issueLease` は既存と同じ permit 直列化 + defect 時キャッシュ破棄を通る。既存 RPC の判定に変更なし
- テスト基盤: `SERVER_ENC_KEY_IKM` から実導出した鍵でサーバー宛ラップを作り「本当に開封できる」ところまで検査。OIDC issuer は outboundService フェイクで実ネットワークに出ない。「ワークロードが開いた DEK = 元のエポック DEK」「issuer 障害中に再取得を繰り返さない」「サーバー鍵未設定ならチェーンを読む前に落ちる(ChainStore を throw スタブ化)」等、PR が主張するテストは全件実在を確認

### A-4. 有効 OIDC トークン 1 枚で任意プロジェクト ID の DO を実体化できる(Info・新規)

**場所**: `apps/server/src/chain-do.ts`(コンストラクタの `ensureProjectDoTables`)、`apps/server/src/programs-lease.ts`(プローブレート上限の申し送りコメント)

**内容**: lease はデータプレーン唯一の未認証エンドポイントであり(認証フロー系の未認証面は別 — A-6)、許可 issuer の有効トークンを 1 枚持つ者が任意の 64 hex プロジェクト ID を投げると、未初期化 404 で監査行は残らないものの、**空テーブル群を持つ DO 自体は生成される**(ストレージコスト)。プロジェクト ID は genesis ハッシュで推測不能・OIDC 検証通過が前提という緩和はあり、コードには「要求レート自体の上限は未実装」という近縁の申し送りが既にあるが、「DO が実体化される」側面は明示されていない。なお同型の DO 実体化は**認証済み**の GET(環境一覧・メタデータのみ pull 等 — セッション主体は任意プロジェクト ID でスコープ検査なし)にもあり、Lax クッキーのトップレベル遷移で第三者が発火させうる(追補 3)。いずれも影響はストレージ消費のみで、対策はプローブレート上限と同じ設計判断に属する(AUTH_SPEC §11-4 の「状態を持つ GET」の定義がこれを対象外とすることは仕様側に明記した)。

**推奨対応**: `programs-lease.ts` の申し送りコメントへ 1 行追記(プローブレート上限の設計判断に DO 生成コストを含める)。対策自体はプローブレート上限と同じ判断に属するため申し送りのまま。→ **コメント追記は実施済み(2026-08-15)**。残るのはプローブレート上限そのものの設計判断(既存の申し送りと同一)。

### A-5. A3(ワークロード実装)への申し送り(Info・新規)

A3 で CI クライアント(unwrap 側)を実装する際の注意 3 点。いずれも現実装の欠陥ではなく、公開 API の使い方の規律:

1. **claims digest は `computeLeaseClaimsDigest` を使う**: 公開されている `buildLeaseClaimsBytes` は issuer / sub / aud の空文字列ガードを持たない(LP により衝突はしないが、検証付きの入口は `computeLeaseClaimsDigest` のみ)
2. **`unwrapLeaseDek` は取り出した DEK の長さを検査しない**(§5 の `unwrapDek` と同じ扱い)。悪意あるサーバーが 32 バイト以外を Seal した場合を捕捉する層は §5.2 のコミットメント照合であり、クライアント検証(§6.3 / §9.1 の受信者義務)を省略しないこと
3. **リプレイ非保証の明示**: `lease-wrap.ts` のヘッダーコメントは「別ジョブへの転用は復号失敗」という保証面のみを述べる。§9.1 が非保証とする「有効期間内トークンのリプレイ」(下記裁定待ち)への 1 行参照を足すと、モジュール単体を読む A3 実装者の読み違えを防げる → **実施済み(2026-08-15)**。なおリプレイ自体の裁定は先着束縛の採用で確定した(下記の状態注記)— crypto 層の非防御(この参照が指す事実)は裁定後も変わらない(束縛はサーバー状態が担う)

### 裁定待ち(所有者判断): OIDC トークンの有効期間内リプレイ

> **状態(2026-08-15 追記)**: **裁定済み — 先着束縛を採用**(3 巡の設計探索を経た所有者裁定。比較・却下案・先例は docs/notes/session-24.md)。サーバーが発行時に「トークンハッシュ → 一時公開鍵」を記録し、同一トークン + 別鍵の再要求を 401 `token-replayed` で拒否する(AUTH_SPEC §14-1 / §14-3、CRYPTO_SPEC §9.1 は非保証を「初回使用前の先着」と「クロスプロジェクト先着」に縮小)。ワイヤ形・lease_policy 照合意味論・claims_digest・チェーン形式は不変のため、以下の「緩和はいずれもワイヤ形・ポリシー照合意味論に影響する」との先行評価は、採用案には当たらなかった(当たるのは却下した所持証明系 — 同ノート)。以下は裁定前の記録として残す。

PR #65 が明示的に申し送った未決事項(実装バグではなく仕様どおりの挙動)。`claims_digest` は issuer / subject / audience のみを束縛し、一時公開鍵も nonce も含まないため、**有効期間内のトークンのコピーを入手した者は自分の一時鍵で正当に再ラップされた DEK を受け取れる**(露出窓 = `exp - iat`。GitHub Actions の OIDC トークンは既定 ~10 分)。§9.1 の保証は「別のワークロード同一性への転用不可」であり、同一同一性でのベアラーリプレイ防止ではない(CRYPTO_SPEC §9.1 に非保証として明文化済み)。緩和はいずれもワイヤ形・ポリシー照合意味論に影響する(`aud` への一時鍵ハッシュ混入 / サーバー発行 nonce の 2 往復)ため、**A3(CI クライアント)実装前に裁定が必要**。

---

## 追補 3(2026-08-15): フォローアップ修正の自己レビュー

M-2 / A-1 / L-1 / L-3 / L-5 / A-3 / A-4 の修正差分そのものを、独立した 2 巡のレビュー(1 巡目 = 単一パスの全面レビュー、2 巡目 = 敵対的レビュー + 規律整合レビューの並行)にかけた。結果は本文の各状態注記に反映済み(L-3 の「緩和済み」への格下げ、A-1 の「是正済み」への限定、M-2 の残余 2 点、A-4 の適用範囲の拡張)。新規指摘は 1 件:

### A-6. `/auth/github/callback` の未認証アウトバウンド増幅と入力上限の欠如(Low・新規)

**場所**: `packages/api-schema/src/auth-api.ts`(`githubCallback` の query)、`apps/server/src/handlers-auth.ts`(callback ハンドラ)

**内容**: L-3 は device/exchange のみを対象としたが、web OAuth の callback も同型の「未認証 → GitHub アウトバウンド」を持つ。state はクッキーとクエリの双方に攻撃者自身が載せられる自己束縛(double-submit)であり、`/auth/github/start` で 1 度 state を得れば、以後は callback 1 リクエストごとに code 交換(正規フローは成功後の `/user`・`/user/emails` を含め最大 3 呼び出し)を誘発できる。しかも `code` / `state` クエリには**サイズ上限が一切なかった**(device/exchange は 512 文字 + 形式検査)。OAuth の code 形式は仕様が定めないため、device/exchange のような形式検査による遮断はできない。

**対応(実施済み)**: `code` / `state` に 512 文字上限を追加(形式検査は不能のため長さのみ。増幅自体は上限内の code で依然誘発できるため、これは肥大入力の遮断であって主対策は運用レート制限)。`SELF_HOSTING.md` の per-IP レート制限推奨表に callback を追加し、「未認証エンドポイントは 2 つ」という誤記(`/auth/config` / `/auth/github/start` も未認証)を「費用の掛かる処理を第三者が誘発できる未認証面 3 つ」の正確な列挙に訂正。AUTH_SPEC §4 の形式事前検査の項に callback への言及を追記。**残余は L-3 と同一**(形式適合・上限内の洪水への per-IP 制限は運用側)のため、深刻度・状態も L-3 に合わせる。

### 2 巡目で検証し「不成立」を確認した主な攻撃仮説(記録)

- L-1: ヘッダー名の大小文字迂回(effect の Headers は全キー小文字正規化)・principal.kind の第 4 の値(型上 3 値で anonymous は 401 先行)・CORS 経由のヘッダー付与(CORS 不在で preflight 不能)
- L-3: パターンの ReDoS(単一文字クラス + アンカーで線形)・実トークンの誤弾き(`gh[a-z]_` は gho/ghp/ghu/ghs/ghr を包含。`github_pat_` は check-token でどのみち 404 になる経路のため機能欠落なし)
- A-1: 削除経路との受理境界のズレ(削除は保存行クラス突合で必ず片方が 404)・epoch の数値表現によるキー衝突(`PositiveInt` Schema + 十進表記の単射性)
- L-5: 204/null ボディ・ストリーミング応答の再ラップ(`new Response(body, …)` は両方合法)・静的資産のキャッシュ破壊(API worker に assets バインディングなし)
- テスト改名(`gho_test<n>` 等)による検証力低下(「不正トークン」系はすべて形式適合のまま check-token 経路を通ることを確認)

---

## 仕様上の既知の残余(参照)

以下は実装の不備ではなく、CRYPTO_SPEC §14.3 が明示する v1 の非保証であり、本レビューでは再指摘しない: 可用性(G8)、平文の正しさ(G9)、床なし初回同期クライアントへの巻き戻し配布、split view の機構的未検出、在籍区間内座標への共謀注入(特にメタステートメントの前進注入)、既読値の取り消し不能。緩和(帯域外アンカー・ヘッドゴシップ・環境マニフェスト)は Phase 2 の責務として仕様に計画済み。

## 推奨する対応順序(2026-08-15 改訂)

1. ~~M-1~~ — **PR #63 で解消済み**
2. ~~M-2 / A-1 / L-1 / L-3 / L-5 / A-3 / A-6~~ — **2026-08-15 のフォローアップで対応済み**(各指摘の状態注記を参照 — L-3 / A-6 は「緩和」・A-1 は「是正」に留まる。A-1 は A2 のリース本稼働により優先度を繰り上げて対応した)
3. ~~A-2~~ — **PR #65 で解消済み**(追補 2 で検証)
4. ~~OIDC リプレイの裁定(追補 2)~~ — **裁定・実装済み(2026-08-15)**: 先着束縛を採用(追補 2 の状態注記と docs/notes/session-24.md を参照)
5. **L-2 / L-4** — Phase 2 のトークン管理 UI / 監査 UI 設計・仕様改訂と同時に
6. **A-5** — A3 実装時の規律として参照(A-4 のコメント追記は実施済み。プローブレート上限の設計判断は既存申し送りと同一)
