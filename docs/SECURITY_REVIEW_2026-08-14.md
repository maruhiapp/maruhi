# maruhi セキュリティレビュー(2026-08-14)

- 対象リビジョン: 本編 = `9e30a56c4efa0c46435e15e4d53a7ff20d3567c8`、追補 = `de8f3af03291a33fa3c5634652040399ded37278`(current main。差 = PR #63 の 67 ファイル / +8,596 行)
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
| M-2 | Medium | CI | 現 main でも有効 | `pullfrog.yml` が可変タグ参照のまま多数の AI プロバイダ API キーを保持(SHA ピン留め規律の例外) |
| L-1 | Low | server | 現 main でも有効 | セッション認証の `GET …/pull`(var.read 監査を記録)に CSRF ヘッダー要求がなく、クロスサイトから監査記録を強制発火できる |
| L-2 | Low | server | 現 main でも有効 | API トークンに有効期限がない(`expires_at` 常に NULL) |
| L-3 | Low | server | 現 main でも有効 | `/auth/device/exchange`(未認証)にレート制限がなく、GitHub check-token API の枠を第三者が消費できる(ログイン可用性) |
| L-4 | Low | server | 現 main でも有効 | `auth.login_failed` の記録上限がグローバル固定窓のため、洪水で標的型失敗の記録を抑制できる(設計文書化済み) |
| L-5 | Low | web / server | 現 main でも有効 | HSTS 未設定(custom domain 時)・API 応答にセキュリティヘッダーなし |
| A-1 | Low | server / crypto | **新規(追補)** | 受信者クラスを跨ぐ識別子衝突(member の user_id = サーバー鍵 FP)でラップ完全集合の初回登録が defect(500)になり、当該環境のローテーション・作成が塞がる |
| I-1 | Info | packaging | — | `checksums.txt` が未署名(TLS のみ)— 文書化・ROADMAP 済みの追認 |
| I-2 | Info | server | — | チェーン追記ごとの全チェーン再検証(最大 10,000 × Ed25519)の DO CPU 上限内の実測未確認 |
| I-3 | Info | .claude | — | リモート開発環境の SessionStart フックが `curl \| bash` で Bun を導入(開発環境限定) |
| A-2 | Info | api-schema / docs | 新規(追補) | `/auth/config` が返す `serverEncPubHex` が AUTH_SPEC §4 の応答定義に明記されていない(仕様先行規律の追随漏れ) |
| A-3 | Info | cli | 新規(追補) | `server grant --expect-fingerprint` は帯域外の控えを渡す前提であり、`/auth/config` から取った値を渡すと照合が自己言及になる(運用ドキュメントで明示すべき) |

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

**場所**: `.github/workflows/pullfrog.yml:24-42`(**現 main でも同様**)

**内容**: `actions/checkout@v6`・`pullfrog/pullfrog@v0` が**可変タグ参照**のまま、`ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` ほか多数のプロバイダ API キーを env で渡している。`release.yml` 自身が「外部 action は commit SHA でピン留めする(特権経路のため。可変タグ経由の上流侵害を排除)」という規律を明文化しており(`ci.yml` / `installer.yml` も遵守)、シークレットを最も多く保持するこのワークフローだけが例外になっている。上流タグの差し替え(アカウント侵害・リポジトリ移譲)でシークレットの持ち出しが成立する。`workflow_dispatch` 限定(起動には write 権限が必要)・`contents: read` である点は緩和要素。

**推奨対応**: 両 action を commit SHA でピン留めする(ファイル冒頭の「DO NOT EDIT」はベンダーテンプレートの注意書きであり、ピン留めは編集許容箇所として扱ってよいか pullfrog 側のドキュメントで確認する)。未使用のプロバイダキー行の削除(設定されていないシークレットは空になるが、行を消せば将来設定されても渡らない)も検討。

### L-1. セッション認証の `GET …/pull` に CSRF ヘッダー要求がない(Low)

**場所**(**現 main でも同様**):
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

**場所**: `apps/server/src/db.package/repos.ts`(`expiresAt: null` 固定)、`apps/server/src/auth.package/token.ts`(**現 main でも同様**)

**内容**: device flow で発行されるトークンは無期限。失効手段(自己失効・同名再発行によるローテーション)はあるが、漏洩に気づかない限り漏洩トークンが永続する。AUTH_SPEC §6 はデータモデルに `expires_at` を持つが TTL を義務付けていないため仕様違反ではない。CLI トークンはキーチェーン保存かつスコープ実効権限が min(スコープ, チェーン role) で束縛される点は緩和要素。

**推奨対応**: 既定 TTL(例: 90 日)+ 再ログインによる更新を検討する(AUTH_SPEC §6 への追記を伴う)。少なくとも `last_used_at` を使った長期未使用トークンの失効ポリシーを Phase 2 のトークン管理 UI と同時に設計することを推奨。

### L-3. `/auth/device/exchange` のレート制限なし(未認証アウトバウンド増幅)(Low)

**場所**: `apps/server/src/handlers-auth.ts`、`apps/server/src/auth.package/github.ts`(**現 main でも同様**)

**内容**: 未認証で叩ける POST であり、リクエストごとにサーバーが GitHub の check-token API(Basic 認証 = client_id:client_secret)へアウトバウンド呼び出しを行う。この API の呼び出し枠は OAuth App 単位でレート制限されるため、第三者がゴミトークンを流し込むとデプロイメントの枠が枯渇し、**正規ユーザーのログイン(device 交換)が失敗する**可用性攻撃が成立する。ボディは 512 バイト上限(api-schema)で肥大は防いでいるが、リクエストレートの制限がない。`auth.login_failed` の記録上限(L-4)は D1 書き込みを守るだけで、アウトバウンド呼び出しは毎回発生する。

**推奨対応**: (1) GitHub トークンの形式事前検査(`gh[a-z]_` プレフィックス。不一致は GitHub へ問い合わせず即 400)で無差別洪水の大半を遮断する。(2) セルフホスト手順(`docs/SELF_HOSTING.md`)に Cloudflare のレート制限ルール(`/auth/device/exchange` への per-IP 制限)の推奨設定を記載する。サーバー内の per-IP 固定窓(D1 or DO)は書き込み増幅と天秤にかけて検討。

### L-4. `auth.login_failed` 記録上限のグローバル固定窓(Low / 設計文書化済み)

**場所**: `apps/server/src/db.package/audit.ts:69-113`(**現 main でも同様**)

**内容**: 記録上限(100 件/時)がデプロイメント全体のグローバル窓のため、攻撃者が無害な失敗を 100 件流して窓を飽和させると、その後の(標的型の)失敗が記録されない。「洪水そのものは窓内の上限到達として観測できる」と実装コメントで文書化された意図的なベストエフォートであり、上限到達自体がシグナルになる点は妥当。

**推奨対応**: 現状維持でも許容範囲。改善するなら理由種別(`authMethod` × `reason`)ごとの窓に分割するか、上限到達時に「以後 N 件を記録しなかった」ことを示す集約イベントを 1 行残す(抑制の可視化)。

### L-5. HSTS・セキュリティヘッダーの不足(Low)

**場所**: `apps/web/scripts/write-headers.ts:41-45`、`apps/server/src/index.ts`(API 応答)(**現 main でも同様**)

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

実装(`packages/api-schema/src/auth-api.ts` / `apps/server/src/handlers-auth.ts`)は `serverKeyFingerprintHex` に加えて `serverEncPubHex` を返す。CRYPTO_SPEC §9 の「サーバーが配布する enc 公開鍵」の配布チャネルとして必要であり公開情報でもある(CLI は FP との自己整合を再計算検証する)ので**実装は妥当**だが、AUTH_SPEC §4 の応答定義には `serverKeyFingerprintHex` しか書かれていない。「仕様が唯一の正」の規律に合わせ、AUTH_SPEC §4 へ 1 行追記して仕様と実装を一致させることを推奨。

### A-3. `--expect-fingerprint` の自己言及照合の注意(Info・新規)

`server grant` の確認の儀式は AI エージェント環境で拒否され、非対話では `--expect-fingerprint` に**帯域外で控えた FP** を渡す設計になっている。「デプロイ直後に FP を控え、それを照合基準にする(非対話は `--expect-fingerprint` に渡す)」ことは `docs/SELF_HOSTING.md` の「フィンガープリントの控え」節と CLI ヘルプ(「帯域外で控えたサーバー鍵 FP」)が**既に記載済み**である。残る差分は 1 点のみ: **grant 実行時に `/auth/config` から機械取得した値をそのまま渡すと照合が自己言及になり儀式が無意味化する**(デプロイ直後の取得は trust-on-first-use のアンカーとして意図された手順であり、grant 時の再取得とは意味が異なる)ことの明示。`SELF_HOSTING.md` の同節に注意書きを 1 行足すことを推奨。

### 追補で検査して問題なしと確認した項目

- lease_policy の CLI ファイル入力: サイズ上限(8/8/1024)を入力段でも検査、claim 名の昇順正規化、`claimValue` は空文字列許容(OIDC claim の実態に一致)— 合意規則の形状検査(crypto 層)と二重化
- `server grant` の儀式は追記スキップ時(バックフィルのみの再実行)でも省略されない
- バックフィルの 409 吸収は「サーバー宛ラップの一覧 API が存在しない(配布は本人宛のみ)」制約下で唯一の収束手段であり、上書きを許さない受理規則と両立
- grant/revoke の CAS リトライは延長検査付き再同期(`resyncExtended`)を経由し、短縮・分岐したチェーンへの再署名を拒否する
- FP ワード表示(BIP39 12 語)は表示符号化のみ(SHA-256 + 固定辞書)で新規プリミティブなし。英語リスト固定・切り詰めなし(§3 どおり)
- DO スキーマ移行(`recipient_class` 列の ALTER TABLE + DEFAULT 'member')は既存行を member として正しく扱う
- テストベクター: grant_server 系の全再生成 + `duplicate-server-key` / 検査順序 / 旧形式拒否(`grant-server-lease-policy-dropped`)/ 受信者クラス server の正負例が追加済み(仕様 §11 の「実装より先にベクター」の規律を維持)

---

## 仕様上の既知の残余(参照)

以下は実装の不備ではなく、CRYPTO_SPEC §14.3 が明示する v1 の非保証であり、本レビューでは再指摘しない: 可用性(G8)、平文の正しさ(G9)、床なし初回同期クライアントへの巻き戻し配布、split view の機構的未検出、在籍区間内座標への共謀注入(特にメタステートメントの前進注入)、既読値の取り消し不能。緩和(帯域外アンカー・ヘッドゴシップ・環境マニフェスト)は Phase 2 の責務として仕様に計画済み。

## 推奨する対応順序

1. ~~M-1~~ — **PR #63 で解消済み(対応不要)**
2. **M-2**(pullfrog.yml の SHA ピン)— 変更 1 行×2、即時
3. **A-1**(クラス横断の識別子重複を受理前に 422 で拒否)— 受信者クラス server の運用開始前が最小コスト
4. **L-1**(pull の CSRF ヘッダー)— Web ダッシュボード実装前が最小コスト
5. **L-3 / L-5 / A-3** — セルフホスト手順書の改訂と合わせて
6. **L-2 / L-4 / A-2** — Phase 2 のトークン管理 UI / 監査 UI 設計・仕様改訂と同時に
