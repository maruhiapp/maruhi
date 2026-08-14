# maruhi セキュリティレビュー(2026-08-14)

- 対象リビジョン: `9e30a56c4efa0c46435e15e4d53a7ff20d3567c8`(main 相当)
- 手法: 全レイヤーの静的レビュー(コード実行なし)。仕様書(`docs/CRYPTO_SPEC.md` v0.5-draft / `docs/AUTH_SPEC.md` v0.9-draft / `docs/AUDIT_SPEC.md`)と CLAUDE.md の絶対規則を判定基準とし、実装との乖離・一般的な脆弱性クラス(認証・認可・注入・CSRF・秘密漏洩・DoS・サプライチェーン)を検査した
- 対象範囲: `packages/crypto` / `packages/core` / `packages/api-schema` / `apps/server` / `apps/cli` / `apps/web` / `packaging` / `.github/workflows` / `.claude`
- 本レビューは指摘の記録のみを行う。修正は別途実施する(このファイルの「推奨対応」参照)

## 総評

**クリティカル(即時悪用可能)な脆弱性は発見されなかった。** 仕様と実装の整合性は極めて高く、暗号境界(E2EE)、認可(チェーン導出 role)、存在秘匿(404 統一)、DO の直列化(TOCTOU 対策)、CLI のディスクレス不変条件、Web の CSP、CI の最小権限・SHA ピン留めのいずれも仕様どおり丁寧に実装されている。SQL は全経路パラメタライズ済みで、サーバー・crypto パッケージにログ出力は一切ない。

指摘の中心は次の 2 点:

1. **承認済み仕様(0.5-draft)と実装の乖離の「危険な窓」**: `grant_server` が旧(0.4)形式のまま現行 API で受理可能であり、0.5 の「後方互換なし」前提を壊し得る(M-1)
2. **防御規律の一貫性の穴**: 特権 CI ワークフローのピン留め漏れ(M-2)、監査を伴う GET への CSRF ヘッダー未適用(L-1)など、他所では守られている自らの規律が一部に届いていない箇所

---

## 指摘一覧

| ID | 深刻度 | 対象 | 要約 |
|---|---|---|---|
| M-1 | Medium | server / crypto | 承認済み 0.5-draft 合意規則が未実装のまま `grant_server` を旧形式で受理できる(grandfathering 不要前提の侵食) |
| M-2 | Medium | CI | `pullfrog.yml` が可変タグ参照のまま多数の AI プロバイダ API キーを保持(SHA ピン留め規律の例外) |
| L-1 | Low | server | セッション認証の `GET …/pull`(var.read 監査を記録)に CSRF ヘッダー要求がなく、クロスサイトから監査記録を強制発火できる |
| L-2 | Low | server | API トークンに有効期限がない(`expires_at` 常に NULL) |
| L-3 | Low | server | `/auth/device/exchange`(未認証)にレート制限がなく、GitHub check-token API の枠を第三者が消費できる(ログイン可用性) |
| L-4 | Low | server | `auth.login_failed` の記録上限がグローバル固定窓のため、洪水で標的型失敗の記録を抑制できる(設計文書化済み) |
| L-5 | Low | web / server | HSTS 未設定(custom domain 時)・API 応答にセキュリティヘッダーなし |
| I-1 | Info | packaging | `checksums.txt` が未署名(TLS のみ)— 文書化・ROADMAP 済みの追認 |
| I-2 | Info | server | チェーン追記ごとの全チェーン再検証(最大 10,000 × Ed25519)の DO CPU 上限内の実測未確認 |
| I-3 | Info | .claude | リモート開発環境の SessionStart フックが `curl \| bash` で Bun を導入(開発環境限定) |

---

## 指摘の詳細

### M-1. 承認済み 0.5-draft 合意規則の未実装と `grant_server` の旧形式受理(Medium)

**場所**:
- `packages/crypto/src/internal.package/chain-canonical.ts:45-49`(grant_server の正規化 payload が 3 フィールド — `lease_policy_lp_hex` なし)
- `packages/crypto/src/internal.package/chain-verify.ts:178-190, 389-420`(`shapeGrantServer` / `applyGrantServer` に `duplicate-server-key` 検査なし)
- `apps/server/src/authz.ts:23-25` + `apps/server/src/chain-do.ts`(汎用 append が `grant_server` / `revoke_server` を受理する)
- `apps/server/src/dek-wraps.ts:147-170` / `apps/server/src/composite-programs.ts:97-104`(ラップ完全集合の判定が現メンバー集合のみ — サーバー鍵宛を含まない)

**内容**: CRYPTO_SPEC 0.5-draft(§6.2 の grant_server payload リースポリシー拡張・サーバー鍵の一意性、§9.1 ワークロードリース)と AUTH_SPEC 0.9-draft(§12-4/§12-6 のサーバー鍵宛ラップ、§14 リース API、§15 招待 API)は「本改訂 PR のマージをもって所有者承認」とされ、リポジトリの仕様書はすでに 0.5 形式である。一方、実装は 0.4 形式のままであり、かつ **現行 API は 0.4 形式の `grant_server` エントリを今この瞬間も受理できる**(owner のチェーン role + admin スコープのトークンがあれば汎用 append で通る)。

0.5 の payload 形式変更・`duplicate-server-key` 導入は「**grant_server エントリを含む受理済みチェーンが公開前に存在しない**」ことを根拠に後方互換条項(grandfathering)を持たない(CRYPTO_SPEC §6.2 に明記)。セルフホスト可能な状態で 0.5 実装前に運用が始まると、この前提が第三者のデプロイで崩れる:

- **(a) 可用性・データ喪失級の事故**: 旧形式 `grant_server` を含むチェーンは 0.5 実装後の検証で全無効化される(チェーンが無効 = プロジェクト全体が操作不能)
- **(b) 合意規則設計のやり直し**: 前提が崩れると 0.5 側に grandfathering 条項の追加(仕様が明示的に避けたコスト)が必要になる
- **(c) `duplicate-server-key` 未検査のままメンバー鍵と衝突するサーバー鍵のエントリが混入しうる**

なお現行実装では、grant_server がチェーンに載ってもサーバー鍵宛ラップの登録経路が存在しない(受信者はメンバー必須・完全集合もメンバーのみ)ため、**機密性への直接の実害はない**(サーバーは DEK を得られない)。危険なのは上記の前提侵食である。

**推奨対応**: 0.5 実装(テストベクター再生成込み)が載るまで、`grant_server` / `revoke_server` の受理を **API 受理ポリシーとして両層(worker ハンドラ + DO)で型付きエラー拒否**する(`create_environment` / `rotate_epoch` の `CompositeRequired` ガードと同型の「未実装 op」ガード)。受理ポリシーの追加であり合意規則には触れないため、仕様改訂を要さずに前提を保全できる。

### M-2. `pullfrog.yml` のピン留め漏れ + 多数のシークレット(Medium)

**場所**: `.github/workflows/pullfrog.yml:24-42`

**内容**: `actions/checkout@v6`・`pullfrog/pullfrog@v0` が**可変タグ参照**のまま、`ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` ほか多数のプロバイダ API キーを env で渡している。`release.yml` 自身が「外部 action は commit SHA でピン留めする(特権経路のため。可変タグ経由の上流侵害を排除)」という規律を明文化しており(`ci.yml` / `installer.yml` も遵守)、シークレットを最も多く保持するこのワークフローだけが例外になっている。上流タグの差し替え(アカウント侵害・リポジトリ移譲)でシークレットの持ち出しが成立する。`workflow_dispatch` 限定(起動には write 権限が必要)・`contents: read` である点は緩和要素。

**推奨対応**: 両 action を commit SHA でピン留めする(ファイル冒頭の「DO NOT EDIT」はベンダーテンプレートの注意書きであり、ピン留めは編集許容箇所として扱ってよいか pullfrog 側のドキュメントで確認する)。未使用のプロバイダキー行の削除(設定されていないシークレットは空になるが、行を消せば将来設定されても渡らない)も検討。

### L-1. セッション認証の `GET …/pull` に CSRF ヘッダー要求がない(Low)

**場所**:
- `packages/api-schema/src/data-api.ts:384`(`GET /projects/:projectId/environments/:environmentId/pull`)
- `apps/server/src/programs-environment.ts:173-188`(pull が変数ごとに `var.read` 監査を記録)
- `apps/server/src/auth.package/middleware.ts:57-63`(CSRF 検査は GET/HEAD/OPTIONS を免除)
- 先例: `apps/server/src/handlers-auth.ts:299-309`(`GET /auth/recovery` は「GET だが状態を持つ」ためセッション主体に `x-maruhi-csrf` を要求)

**内容**: 一括 pull は GET だが `var.read` 監査行の記録という状態変化を持つ。セッションクッキーは `SameSite=Lax` のためクロスサイトの**トップレベル遷移**(リンク・`window.open`)でも同送され、第三者サイトが被害者のセッションで pull を発火できる。応答(暗号文・ラップ)は攻撃者に読めない(CORS なし)ため**データ漏洩はない**が、次の影響がある:

- 監査証跡の汚染: 「user X が変数 Y を読んだ」という偽の `var.read` を第三者が被害者アカウントに刻める(退職者を後から exfiltration したように見せる等、フォレンジクスへの毒入れ)。要ローテーション検出(AUDIT_SPEC §4.1)の「確実に取得した」ランクにも混入する(過剰ローテーション側に倒れるため危険方向ではない)
- リカバリーブロブ GET に同じ理由で CSRF ヘッダーを課した自らの規律(「取得計数という状態を持つ GET」)と非対称

緩和要素: project_id = genesis ハッシュは実質 capability であり(AUTH_SPEC §11-2)、攻撃者は対象プロジェクト ID を知る必要がある。また現時点で Web ダッシュボード(セッションで pull を呼ぶクライアント)は存在しない。

**推奨対応**: `recoveryGet` と同じく、**セッション主体の pull(値付き)に `x-maruhi-csrf: 1` を要求**する(Bearer は対象外)。メタデータのみモードは監査を記録しないため対象外でよい。将来 Web ダッシュボードを別 origin に置いて CORS を導入する場合は、この前提(「カスタムヘッダーはクロスサイトから送れない」)が崩れないよう `Access-Control-Allow-Origin` を固定 origin + ヘッダー allowlist で最小に保つこと。

### L-2. API トークンに有効期限がない(Low)

**場所**: `apps/server/src/db.package/repos.ts:394`(`expiresAt: null` 固定)、`apps/server/src/auth.package/token.ts`

**内容**: device flow で発行されるトークンは無期限。失効手段(自己失効・同名再発行によるローテーション)はあるが、漏洩に気づかない限り漏洩トークンが永続する。AUTH_SPEC §6 はデータモデルに `expires_at` を持つが TTL を義務付けていないため仕様違反ではない。CLI トークンはキーチェーン保存かつスコープ実効権限が min(スコープ, チェーン role) で束縛される点は緩和要素。

**推奨対応**: 既定 TTL(例: 90 日)+ 再ログインによる更新を検討する(AUTH_SPEC §6 への追記を伴う)。少なくとも `last_used_at` を使った長期未使用トークンの失効ポリシーを Phase 2 のトークン管理 UI と同時に設計することを推奨。

### L-3. `/auth/device/exchange` のレート制限なし(未認証アウトバウンド増幅)(Low)

**場所**: `apps/server/src/handlers-auth.ts:194-233`、`apps/server/src/auth.package/github.ts:110-129`

**内容**: 未認証で叩ける POST であり、リクエストごとにサーバーが GitHub の check-token API(Basic 認証 = client_id:client_secret)へアウトバウンド呼び出しを行う。この API の呼び出し枠は OAuth App 単位でレート制限されるため、第三者がゴミトークンを流し込むとデプロイメントの枠が枯渇し、**正規ユーザーのログイン(device 交換)が失敗する**可用性攻撃が成立する。ボディは 512 バイト上限(api-schema)で肥大は防いでいるが、リクエストレートの制限がない。`auth.login_failed` の記録上限(L-4)は D1 書き込みを守るだけで、アウトバウンド呼び出しは毎回発生する。

**推奨対応**: (1) GitHub トークンの形式事前検査(`gh[a-z]_` プレフィックス。不一致は GitHub へ問い合わせず即 400)で無差別洪水の大半を遮断する。(2) セルフホスト手順(`docs/SELF_HOSTING.md`)に Cloudflare のレート制限ルール(`/auth/device/exchange` への per-IP 制限)の推奨設定を記載する。サーバー内の per-IP 固定窓(D1 or DO)は書き込み増幅と天秤にかけて検討。

### L-4. `auth.login_failed` 記録上限のグローバル固定窓(Low / 設計文書化済み)

**場所**: `apps/server/src/db.package/audit.ts:69-113`

**内容**: 記録上限(100 件/時)がデプロイメント全体のグローバル窓のため、攻撃者が無害な失敗を 100 件流して窓を飽和させると、その後の(標的型の)失敗が記録されない。「洪水そのものは窓内の上限到達として観測できる」と実装コメントで文書化された意図的なベストエフォートであり、上限到達自体がシグナルになる点は妥当。

**推奨対応**: 現状維持でも許容範囲。改善するなら理由種別(`authMethod` × `reason`)ごとの窓に分割するか、上限到達時に「以後 N 件を記録しなかった」ことを示す集約イベントを 1 行残す(抑制の可視化)。

### L-5. HSTS・セキュリティヘッダーの不足(Low)

**場所**: `apps/web/scripts/write-headers.ts:41-45`、`apps/server/src/index.ts`(API 応答)

**内容**: web の `_headers` に `Strict-Transport-Security` がない。`workers.dev` は HSTS プリロード済みのため既定 URL では実害がないが、**custom domain を routes で割り当てた場合**は初回接続のダウングレードが理論上可能。API worker の応答には `X-Content-Type-Options: nosniff` 等が一切付かない(JSON API のみで HTML を返さないため実害は小さい)。

**推奨対応**: `_headers` に `Strict-Transport-Security: max-age=31536000; includeSubDomains` を追加。API 側は共通レスポンスヘッダー(`nosniff` + `Cache-Control: no-store`(トークン・暗号文応答のキャッシュ抑止))の付与を検討。

### I-1. `checksums.txt` 未署名(Info・追認)

`packaging/install.sh:12-13` に「署名検証は書かない(無いものを検証したように見せない)」と明記され、完全性の根拠が github.com への TLS のみであることは正直に文書化されている。ROADMAP の署名導入(minisign / Sigstore 等)を追認する。スクリプト自体は模範的(全体を `main()` に包む・checksum 検証前にインストール先へ書かない・sudo なし・rc ファイル無編集)。

### I-2. チェーン追記ごとの全チェーン再検証コスト(Info)

`apps/server/src/chain-accept.ts:112` は追記受理のたびに `verifyChainEffect([...entries, entry])` で全チェーンを再検証する(最大 10,000 エントリ × Ed25519 検証)。AUTH_SPEC §12-8 が受理済みのコスト水準だが、workerd の CPU 時間上限内に収まるかは上限付近の実測がまだない。member 権限での追記連打は 1 追記あたり O(n) の CPU を消費させられる(直列化されるため DO 単位の遅延)。上限付近のベンチマーク(または導出状態キャッシュを使った増分検証への最適化)を Phase 2 で検討。

### I-3. SessionStart フックの `curl | bash`(Info・開発環境限定)

`.claude/hooks/session-start.sh:17-19` がリモート開発環境で `curl -fsSL https://bun.sh/install | bash` を実行する。バージョンはピン留め済みだがインストーラ自体の検証はない。ユーザー向け成果物ではなく開発環境のみのため Info。気にするなら公式 GitHub Releases からの checksum 付き取得へ置き換え。

---

## 検査済み・問題なしと確認した項目

修正チャットでの再確認を省けるよう、検査して問題がなかった項目を記録する。

### 認証(AUTH_SPEC §3〜§6)
- OAuth state: 128-bit 乱数 + `__Host-` クッキー(HttpOnly/Secure/Lax/10 分)+ 定数時間比較(`handlers-auth.ts:159-164`)。ログイン CSRF はクッキー束縛で遮断
- `redirect_uri` は Host ヘッダーではなく実リクエスト URL の origin から導出(`handlers-auth.ts:44-53`)。オープンリダイレクトなし
- device flow の audience 検証(check-token API)実装済み — 他 App 向けトークンの流用(confused deputy)遮断(`auth.package/github.ts:110-129`)
- GitHub アクセストークンは非永続・非ログ(全経路確認)
- セッション: 256-bit 乱数 → SHA-256 ハッシュのみ DB 保存、スライディング 30 日、DB バック失効、期限切れ行の cron 掃除。トークン: `maruhi_pat_` + Base62(256-bit)、ハッシュ照合 + 定数時間比較、同名ローテーション原子化(atomic batch + UNIQUE)、発行上限 100
- CSRF: カスタムヘッダー `x-maruhi-csrf` + SameSite=Lax + **CORS 不在**(プリフライトが通らないためクロスサイトからカスタムヘッダーを送れない)+ Authorization ヘッダー優先でクッキーへフォールバックしない設計
- 未設定サーバーの fail-closed(503 SetupIncomplete)、プレースホルダ検出
- リカバリーブロブ API(§13): `*`×admin スコープ条件・GET の CSRF ヘッダー・固定窓 5 回/時・404 非計数・suite 検査 — すべて仕様どおり
- メールによる自動リンク・メール検索のコードパスは存在しない。`getOrCreateUser` は (provider, provider_user_id) のみで解決

### 認可・存在秘匿(AUTH_SPEC §9-2 / §11 / §12-3)
- 実効権限 = min(トークンスコープ, チェーン role) の両半分が実装済み(`authz.ts` + DO 側 `requireRole`)。スコープ外 404 / 水準不足 403 / 非メンバー 404 の使い分けが仕様の判定順どおり
- org ロールはプロジェクトアクセスに一切関与しない(真実源はチェーンのみ)
- DO の Semaphore(1) による全操作(読み取り含む)直列化 — メンバーシップ判定とデータ配布の TOCTOU(削除直後メンバーへの配布)を遮断。defect 時のキャッシュ無効化(phantom 状態の防止)も実装済み

### チェーン(CRYPTO_SPEC §6)
- 検証段順(フレーミング → payload 構造 → actor 解決 → 署名 → 認可 + 状態遷移)・全理由コードがテストベクター駆動で固定。不信入力で throw しない設計(`unknown` 受けの実行時検査)
- 合意規則: エポック +1 厳密、`create_environment` 先行要求、環境 ID の履歴全体一意、メンバー鍵一意性(enc/sig 個別)、admin/owner 操作の owner 限定、最後の owner 保護、フィールド 1024 バイト上限、再 grant のスコープ拡大のみ — すべて実装確認
- 正規化(LP エンコーディング)は §2.1 の単一実装を全用途で共有。長さプレフィックスにより連結曖昧性なし
- プロジェクト ID = genesis ハッシュの DO ルーティング束縛(worker 計算 + DO 側再検証)
- 受理ポリシー(1 MiB / 10,000 / 32 MiB)+ HTTP 生ボディ 8 MiB の前段(Content-Length 偽装に依存しない実測強制)
- チェーンミラー監査はチェーン挿入と同一同期タスクで原子コミット。監査 seq の欠番防止(失敗時キャッシュ破棄)

### データプレーン(AUTH_SPEC §12 / CRYPTO_SPEC §4〜§5)
- 値署名・メタステートメントのサーバー検証(§12-5 の 1〜5): 呼び出し主体 = 署名者、宣言ヘッド実在、ヘッド時点の role・鍵束縛(tenure 跨ぎ拒否)、エポック整合(環境作成前ヘッド拒否・既定値フォールバック禁止)、prev 連鎖(CAS 通過後の保存済みアンカー照合)、削除後の再 active 化拒否 — crypto 層 `verifyDistributedValue` / `verifyDistributedMetaStatement` に一元化され、server はそれを呼ぶだけ
- 署名対象の座標はサーバー側の値(genesis ハッシュ・URL・保存先)から再構成し、ワイヤ申告値から組まない(§12-5 の不変条件)。AAD 座標一致検査(422)は認可先行の例外規定どおり自己整合検査のみ
- CAS: version(+1 厳密)・現エポックのみ受理・metaVersion CAS・409 に勝者のハッシュを含めない(証拠連鎖の汚染防止)
- DEK ラップ受理(§12-6): 受信者 = user_id + enc 公開鍵の両方一致、初回登録の完全一致(個数 = 現メンバー数、受信者・重複検査済みなので同値)、追記のみ・上書き禁止(409)、修復経路は admin、登録署名(§5.1)を全経路で検証、配布は本人宛のみ(SQL で recipient 束縛確認)、複合同梱ラップの epoch 等値検査
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

## 仕様上の既知の残余(参照)

以下は実装の不備ではなく、CRYPTO_SPEC §14.3 が明示する v1 の非保証であり、本レビューでは再指摘しない: 可用性(G8)、平文の正しさ(G9)、床なし初回同期クライアントへの巻き戻し配布、split view の機構的未検出、在籍区間内座標への共謀注入(特にメタステートメントの前進注入)、既読値の取り消し不能。緩和(帯域外アンカー・ヘッドゴシップ・環境マニフェスト)は Phase 2 の責務として仕様に計画済み。

## 推奨する対応順序

1. **M-1**(`grant_server` / `revoke_server` の受理ブロック)— 最初の実デプロイ・セルフホスト公開より前に必須
2. **M-2**(pullfrog.yml の SHA ピン)— 変更 1 行×2、即時
3. **L-1**(pull の CSRF ヘッダー)— Web ダッシュボード実装前が最小コスト
4. **L-3 / L-5** — セルフホスト手順書の改訂と合わせて
5. **L-2 / L-4** — Phase 2 のトークン管理 UI / 監査 UI 設計と同時に
