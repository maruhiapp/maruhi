# セッション 06 メモ(認証・アイデンティティ基盤 — AUTH_SPEC 本実装 + org 連携)

日付: 2026-08-02。前提: PR #14 / #15 マージ済み(チェーン保存・追記 API)。
スコープ: AUTH_SPEC §2〜§6 の本実装(D1 + Drizzle、GitHub OAuth、セッション /
トークン)、チェーン API の認可結線(§11 として仕様化)、統合テスト全面改修。

## 1. やったこと(コミット順 = 層順)

1. **spec**: AUTH_SPEC v0.2 — §11(チェーン API との接続)を追加、§6 にスコープ
   表現・op 別必要権限・v1 線引きを規定(下記 §2 の裁定を反映)
2. **core/api-schema**: 認証サービス境界(Principal / RequestAuth / SessionService /
   TokenService)を core に新設、AuthMiddleware 契約 + auth グループ + 401/403/400
   エラー型を api-schema に追加。membership 全エンドポイント認証必須化・init に orgId
3. **server(D1)**: Drizzle v1(rc.4 完全ピン)+ drizzle-kit generate。リポジトリ層は
   `src/db.package/`(ImportLint 境界)に隔離、公開はドメイン型のみ
4. **server(auth.package)**: GitHub OAuth(web + device 交換)、SessionService /
   TokenService、AuthMiddleware 実装
5. **server(結線・認可)**: env 単位の Layer 構築、DO への ChainState 導出追加、
   §11 の認可順序(404 秘匿 / actor 一致 / スコープ / org)
6. **テスト**: 59 件(サーバー)/ 226 件(root)。認証セットアップ込みに全面改修

## 2. 裁定事項(所有者の実時間裁定を取得済み)

セッション 05 と異なり、AskUserQuestion への実時間応答が得られた。

- **裁定 1(actor 対応)**: 「工数を考慮しない最適解を」との指示。採用: **厳密一致を
  API 受理ポリシーとして要求**(init / append とも認証 user_id == entry.actor.user_id)。
  チェーン合意規則(crypto)は ID 形式非依存のまま — ID 形式を有効性規則へ持ち込む
  ことは暗号学的利得なしにプロバイダ独立性を毀損するため、これが工数と無関係に最適。
  テストベクターは無変更、サーバー統合テストは D1 シード(固定 user_id +
  linked_identities)+ 実発行経路で整合
- **裁定 2**: 非メンバーへの拒否は**一律 404**(存在秘匿)。未初期化と区別しない
- **裁定 3**: init は org 指定必須(member 以上)。**DO 先行 + D1 projects 追従 +
  冪等修復**(行欠損 + 要求者 = genesis actor なら再 init を成功扱い)
- **裁定 4**: 認証エンドポイントは**全部 api-schema**(OAuth リダイレクト系含む)。
  → HttpApi の 302 + Set-Cookie は成立した(§3 参照)
- **確認 A**: 監査ログスキーマ提案は所有者自身が起草済みの docs/AUDIT_SPEC.md
  (PR #10)を提案本体とみなし、重複作成しない。実装は引き続き承認待ち
- **確認 B**: トークンは device flow 発行 + 自トークン失効まで(v1 線引き)

### その他の設計判断(機械的・可逆)

- **Drizzle 採用確定(ADR-0006 の帰結)**: drizzle-orm / drizzle-kit 1.0.0-rc.4。
  ただし **effect-d1 ドライバは不採用** — rc.4 時点で transaction / batch 未対応で、
  getOrCreateUser(§1-5)の原子性(users + linked_identities + org + membership)が
  成立しない。classic drizzle-orm/d1 + D1 atomic batch を tryPromise の薄いアダプタで
  境界内に閉じた(ADR-0006 の想定退避経路)。DO 側チェーンテーブルは引き続き素の SQL
- **DO の membership 判定は CAS より先**: 非メンバーに head-conflict(現ヘッドの
  ハッシュ・seq)や受理ポリシーの判定結果を返すと §11-2 の存在秘匿が破れるため。
  導出 ChainState はヘッドハッシュをキーに DO インスタンスメモリへキャッシュ
- **認可の判定順(init)**: サイズ 413 → actor 403 → トークンスコープ → org 403 →
  DO。資源保護(1 MiB 先行検査)を意味論的判定より先に置く
- **ULID / Base62 は自前実装**(依存追加なし。暗号プリミティブではなく
  エンコーディング。乱数と SHA-256 は WebCrypto)

## 3. ハマったこと・環境知見

- **HttpApi のリダイレクト + Set-Cookie は成立する**(session-05 の未検証項目)。
  ハンドラは success スキーマの値の代わりに `HttpServerResponse` を直接返せる
  (`HttpServerResponse.redirect` + `setCookie` / `expireCookie`。後二者は
  Effect を返すので `Effect.orDie` で合成)。success: `Schema.Void` の通常経路は
  200 で返る(204 が欲しければ raw response を返す)
- **`HttpServerRequest.url` はパスのみ**。絶対 URL(origin 取得)は
  `request.source`(生の Web Request)から取る
- **HttpApiMiddleware の requires は bare requirement になる**: handler 側の要求は
  `Request<"Requires", T>` ファントムとして toWebHandler のリクエストコンテキストへ
  遅延できるが、ミドルウェアの requires(SessionService 等)は Layer 構築時に
  静的に満たす必要がある。env(D1 binding)依存のサービスなので、**webHandler を
  env 単位で構築・WeakMap キャッシュ**する形にした。ミドルウェア実装は
  `HttpApiMiddleware.HttpApiMiddleware<Provides, ErrorSchemas, Requires>` の
  具象型で宣言しないと provideService の Exclude が genericに簡約されず型エラーになる
- **vitest-pool-workers 0.20.1 に fetchMock はない**(cloudflare:test の export から
  消えている)。アウトバウンド fetch のスタブは **miniflare の `outboundService` に
  関数を渡す**(vitest.config.ts = Node 側で実行。本番コードにスタブ分岐が不要になる)
- **drizzle-kit v1 の migration はフォルダ形式**(`drizzle/<name>/migration.sql`)。
  wrangler は `d1_databases[].migrations_pattern: "drizzle/*/migration.sql"` で対応
  済みだが、vitest-pool-workers の `readD1Migrations` はフラット `*.sql` のみ対応
  → 自前リーダー(test/support/read-migrations.ts)で D1Migration[] を組み立て、
  miniflare bindings(TEST_MIGRATIONS)経由で `applyD1Migrations` に渡す
- **`bun x wrangler` 等で消した依存の lock エントリが残ることがある**
  (@effect/sql-d1 を bun remove しても optional peer 解決として復活)。lock から
  手で消して `bun install` で整合確認した
- **`.dev.vars` は gitignore 済み** → コミットするのは `.dev.vars.example`(ダミー値)
- vitest.config.ts のパスは **process cwd 基準**になる(root の `vitest run` で壊れる)。
  `new URL("drizzle/", import.meta.url).pathname` で設定ファイル基準に絶対化
- fallow: `*.package` の index 再エクスポートも未使用エクスポート検査の対象。
  境界の公開面は「実際に消費されるものだけ」に絞る

## 4. 既知の制約の更新

- **解消**: 「API リクエスト認証は未実装(RequestAuth は全リクエスト匿名)」
  「チェーン取得 API は全公開」「プロジェクト作成は org と未連携」(session-05 §4)
  → 本セッションで全て解消。テスト用認証スタブ(auth-stub.ts)は実発行経路 +
  フェイク GitHub(outboundService)に置き換えて削除
- **残る制約**: リカバリーブロブ取得のレート制限は未設計(CRYPTO_SPEC §8。
  今回スコープの optional 項目、未着手)。トークンの一覧・追加発行 UI/API は
  Web ダッシュボード実装時(確認 B の線引き)

## 4.5 レビュー→修正ループ(PR #16 内。3 観点の並行レビュー → 検証 → 修正)

採用・修正済みの指摘(重要度順):

1. **device 交換の audience 検証欠如(セキュリティ・高)**: `/user` での有効性確認
   だけでは他 App 向けに発行されたトークンで他人のアカウントに解決できた
   (confused-deputy)。check-token API(`POST /applications/{client_id}/token`)で
   「自 OAuth App 発行」まで検証する形に修正し、AUTH_SPEC §4-4 に明文化。
   フェイク GitHub に other-app トークンを追加して判別テスト化
2. **同名トークンのローテーション**: 同一 (user, name) への device 交換は既存
   トークンの失効を伴う再発行(api_tokens の無制限増加 DoS 対策。§6 に明文化)
3. **資格情報の優先順位の固定**: Authorization ヘッダー提示時はクッキーへ
   フォールバックしない(無効 Bearer + 有効クッキー = 401)。Bearer スキームは
   RFC 7235 どおり大文字小文字非区別。テストで pin
4. **API 契約の乖離**: logout / revokeToken は `HttpApiSchema.NoContent`(204)、
   OAuth リダイレクト系は `HttpApiSchema.Empty(302)` を宣言(導出クライアントの
   成功ステータス照合が実応答と一致するように)
5. **§3-3 メールフィルタの検証可能化**: フェイク GitHub を ID 帯で応答分岐させ
   (unverified / non-primary / emails 404)、negative テスト 3 件 + 再ログイン時の
   自己修復(サインアップ時の取り損ねを verified メールで補完)を追加
6. **§6 op→権限表の判別テスト**: write スコープで rotate_epoch 可・add_member 403・
   init 403 を追加(全 op を単一水準に潰す退行を検知可能に)
7. **DO キャッシュの単調ガード**: permit なしの snapshotFor が古い ChainState で
   新キャッシュを上書きしうる競合(perf のみ)を headSeq 比較で防止。
   `?? ""` フォールバック(破損を成功応答化しうる)は defect 化
8. **期限切れセッションの cron 掃除**: scheduled ハンドラ + `triggers.crons` +
   sessions.expires_at インデックス(未提示行は resolve 時掃除では消えないため)
9. **認証成功ごとの D1 書き込み間引き**: セッション延長・トークン last_used_at
   とも 1 時間閾値(30 日スライディングの意味論は不変)
10. **その他**: getOrCreateUser の競合判別を UNIQUE constraint メッセージで厳密化
    (非競合の D1 障害を誤分類しない)、requestOrigin の Host ヘッダーフォール
    バック廃止、トークン交換リクエストに User-Agent 付与、フェイクの忠実性強化
    (UA 必須・Accept 分岐・check-token)、core スコープ結合則のユニットテスト
    (個別エントリはワイルドカードを絞れない = 最強一致、を意図として固定)

採用せず記録に留めた指摘(実害小・v1 許容):

- 複数タブでの OAuth 開始は state クッキーが単一スロットのため先行タブが 400 に
  なる(リトライで回復。修正するなら state の複数許容化)
- callback 失敗経路では state クッキーを expire しない(TTL 10 分で自然失効)
- transport 413(生ボディ上限)はスキーマ外の素の応答で、導出クライアントは
  デコードできない(CLI 実装時にハンドリング分岐が要る)

## 5. 次セッションへの申し送り

- **PR マージ後**: ROADMAP Phase 1「サーバー: プロジェクト DO、D1、HttpApi、
  監査ログ(append-only)」の注記更新(D1 + 認証 + チェーン認可まで完了。
  監査ログ実装は AUDIT_SPEC 承認待ち)
- **AUDIT_SPEC(PR #10 で所有者起草)のレビュー・承認が監査ログ実装の前提**
- ~~CI のテレメトリ無効化(spike-b からの申し送り)~~ → **解消済みを確認**:
  .github/workflows/ci.yml に DO_NOT_TRACK=1 / WRANGLER_SEND_METRICS=false が
  設定済み(所有者側で対応済み)
- 未回収の optional 項目: リカバリーブロブ取得のレート制限設計(CRYPTO_SPEC §8)
- CLI 実装時: device flow の CLI 側は `/auth/device/exchange`(HttpApi 導出
  クライアント)+ OS キーチェーン保存。トークンの既定スコープは `* × admin`
  (実効権限はチェーン role で束縛)
- Web ダッシュボード実装時: セッションクッキーは `__Host-` のため wrangler dev
  (http)ではブラウザに保存されない(検証は https 環境かヘッダーで)。書き込み系
  fetch には `x-maruhi-csrf: 1` を付けること
- セルフホスト手順に追加が必要: `wrangler d1 create maruhi` + database_id 差し替え、
  `wrangler d1 migrations apply`、GitHub OAuth App 作成 + GITHUB_CLIENT_ID(vars)/
  GITHUB_CLIENT_SECRET(secret)設定(Phase 1 セットアップウィザードの入力)
