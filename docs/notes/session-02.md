# セッション 02 引き継ぎメモ(Phase 0 検証スパイク C / B / A + 決定事項)

日付: 2026-08-01。スコープは ROADMAP Phase 0 の検証スパイク 3 本と、その結果を受けた所有者との決定。

## このセッションでやったこと

1. ステップ 0: セッション 01 指摘の文書修正(ADR-0003 Status 明記、ROADMAP 要決定 3 件化、adr README 前文削除、ADR-0005/0009 誤字)→ スパイク C の PR に同梱
2. スパイク C(PR #2): HPKE 検証 → `docs/notes/spike-c.md`
3. スパイク B(PR #3): サーバー基盤結線 → `docs/notes/spike-b.md`
4. スパイク A(PR #4): フロント基盤 → `docs/notes/spike-a.md`
5. 所有者との Q&A による決定(下記)と CRYPTO_SPEC への反映(本 PR)

## 決定事項(2026-08-01、所有者確認済み)

1. **HPKE ライブラリ = `hpke`(panva)を採用**。退避経路 = hpke-js(dajiaji)。CRYPTO_SPEC §2 / §13 に反映済み(本 PR)。Open は KeyPair 渡しを標準とする
2. **Safari(Navigation API 未対応ブラウザ)はサポートしない**。主要ターゲットは PC の Chrome。`<Router fallback="static">`(MPA 劣化)は保険としてコードに残すが、劣化モードの UX 検証・改善は行わない
3. **Effect v4 は今月中に stable リリース見込み**のため、beta 固有の問題は深追いしない。stable が出たら独立 PR でピン更新(ADR-0011 の運用)
4. Cloudflare 資格情報は後日登録。**実デプロイ検証(wrangler / Alchemy v2)は資格情報登録後の別セッション**で行う
5. **CSP のインラインブートストラップ例外を承認**(所有者)。「自ビルドが生成する起動スクリプトへの SHA-256 ハッシュ許可」のみ可、`'unsafe-inline'` は常に禁止。CLAUDE.md に明文化済み(本 PR)。funstack-static への外部ファイル化オプションの upstream 提案は別途行う

## 決定事項(エージェント裁量。所有者は「複数案から長期最良を選べ」と委任)

6. **DO 内の Effect Layer の後始末方針**: ManagedRuntime は DO インスタンス生成時に 1 度だけ構築し、**dispose は呼ばない**。その代わり、DO インスタンス寿命の Layer は「ファイナライザの実行に正しさを依存しないもの」に限定し、後始末が必要な本物のリソース(接続・ロック等)は **リクエスト / RPC 呼び出し単位の `Effect.scoped`** で獲得・解放する
   - 理由: workerd の Durable Object には破棄フック(onDestroy 相当)が存在せず、ハイバネーション・エビクションはいつでも起こる。「dispose がいつか呼ばれる」を前提にした設計は原理的に成立しないため、呼ばれなくても正しいことを構造で保証する方が長期的に安全
   - 却下した代替案: (a) リクエストごとに ManagedRuntime を構築・破棄 — DO のインメモリ状態の利点を失い、レイテンシ税を毎回払う。(b) alarm による定期 dispose — 実行保証がなく複雑さだけ増える
7. **3 PR のマージ手順(実測済み)**: **C(#2)→ B(#3)→ A(#4)の順**でマージする。C → B は衝突なし。A のマージで `.fallowrc.json` に 1 箇所衝突が出るが、**A 側(`git checkout --theirs .fallowrc.json`)を採用**すれば正しい統合結果になる(A のブランチに B/C と同一の `spikes/**` 除外行を先行して入れてあるため)。統合状態で `bun run check` 全通過をローカルで確認済み
8. **root 統合(web e2e の CI 追加・`doctor:astryx` の品質ゲート追加・web vitest プロジェクトの扱い)は、3 PR + 本 PR のマージ後の次セッション冒頭で独立 PR として実施**。Cloudflare 資格情報は不要(wrangler dev はローカル完結)なので、デプロイ検証セッションを待つ必要はない

## 決定事項(エージェント委任分・追加)

9. **CRYPTO_SPEC §8 改訂案(2026-07-31 反映分)を承認**(所有者が判断を委任)。根拠: recovery_secret は一様ランダム 256-bit であり RFC 5869 §3.1 の salt 省略条件に該当、用途分離は info が担保、AAD は §2.1 エンコーディングで user_id に文脈束縛される。セッション 01 の裏取り(Infisical のリカバリー経路と同型 + AAD は上乗せ強化)とも整合
10. **セッション 01 指摘の文書不一致を解消**(所有者が委任): CLAUDE.md 技術スタック表の docs 行を `apps/docs` に確定 / ADR-0010 の CI 順序に第 7 ステップ(テスト)を追記(本 PR)

## 決定事項(追加裁定)

11. **環境モデル = 案 C を採用**(所有者裁定 2026-08-01): DEK 粒度 = **プロジェクト × 環境 × エポック**。AAD / HPKE info に環境識別子を追加し、エポックは (プロジェクト, 環境) ごとに独立。v1 では環境別の権限 UI は作らず(全メンバー全環境)、データ構造のみ環境対応にする。CRYPTO_SPEC 本文の改訂(§3 / §4 / §5 / §13 #6)は認可モデル・org 関係の裁定と合わせて 1 回で行う
12. **暗号テストベクターの方針を承認**(所有者): HPKE 層は RFC 9180 公式ベクター(spike-c で抽出済み)を流用し、maruhi 固有部(§2.1 エンコーディング、変数暗号化 AAD、チェーン正規化 + 署名、リカバリーラップ)は固定鍵・固定 nonce の手書き JSON + 改竄系 negative を定義。環境モデル反映後・実装開始前にコミット
13. **npm 確保の分担**(所有者): org `maruhi` の作成のみ所有者が Web UI で実施(API 非提供のため)。プレースホルダパッケージ `maruhi` の publish はエージェントが行う。npm トークン(Granular Access Token)は Cloud Agents > Secrets に `NPM_TOKEN` として登録予定 → 登録後の新セッションで実施

14. **認可モデル = 案 B を採用**(所有者裁定 2026-08-01): org ロールとプロジェクトロールの完全分離。チェーン上の role は owner / admin / member / reader の 4 段、grant_server / revoke_server は owner 限定。CRYPTO_SPEC §6.2 / §13 #7、AUTH_SPEC §2 / §9-2 に反映済み(本 PR)
15. **プロジェクトと組織の関係 = 案 A を採用**(所有者裁定 2026-08-01): パーソナル org 自動作成、projects.org_id は NOT NULL、単独利用時は UI で org を隠す。AUTH_SPEC §9-1 に反映済み(本 PR)
16. **「セルフホスト = 1 人専用 + ホステッド = WorkOS で組織機能」案は取り下げ**(所有者、2026-08-01 議論の結果)。評価の記録: (1) WorkOS が提供するのは認証(SSO)とディレクトリ同期であり、maruhi の組織機能の本体(誰が DEK を受け取るか = チェーン + クライアント暗号操作、role 認可)は E2EE の性質上外注不能で、設計量は減らない。(2) 1 人専用とマルチテナントで製品が分岐し、以後の全機能を 2 回作ることになる(ADR-0009 の同一コードベース戦略と衝突)。(3) セルフホストからチーム利用を外すと OSS 配布物の価値が痩せる(FSL が禁じたいのは競合 SaaS であり、企業の自社チーム利用は歓迎すべき採用経路)。(4) 「後から WorkOS を無停止で挿せる」ことは AUTH_SPEC §7 の挿入ポイント設計が既に最小コストで担保している。なお監査ログは actor = 内部 user_id + 鍵フィンガープリントのみという絶対規則により WorkOS 採否と独立
17. **監査ログスキーマ(`docs/AUDIT_SPEC.md`)は次セッションで起草**(所有者確認済み): 本 PR の仕様改訂(環境モデル・認可モデル)がレビュー・マージされた内容を前提に書くのが手戻りがないため
18. **npm の名前確保は完了**(2026-08-01): org `maruhi`(@maruhi スコープ)は所有者が作成、プレースホルダ `maruhi@0.0.1` はエージェントが publish 済み(maintainer: 所有者アカウント)。使用したトークンは短命の使い捨てで、publish 直後に所有者が Revoke する運用とした(Cloud Agents Secrets への恒久登録はせず。Phase 2 の本 publish は provenance 付き CI publish に切り替える)

## 次セッション以降の残タスク

- [ ] 3 スパイク PR + 本 PR のマージ(上記手順 7)
- [ ] マージ後: 環境セットアップエージェントの実行(bun 1.3.14 / `bun install` / `bunx playwright install chromium`)
- [ ] root 統合 PR(上記 8)+ ROADMAP のスパイク項目チェックオフ
- [ ] 監査ログスキーマ(`docs/AUDIT_SPEC.md`)起草 → 暗号テストベクター定義(実装より先にコミット)。いずれも本 PR の仕様改訂マージ後
- [x] ~~npm プレースホルダ publish~~(2026-08-01 完了。`maruhi@0.0.1`)
- [ ] ROADMAP のチェックオフ(#2 マージ後の root 統合 PR で。対象: 要決定 3 件・検証スパイク 3 本・npm プレースホルダ + org — いずれも完了済み)
- [ ] `spikes/` の使い捨てコードの削除(所有者承認済みの方針: Phase 1 で crypto の 3 環境 CI とサーバー実装の雛形として参照し終えた時点で削除。その際 `.fallowrc.json` の `spikes/**` 行も戻す)
- [ ] funstack-static への upstream 提案: 起動スクリプトの外部ファイル化オプション(+ `<link rel="preload" as="stylesheet">` の誤値報告)
- [ ] Cloudflare 資格情報登録後: 実デプロイ検証(wrangler 一発デプロイ / Alchemy v2 / Static Assets の _headers 反映確認)
- [ ] Effect v4 stable リリース後: ピン更新の独立 PR
