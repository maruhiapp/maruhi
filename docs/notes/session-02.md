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

## 未決事項への推奨(所有者の裁定待ち。詳細な選択肢比較はセッション 02 の対話ログ参照)

- **環境モデル(CRYPTO_SPEC #6)**: DEK 粒度 = **プロジェクト × 環境 × エポック**(案 C)を推奨。AAD / HPKE info に環境識別子を追加し、エポックは (プロジェクト, 環境) ごとに独立。「prod だけ閲覧を絞る」将来要件と Phase 2 パリティチェックの前提を、後から変えられない鍵階層のうちに確保する
- **認可モデル(CRYPTO_SPEC #7 + AUTH_SPEC §9-2)**: **org ロールとプロジェクトロールの完全分離**(案 B)を推奨。プロジェクトアクセスの真実源はチェーンのみ(§6.4 と一致)。チェーン上のロールは owner / admin / member / reader の 4 段。grant_server は owner 限定
- **プロジェクトと組織の関係(AUTH_SPEC §9-1)**: **パーソナル org 自動作成**(案 A)を推奨。パーソナル org は通常の org と同一モデル(特別扱いは自動作成のみ)で、チームへ連続的に成長できる
- **監査ログスキーマ**: 独立の `docs/AUDIT_SPEC.md` として、上記 3 決定の直後(同一セッション)に起草することを推奨(読みイベントが 変数 × 環境 を参照するため環境モデルが前提)
- **暗号テストベクター**: HPKE 層は RFC 9180 公式ベクター(spike-c で抽出済み)を流用し、maruhi 固有部(§2.1 エンコーディング、変数暗号化 AAD、チェーン正規化 + 署名、リカバリーラップ)は固定鍵・固定 nonce の手書き JSON + 改竄系 negative を定義。AAD に環境が入るため環境モデル決定後・実装開始前に作成
- **npm `maruhi` プレースホルダ + org**: 所有者の手動作業を推奨(名前確保はエージェントに npm トークンを渡すより所有者アカウントで直接が安全)。時期は「早いほど良い」

## 次セッション以降の残タスク

- [ ] 3 スパイク PR + 本 PR のマージ(上記手順 7)
- [ ] マージ後: 環境セットアップエージェントの実行(bun 1.3.14 / `bun install` / `bunx playwright install chromium`)
- [ ] root 統合 PR(上記 8)+ ROADMAP のスパイク項目チェックオフ
- [ ] 「実装開始前に要決定」3 件の裁定(上記推奨参照)→ CRYPTO_SPEC / AUTH_SPEC 改訂
- [ ] 監査ログスキーマ(`docs/AUDIT_SPEC.md`)起草 → 暗号テストベクター定義(実装より先にコミット)
- [ ] npm `maruhi` プレースホルダ publish + org 作成(所有者の手動作業)
- [ ] funstack-static への upstream 提案: 起動スクリプトの外部ファイル化オプション(+ `<link rel="preload" as="stylesheet">` の誤値報告)
- [ ] Cloudflare 資格情報登録後: 実デプロイ検証(wrangler 一発デプロイ / Alchemy v2 / Static Assets の _headers 反映確認)
- [ ] Effect v4 stable リリース後: ピン更新の独立 PR
