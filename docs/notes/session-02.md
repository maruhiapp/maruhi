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

## 決定事項(エージェント裁量。所有者は「複数案から長期最良を選べ」と委任)

5. **DO 内の Effect Layer の後始末方針**: ManagedRuntime は DO インスタンス生成時に 1 度だけ構築し、**dispose は呼ばない**。その代わり、DO インスタンス寿命の Layer は「ファイナライザの実行に正しさを依存しないもの」に限定し、後始末が必要な本物のリソース(接続・ロック等)は **リクエスト / RPC 呼び出し単位の `Effect.scoped`** で獲得・解放する
   - 理由: workerd の Durable Object には破棄フック(onDestroy 相当)が存在せず、ハイバネーション・エビクションはいつでも起こる。「dispose がいつか呼ばれる」を前提にした設計は原理的に成立しないため、呼ばれなくても正しいことを構造で保証する方が長期的に安全
   - 却下した代替案: (a) リクエストごとに ManagedRuntime を構築・破棄 — DO のインメモリ状態の利点を失い、レイテンシ税を毎回払う。(b) alarm による定期 dispose — 実行保証がなく複雑さだけ増える
6. **3 PR のマージ手順(実測済み)**: **C(#2)→ B(#3)→ A(#4)の順**でマージする。C → B は衝突なし。A のマージで `.fallowrc.json` に 1 箇所衝突が出るが、**A 側(`git checkout --theirs .fallowrc.json`)を採用**すれば正しい統合結果になる(A のブランチに B/C と同一の `spikes/**` 除外行を先行して入れてあるため)。統合状態で `bun run check` 全通過をローカルで確認済み
7. **root 統合(web e2e の CI 追加・`doctor:astryx` の品質ゲート追加・web vitest プロジェクトの扱い)は、3 PR + 本 PR のマージ後の次セッション冒頭で独立 PR として実施**。Cloudflare 資格情報は不要(wrangler dev はローカル完結)なので、デプロイ検証セッションを待つ必要はない

## 承認待ち(人間の判断が必要)

- **CSP のインラインブートストラップの扱い**(スパイク A の発見)。推奨: 当面は「ビルド時 SHA-256 ハッシュ許可」方式(実装済み・動作確認済み)で運用し、funstack-static に「ブートストラップの外部ファイル化オプション」を upstream 提案する。承認されれば CLAUDE.md の「inline script・eval 禁止」を「inline script・eval 禁止(自ビルドが生成する起動スクリプトへのハッシュ許可を除く)」に改訂する

## 次セッション以降の残タスク

- [ ] 3 スパイク PR + 本 PR のマージ(上記手順 6)
- [ ] マージ後: 環境セットアップエージェントの実行(bun 1.3.14 / `bun install` / `bunx playwright install chromium`)
- [ ] root 統合 PR(上記 7)+ ROADMAP のスパイク項目チェックオフ
- [ ] 「実装開始前に要決定」3 件: 環境モデル(CRYPTO_SPEC #6)、認可モデル(#7 + AUTH_SPEC §9-2)、プロジェクトと組織の関係(AUTH_SPEC §9-1)
- [ ] セッション 01 から持ち越しの承認 2 件: CRYPTO_SPEC §8 改訂案(リカバリーラップの AAD / salt)
- [ ] セッション 01 指摘の残り: CLAUDE.md 技術スタック表の docs 行を apps/docs に確定 / ADR-0010 の CI 順序に第 7 ステップ(テスト)がない不一致
- [ ] ROADMAP Phase 0 の残り: 監査ログスキーマ設計、暗号テストベクター定義(実装より先にコミット)、npm `maruhi` プレースホルダ publish + org 作成
- [ ] Cloudflare 資格情報登録後: 実デプロイ検証(wrangler 一発デプロイ / Alchemy v2 / Static Assets の _headers 反映確認)
- [ ] Effect v4 stable リリース後: ピン更新の独立 PR
