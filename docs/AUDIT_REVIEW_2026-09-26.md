# maruhi 外部監査レビューの照合記録(2026-09-26)

- 対象: 外部 AI による 9 領域の並列監査レポート(security / performance / accessibility / maintainability / scalability / architecture / documentation / testing / automation)。対象リビジョン = main `7365781`〜`12e2b9a`。報告は生指摘 60 件・重複 5 件を除いた 55 件(High 6 / Medium 20 / Low 29)
- 手法: 全指摘を現行コード(`12e2b9a`)と 1 件ずつ照合し、「事実 / 一部事実 / 誤り」を判定した。事実のうち、仕様・ADR の改訂も所有者判断も要らないものは PR #203 で修正した
- 本ファイルの役割: **未修正の指摘を忘れないための台帳**。着手・解決したら「状態」列を更新する(SECURITY_REVIEW_2026-08-14.md と同じ運用)

## 状態の凡例

| 状態 | 意味 |
|---|---|
| **修正済み(PR #203)** | この照合で修正した |
| **要仕様改訂** | 事実だが、現挙動を仕様(CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC)が定めている。改訂案 → 所有者承認 → 実装の順 |
| **要人間レビュー** | 事実だが `packages/crypto` に触れる(CLAUDE.md: 人間レビュー必須) |
| **所有者判断** | 事実だが、運用方針・公開契約・依存追加などの判断が要る |
| **見送り** | 事実だが、効果に対して変更の影響が大きい(判断が変われば着手してよい) |
| **誤り** | 照合の結果、主張が成り立たない(理由を併記) |

## 総評

- 報告のとおり、E2EE 境界・暗号仕様との一致・モジュール境界・CI の権限設計に問題は見つからなかった
- High 6 件のうち 2 件(CLI 指紋帳の消失・getting-started の手順)は修正済み。残る 4 件は**同じ根**(メンバーシップチェーンを毎回全件再生する設計)で、いずれも CRYPTO_SPEC §6.4 / AUTH_SPEC §11-5・§14-2 が現挙動を定めている — 仕様改訂の単位でまとめて扱うのが筋
- 監査が見落としていた問題を 1 件、修正中に発見した(P-3 の注記)

---

## Security

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| S-1 | Low | **修正済み(PR #203 `195b8e0`)** | スナップショット復元で退避物の列名を検証せず SQL に埋め込んでいた → 生きた表の列名と順序込みで完全一致を要求し、SQL には生きた表側の列名だけを使う |
| S-2 | Low | 所有者判断 | IP レート制限が binding 欠落・例外時に fail-open。SELF_HOSTING.md が「ratelimits を外せば旧来の無制限に戻る」と公開済みの契約で、fail-closed 化は契約変更。なお報告の「300/hr per project も失われる」は誤り(DO 側の固定窓は影響を受けない。失われるのは per-IP 層のみ) |

## Performance / Scalability

性能と拡張性の指摘は根が重なるため 1 つの表にまとめる(報告の Sc1 = P-1、Sc2 = P-2、Sc4 = P-4、Sc5 ⊃ P-3)。

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| P-1 | High | 要仕様改訂 + 要人間レビュー | 追記・DO コールドスタートのたびにチェーン全件を逐次 Ed25519 検証し、その間は DO の単一 permit が全操作を直列化する。増分検証は CRYPTO_SPEC §6.4(追記時の全チェーン再検証)の改訂。同一パス内の CryptoKey メモ化は仕様変更不要だが `packages/crypto` の変更。`proposalIndexOf` の全件再走査も同根 |
| P-2 | High | 要仕様改訂 | `GET /projects` が候補ごとに `memberRoleFor` の DO RPC を最大 100 件発行し、コールドな DO は全件検証を払う。AUTH_SPEC §11-5 が「≤ 100 DO 確認」を許容し、`project_members` にロール列を持たないのは裁定 BI、D1 にロールを持つ案は §6.4「2 つの真実源の禁止」に反する |
| P-3 | Medium | 一部修正済み(PR #203 `467db6d`)/ 残りは要仕様改訂 | 要ローテーション検出が監査ログを全履歴走査する。**修正**: `variableReadsBy` を窓の包絡(開区間)に絞った。修正中に、従来のクエリが `ae_event` 索引で**全ユーザー**の var.read を読んでいたことが判明(監査の見落とし)→ `+event` で `ae_actor` の範囲走査に固定し、クエリプランをテストで固定した。**残り**: `variableLifecycles` は下限で絞れない(創設は窓より前でも候補)、フラグ状態の実体化は AUDIT_SPEC §4.1 手順 5「解消状態はイベント列から導出する」の改訂。**報告の誤り**: `rotationFlagEvents` は書き込み経路で走らない(GET flags と dismiss のみ)。提案の「seq ≥ triggerSeq」は向きが逆(§4.1 の窓は trigger で**終わる**) |
| P-4 | Medium | 要仕様改訂 | CLI のプロジェクトコマンドごとにチェーン全件を取得・再検証する(sync.ts の「v1 はローカルキャッシュ・差分検証を持たない」は意図した設計)。差分同期は AUTH_SPEC §11 のエンドポイント追加と CRYPTO_SPEC §6.3 のクライアント検証意味論の改訂 |
| P-5 | Medium | 見送り | CLI の値検証・復号が変数ごとに逐次 await(最大 1,000 変数 × 2 操作)。並列化は仕様変更不要。最初の失敗を入力順で報告する現在の意味論を保てば着手してよい |
| P-6 | Medium | 見送り | CLI 起動時に全コマンドモジュールを即時 import する(`--version` で約 0.6 秒)。遅延 import は `COMMAND_SPECS` がパースに要るため中規模のリファクタ |
| P-7 | Medium | **修正済み(PR #203 `f996b8e`)** | `deleteStaleMemberWraps` が `dek_wraps` を全件走査 → 受信者索引 `dw_recipient` を DO マイグレーションに追記。**注意**: DO スキーマ版が 1 上がるため、デプロイ前に取った R2 スナップショットは同じ版のコードでしか復元できない(hosted-ops.md §2-E の想定どおり) |
| P-8 | Low | 誤り | web の `deriveReportedView` の useMemo 化。親の `OverviewTab` は新しい値の到着でしか再描画されず、非表示タブはアンマウントされるため、同じスナップショットでの再計算は実際には起きない |
| Sc-3 | High | 要仕様改訂 | pull / lease / チェーン取得が全件を 1 応答に組み立てる(最大 1,000 変数 × 64 KiB、lease はチェーン全体も同梱)。AUTH_SPEC §14-2(応答 = チェーン全体 + 全アクティブ変数)・§12-7 の規定。「大きすぎる」型付きエラーの上限も仕様変更 |
| Sc-5 | High | 要仕様改訂 | 要ローテーション検出が commit タスク内で同期実行され、推奨の出力件数に上限がない(候補 1 件ごとに `rotation.recommended` 1 行)。出力上限・遅延出力は AUDIT_SPEC §4.1 手順 4(推奨をイベントとして永続化する)の改訂。走査範囲の絞り込みは P-3 で一部実施 |
| Sc-6 | Medium | 要仕様改訂 | ストレージガードの例外面(pull / lease の監査行・削除の墓標・checkpoint)が 9 GB の拒否閾値を越えても書き続け、10 GB の SQLite 上限へ近づく。例外面は AUTH_SPEC §12-8 の列挙。**報告の誤り**: 「警告を ops-alerts へ配線すべき」は実装済み(`storage_warn_projects` / `storage_reject_projects`)— 古いコメントは PR #203 `a7b6dfc` で訂正 |
| Sc-7 | Medium | 要仕様改訂 | lease 発行が未知のプロジェクト ID でも DO を実体化する(SECURITY_REVIEW_2026-08-14 A-4 と同じ事象)。D1 の存在検査は小さな変更だが、AUTH_SPEC §14-3 の判定順・緩和策の記述と、§11-3 の部分状態(DO 初期化済み・D1 行未作成)での偽 404 の扱いを要検討 |
| Sc-8 | Low | 要仕様改訂 | 非 admin の監査可視性述語(OR 条件)が `ORDER BY seq DESC LIMIT` で表の大半を走査しうる。可視性列の追加は AUDIT_SPEC §5.1 のスキーマ、走査予算 + 継続カーソルは §7 のページング意味論の改訂 |
| Sc-9 | Low | **修正済み(PR #203 `128184c`)** | 単独 checkpoint が覆う全環境のスナップショット列挙を毎回 DELETE + 再 INSERT → values digest が不変なら列挙の置換を省く(`environment_checkpoints` 行は常に更新)。**報告の誤り**: 規模は約 1M 行ではなく最大約 100k 行(削除済み環境は対象外) |

## Accessibility

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| A-1 | Medium | **修正済み(PR #203 `42dc6b9`)** | SPA の全画面で `document.title` が "maruhi" 固定 |
| A-2 | Medium | 見送り | SPA 遷移後にフォーカスが h1 へ移らない(報告の「切り離されたノードに残る」は不正確で、実際はブラウザ既定の focus reset で body へ行く)。`navigation.transition.finished` 後にフォーカスする必要があり、初回ロードとの区別も要るので単独で扱う |
| A-3 | Medium | **修正済み(PR #203 `df824de`)** | Load more が読込中にボタンごとアンマウントされ、フォーカスが body へ落ちる |
| A-4 | Medium | **修正済み(PR #203 `cfa1dfb`)** | 失効後の再取得で一覧が消えてフォーカスを失い、成功が通知されない |
| A-5 | Low | **修正済み(PR #203 `e68b75b`)** | サインイン・読込・失敗画面に main ランドマークがない |
| A-6 | Low | **修正済み(PR #203 `03b8b02`)** | 各行の Revoke ボタンの読み上げ名が同一 |
| A-7 | Low | **修正済み(PR #203 `f10aeec`)** | Variable names トグルに `aria-expanded` / `aria-controls` がない |
| A-8 | Low | 見送り | LP の偶数ステップで視覚順と DOM 順が逆。各ステップの本文が自己完結しており影響は軽微。報告の「図をすべて aria-hidden に」はステップ 3 の実体リストを隠してしまうので不可 |
| A-9 | Low | **修正済み(PR #203 `d4c38fa`)** | LP の端末例 2 つでラベルの扱いが不一致 |

## Maintainability

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| M-1 | High | **修正済み(PR #203 `2085907`)** | `known-fingerprints.ts` が ENOENT 以外の読み込み失敗(EACCES / EISDIR / EIO)も「なし」に畳み、`record` が空の帳で上書きして検証済み指紋を失い、`lookup` が変更警告を黙らせていた → ENOENT のみ「なし」。回帰テスト付き |
| M-2 | Medium | 要人間レビュー | §6.2 の投票・定足数ロジックが crypto / CLI(`approval-rules.ts`)/ web(`chain-view.ts`)に 3 重実装。集約は `packages/crypto` からの公開が要る。代替の「共有ゴールデンベクターで 3 実装を同じ入力で検査する」も設計判断(A-F1 と同じ話) |
| M-3 | Medium | 見送り | `isRecord` が 11 ファイルに 2 通りの意味(配列を受けるか)で複製、`parseJsonRecord` の利用は 3 か所のみ。CLI 内の統一は可能だが、crypto と web の写しはパッケージ境界・レビュー境界を越える |
| M-4 | Medium | 見送り | `makeRootCommand` が約 1,500 行の 1 関数(`effect-cli.ts` 5,037 行)。挙動変更なしの大規模リファクタで、並行作業との衝突が大きい |
| M-5 | Medium | 見送り(一部誤り) | `data-http.ts` の `toMetaStatementInput` が §12-2 ステートメントの形を手書きの型で 3 重に宣言。**報告の誤り**: 「黙って別のステートメントが検証される」は誤りで、落ちたフィールドは署名済みステートメントを変え、クライアント側検証が fail-closed で落ちる |
| M-6 | Low | 要人間レビュー | crypto のバイト長定数(`DEK_BYTES` 等)が複数ファイルに再宣言(`FINGERPRINT_BYTES` は報告の 2 ではなく 3 ファイル) |
| M-7 | Low | **修正済み(PR #203 `dcdb9ca`)**(一部誤り) | マニフェスト発行材料の組み立ての重複 → `manifestIssueBaseOf` に一本化。**報告の誤り**: 重複は CLI↔サーバー(通信の両端)ではなく CLI 内部の `push.ts` ↔ `apps/cli/src/schema.ts`。`apps/server/src/schema.ts` は存在しない |
| M-8 | Low | 見送り | `repos.ts`(2,017 行)に 9 つのリポジトリ工場が同居 |
| M-9 | Low | **修正済み(PR #203 `637dcae`)** | `floor-log.ts` の short write 再試行ループの重複 → `appendAll` に一本化 |

## Architecture

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| F-1a | Medium | **修正済み(PR #203 `8e1e9a9`)** | web の `audit-read.ts` が整数でない epoch/version の要素を受理し、core の `auditReadVariablesOf`(落とす)と食い違っていた → core に揃え、core と直接比較するテストを追加 |
| F-1b | Medium | 所有者判断 | web の `chain-view.ts`(約 910 行)がチェーンの畳み込みを手で再実装しており、canonical な fold との一致を検査する仕組みがない。検査には `@maruhi/crypto` / `@maruhi/core` を web の devDependencies に加え、署名付きのフィクスチャ列を用意する必要があり、ADR-0018 の範囲に触れる(M-2 と一緒に扱う) |
| F-2 | Low | **修正済み(PR #203 `5fdd73d`)** | RSC(サーバーグラフ)から dashboard 補助モジュールへの import を止める機械的な検査がなかった |

## Documentation

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| D-1 | High | **修正済み(PR #203 `2350f82` / `b2de09d`)** | getting-started の手順 5 がそのままでは実行できない(`env create` の必須位置引数・既定 project/env の未設定)→ 実行できる並びに修正し、docs の ```sh ブロックが USAGE の必須位置引数を添えているかの検査を `cli-vocabulary.test.ts` に追加 |
| D-2 | Low | **修正済み(PR #203 `2350f82` / `78a573c`)** | docs と web が dashboard を "read-only" と記述(実際は失効 mutation を持つ — ADR-0018 改訂 2) |
| D-3 | Low | **修正済み(PR #203 `2350f82`)** | 削除済みの `args.ts` を指すコメント 2 か所 |
| D-4 | Low | **修正済み(PR #203 `2350f82`)** | AUDIT_SPEC.md が README・docs index の仕様一覧にない |
| D-5 | Medium | **修正済み(PR #203 `2350f82`)** | CONTRIBUTING.md に構成・ローカル実行・テスト範囲(e2e はルートの `bun run test` に含まれない)の記述がない |
| D-6 | Low | 所有者判断 | 英語の HTTP API リファレンスがない。HTTP API を公開面とするか内部とするか(ADR-0017 の境界)の製品判断 |
| D-7 | Low | 所有者判断(一部誤り) | セルフホスト向けの統合インシデント対応手順がない。**報告の誤り**: client_secret のローテーション手順は SELF_HOSTING.md に既にある |

## Testing

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| T-1 | Medium | **修正済み(PR #203 `83b6055` / `b06e044`)** | `maruhi token list / revoke` にテストがなく、`device revoke --revoke-token` は 403 経路しか通っていなかった |
| T-2 | Low | 見送り | サーバーテストが `isolate: false` で共有状態を使い、順序独立性を強制していない(ファイル数は報告の 56 ではなく 63)。`sequence.shuffle`(ファイル単位)で強制できるが、先にシャッフル実行が通ることの確認が要る |
| T-3 | Low | 所有者判断 | 実 CLI を実サーバーに当てるテストがない(ハーネス設計が要る) |
| T-4 | Low | 所有者判断 | カバレッジ計測がない(`@vitest/coverage-*` の依存追加が要り、workerd プールは istanbul が必要) |

## Automation / CI

| ID | 深刻度 | 状態 | 要約 |
|---|---|---|---|
| C-1 | Medium | 所有者判断 | DCO の Signed-off-by を自動で強制していない(DCO App か独自 workflow か) |
| C-2 | Medium | 所有者判断 | ホステッドのデプロイ自動化がない。`deploy` スクリプトが D1 マイグレーションをデプロイ前に適用する(破壊的マイグレーションで稼働中の worker が壊れうる)、ステージングがない、worker コードのロールバック手順がない |
| C-3 | Medium | 所有者判断 | リリースバイナリにビルド来歴の attestation がない(npm は provenance あり。install.sh は checksums 未署名と明記済み — SECURITY_REVIEW_2026-08-14 I-1) |
| C-4 | Low | **修正済み(PR #203 `a7b6dfc`)** | ci.yml に concurrency がない → PR では古い run を取り消し、main の push と release.yml からの workflow_call は run ごとの別グループ(報告の案は release の dry-run と main の push が取り消し合う欠陥があったため修正して適用) |
| C-5 | Low | 一部修正済み(PR #203 `a7b6dfc`)/ 残りは所有者判断 | ops-backup.yml: 並走防止の concurrency は追加。R2 アップロード後の検証と「最新バックアップが古い」検出は運用方針 |
| C-6 | Low | 所有者判断 | pullfrog.yml に `timeout-minutes` がなく、10 個のプロバイダキーを渡している(値と使うプロバイダは所有者のみ知る) |
| C-7 | Low | 所有者判断 | Dependabot と定期 CI 実行がない(「更新は意図した独立 PR で行う」方針との兼ね合い) |
| C-8 | Low | 所有者判断 | CODEOWNERS と PR テンプレートがなく、「crypto 変更は人間レビュー必須」が機械的に担保されない(担当者のハンドルが要る) |
| C-9 | Low | **修正済み(PR #203 `a7b6dfc`)** | Playwright のキャッシュキーが apps/web のピンだけに依存 → apps/web と apps/site のピンが割れたら resolve ステップで止める(実際の危険は導入ステップが web の版しか入れないことで、キャッシュキーではない) |
| C-10 | Low | 見送り | `bun install` のキャッシュがない(効率のみの問題) |

---

## 未修正の指摘の着手単位(提案)

1. **チェーン経済性の仕様改訂**(P-1 / P-2 / P-4 / Sc-3 / Sc-5 / Sc-7 / Sc-8): 報告の推奨順 = ① キャッシュ済み VerifiedChainView に対する追記時の増分検証 → ② member→role の実体化 → ③ 差分同期(afterSeq)+ カーソル付き pull → ④ 追記時に有界な rotation-flag 状態の実体化。いずれも CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC の改訂案 → 所有者承認 → テストベクター先行の順
2. **crypto の整理**(P-1 の CryptoKey メモ化 / M-2 / M-6 / F-1b): 人間レビュー前提。M-2 と F-1b は「3 実装を同じ入力で検査するゴールデンベクター」で一緒に扱える
3. **運用方針**(S-2 / C-1〜C-3 / C-5 残り / C-6〜C-8 / T-3 / T-4 / D-6 / D-7): 所有者判断の後、個別の小 PR
4. **見送り分**(P-5 / P-6 / A-2 / A-8 / M-3〜M-5 / M-8 / T-2 / C-10): 仕様変更不要。手が空いたときに単独 PR で着手してよい
