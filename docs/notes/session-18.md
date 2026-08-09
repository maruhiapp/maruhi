# セッション 18 メモ(リカバリーコード — CRYPTO_SPEC §8 の製品化。Phase 1 残項目)

日付: 2026-08-09。前提: PR #37(ADR-0014)マージ済みの main から開始。
スコープ: ROADMAP Phase 1 の「リカバリーコード(保存確認・保管リマインダ等の
紛失対策 UX 込み — ADR-0014 裁定 4 の第一歩)」。暗号層(§8 の wrap / unwrap +
テストベクター)は PR #12 で実装済みのため、本セッションは**サーバー保存・配布
面(AUTH_SPEC §13 起草)+ CLI UX** のみで、`packages/crypto` には触れていない
(暗号仕様の変更なし)。

## 1. やったこと

1. **AUTH_SPEC §13(リカバリーブロブ API)起草**: 実装 PR のマージをもって
   所有者承認とする形式(§5.1 = PR #21 の先例)。要点:
   - ブロブは user 単位で高々 1 つ。再発行 = 置換 upsert(旧ラップは受理と
     同時に消える。削除専用エンドポイントは作らない)
   - **鍵素材管理操作のトークン条件**: 登録・再発行・取得はセッション主体
     または `*` × admin スコープを含むトークンのみ(既定 device flow トークンは
     満たす)。窃取されたスコープ限定トークンによるラップ差し替え =
     可用性攻撃(§12-6 の上書き禁止と同型)と、要監視のブロブ取得を遮断する
   - **取得レート制限(CRYPTO_SPEC §8 の要件)**: 固定窓 1 時間 5 回。
     計数はブロブ行に併置(fetch_window_start / fetch_count)、404 は計数外、
     再発行で窓リセット。ベストエフォートの補助線(暗号境界ではない)
   - `GET /auth/recovery/status` は登録有無 + 更新時刻のみ(リマインダ用。
     スコープ条件・レート制限の対象外)
2. **api-schema**: recoveryPut / recoveryGet / recoveryStatus +
   RecoveryWrapNotFound(404)/ RecoveryRateLimited(429、retryAfterSeconds)。
   ciphertext は 16 B〜16 KiB の hex(受理ポリシー §13-4)
3. **server**: D1 `recovery_wraps`(drizzle migration)、RecoveryRepo
   (upsert / find / recordFetch)、handlers-auth に 3 ハンドラ。
   保存 suite が `maruhi/v1` 以外なら defect(黙って配布しない)
4. **CLI**:
   - `recovery-code.ts`: Base32(RFC 4648)52 シンボル = 4 文字 × 13 グループ。
     復号側は小文字・空白・ハイフンを吸収、**アルファベット外(0/1/8/9)は推測
     置換せず拒否**(誤変換は黙った復号失敗になり原因に辿り着けないため)。
     末尾 4 bit のゼロ詰め検査つき
   - ブロブの直列化形式(§8 の「CLI 実装時に確定」)= キーチェーンの
     StoredMasterKey レコードの JSON。復元側は importMasterKeys の自己検証を
     通してから保存する
   - `key generate` の後段で自動発行: 表示 → **保存確認(最終グループの
     再入力、3 回まで)**。登録は確認より先(確認失敗でも再発行でやり直せる
     状態を先に作る)。確認失敗・登録失敗でも鍵生成は成立し、
     `maruhi key recovery` を案内する
   - `key recovery`(発行・再発行。既登録なら「旧コード無効化」を明示)/
     `key recover`(復元: 認証済み取得 → コード入力 → ローカル復号 →
     キーチェーン保存。**コード入力の再試行はローカル**でレート制限の窓を
     消費しない。既存鍵があれば上書き拒否)
   - **エージェント環境**: コードは鍵素材なので表示を拒否(agent.ts と同じ
     線引き)。`key generate` では発行をスキップして人間の端末を案内(鍵生成
     自体は成立)、`key recovery` 単体では拒否
   - 保管リマインダ: `key show` に recovery 行(未登録なら発行を促す)、
     login 後に状態別の次の一歩(recover / generate / recovery)を案内
     (状態確認の失敗はログイン成功を失敗に変えない — 明示の劣化)
   - CliIo に `promptLine`(対話 1 行入力)を追加。live 実装は TTY では
     raw mode の非エコー入力(secret: true)、非 TTY は素の 1 行読み

## 2. 実装の細部

- **レート制限の設計**: 読み → 条件付き更新の 2 文で、並行リクエストでは計数が
  僅かに超過しうる(仕様に明記)。位置づけは「認証 + 高エントロピーコードの
  二重防御の補助線 + 検出時間稼ぎ」であり、D1 の atomic batch 化は複雑さに
  見合わないと判断
- **status ハンドラを 403 対象にしない理由**: ブロブを運ばず、CLI が認証のたびに
  呼ぶリマインダの前提になるため
- **fallow 対応**: keygen / recover の「既存鍵の上書き拒否」プロローグが
  クローン検出されたため `session.ts` の `ensureNoStoredMasterKey` へ抽出。
  raw mode 入力の文字処理は CRAP 閾値(未テストの live 層)に触れたため
  文字集合の Set + 分岐削減で分割
- **サーバーテストの注意**: 同名 device flow トークンの再発行はローテーションで
  旧トークンを失効させる(§6)ため、同一ユーザーの別主体が要るテストは
  セッション経由で登録した

## 3. スコープ外(申し送り)

- **監査イベント**(auth.recovery_blob_fetched / auth.recovery_code_reissued =
  AUDIT_SPEC §3.1): D1 側監査ログ基盤(§3.1〜§3.2 の保存先)が未実装のため
  記録していない。基盤導入と同時に実装する(AUTH_SPEC §13-5 に明記)
- 印刷用テンプレート等のリッチな保管 UX は将来(v1 はコード表示 + 保存確認 +
  リマインダ)。封印バックアップ・パスキー PRF は ADR-0014 / ROADMAP 将来のまま
- session-11 §5 の残り(公開設定エンドポイント / pull メタデータのみモード)・
  チェーン追記系コマンド・crypto test/checks の整理候補(session-17 §4)は
  未着手のまま有効

## 4. セルフレビューと修正(2 コミット目)

初回コミット後のレビューで CLI 対話レイヤに 5 件の指摘。サーバー層・Base32 は
指摘なし。すべて修正済み:

1. **コード表示を stderr へ**(最重要): 表示ブロックが stdout でプロンプトが
   stderr という不整合は、`key generate > log` で鍵素材が平文ファイルに残り、
   かつ画面にコードが見えないまま保存確認だけが出る形だった。発行の儀式
   (置換警告・コード・案内・確認完了)を丸ごと stderr へ移動
2. **非 TTY の行リーダー共有**: readline を都度作って閉じる形は、閉じた
   インスタンスがバッファ済みの次行を捨てるため、複数プロンプト
   (復元コードの再入力等)で 2 行目以降が消えた。未消費分を保持する
   単一バッファの `makeStdinLineReader` に置換(既終端は `readableEnded` で
   検出 — 'end' は一度しか発火しない)
3. **`key show` のオフライン動作**: recoveryStatus の失敗でコマンド全体が
   落ちるリグレッションを、「確認できませんでした」の明示表示つき劣化に変更
   (本務 = ローカル鍵の表示は成立させる)
4. **raw mode 入力の頑健化**: end/error で settle しない(ハング)・Ctrl+D が
   不可視の入力として連結される・矢印キーのエスケープ列が入力を黙って壊す、を
   修正(エスケープ列は終端英字まで無視、制御文字は無視、Ctrl+D = 中断)
5. **login の案内の無言 catch**: `Effect.catch(() => Effect.void)` は
   CLAUDE.md の「catch で無言に飲まない」に違反。スキップした旨を 1 行
   明示する形へ(コマンドの成否は変えない)

live.ts の入力プリミティブは「テスト用に公開」(repos.ts の isUniqueConflict の
先例)し、live-io.test.ts で 7 件の単体テストを追加(行の持ち越し・CRLF・
改行なし終端・EOF ハング・Backspace・エスケープ列・Ctrl+C/D)。

PR 上のボットレビューからさらに 2 件を反映:

6. **未知 suite の検査を取得計数より先に**(Bugbot。Cursor Autofix も同一修正を
   push — リベースで統合): 配布に至らない defect 応答に固定窓を消費させない。
   未知 suite 行を D1 直接更新で作る回帰テストを追加(500 + fetch_count 不変)
7. **ブロブ取得の CSRF ヘッダー(Security Agent)**: `GET /auth/recovery` は
   状態(取得計数)を持つ GET で、Lax セッションクッキーはクロスサイトの
   トップレベル遷移でも同送される — 第三者サイトが被害者の取得窓(5/h)を
   消費できた。セッション主体に書き込み系と同じ `x-maruhi-csrf: 1` を要求
   (AUTH_SPEC §13-2 に追記。Bearer 主体は対象外)

pullfrog レビュー(設計確認 3 件 + nit 2 件、ブロッカーなし)への裁定:

8. **`key recover` にもエージェント拒否を追加(境界の対称化)**: コードは
   鍵素材であり、エージェント越しの stdin に打ち込ませる経路(入力は
   エージェントのセッション層から読める)も作らない。発行(表示)側と同じ
   線引きで、復元は人間の対話端末で行う。ブロブ取得(要監視イベント)にも
   到達させない
9. **`key generate` の非対話・オフライン契約(意図的、と明文化)**: 発行の
   儀式(コード表示 + 保存確認)は対話端末前提。非対話・オフラインでは
   exit 1 だが、**鍵生成そのものは成立しており**、エラーメッセージが
   `maruhi key recovery` での再開を案内する(再実行の「既に存在します」は
   鍵の上書き拒否として正しい)。非 TTY での確認自動スキップは採らない —
   確認なしの発行を成功と報告すると「保存していないのに登録済み」の状態を
   量産する。CI で master 鍵を生成する正当なフローは存在しない
10. **中断判定の型付け(nit)**: `error.message === "interrupted"` の文字列
    一致を `PromptInterruptedError` クラスの instanceof 判定へ
11. **無監査の窓(確認のみ)**: 鍵素材操作の監査記録が D1 監査基盤導入まで
    存在しない間は §13-5 とおり申し送り。本 PR のマージ = 所有者がこの間を
    明示的に許容した記録とする。nit のもう 1 件(suite 検査と計数の順序)は
    §4-6 で対応済み(レビューは 1316cc9 時点のため既知)

## 5. テスト結果

- server(vitest-pool-workers): recovery.test.ts 13 件(認可 2 主体 / スコープ
  条件 403 / 置換 / レート制限と窓リセット / 404 計数外 / status / Schema 400 /
  401)を含め全通過
- cli(Vitest): recovery.test.ts 13 件(Base32 roundtrip・拒否系、発行 →
  表示コードで実復号できる roundtrip、保存確認失敗、エージェントスキップ /
  拒否、復元成功・誤コード 3 回・404・429・上書き拒否)+ login の案内 2 件 +
  key show の recovery 行 2 件。既存テストは新フローに追随
- `bun run check`(oxfmt / oxlint / tsc / ImportLint / fallow audit / React
  Doctor / 全テスト)green
