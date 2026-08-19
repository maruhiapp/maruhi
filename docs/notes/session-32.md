# セッション 32 メモ(session-31 裁定 1 の仕様起草と strict 受理経路の実証)

日付: 2026-08-19。対象: session-31(PR-M1 マージ後監査)§7 の所有者裁定 3 件のうち
裁定 1 の仕様起草。形式: 仕様改訂 + 技術検証の記録。実装(PR-F1〜F4)は
仕様承認後の別 PR で行う。

## 1. 本 PR で起草したもの(裁定 1 = session-31 の最終推奨をそのまま採用)

- AUTH_SPEC §12-10: security-critical 受理スキーマの厳格性(1-E)・
  wire 非互換変更の設計規範・mutation 成功の定義(1-E′)
- CRYPTO_SPEC §1 原則 6: 意味論は署名バイト列の中に置く(既存アーキテクチャの
  明文化。残余 = 受理側の検証モード選択は裁定 2 の帰結に従うことを明記)

裁定 2(H+1 例外 — 2-F / 2-E / 2-D のはしご)と裁定 3(床 — 3-D + 3-E + 3-E′)は
本 PR に含めない。裁定 2 は一時コスト(2-F = re-genesis + データ層全再構築)の
受け入れが所有者にしか決められず、裁定 3 の §6.3 床節の書き直しは裁定 2 の帰結
(2-F なら床のマニフェスト記録材料がチェーン導出になる — session-31 §7 裁定 1
第 4 次の相乗効果)と文言が絡むため、裁定確定後にまとめて起草する。

## 2. strict 受理の実装経路の実証(session-31 が「PR-F1 の最初の作業」とした確認)

環境: effect 4.0.0-rc.109(リポジトリの厳密ピン)。検証スクリプトは使い捨て
(コミットしない)。

### 2-1. 結論: スキーマ AST 注釈だけで到達できる(HttpApiBuilder の変更不要)

session-31 は「`onExcessProperty` は decode 呼び出しの `ParseOptions` であって
スキーマ注釈ではなく、現行の `HttpApiBuilder` は payload デコーダを
ParseOptions なしで組み立てる」ため、エンドポイント定義でのオプション指定・
手動 decode 層・upstream 対応のいずれかが要ると見込んでいた。実測の結果、
**第 4 の経路(スキーマ自身への焼き込み)が存在し、それだけで足りる**:

- `SchemaParser.makeParser`(dist/SchemaParser.js)は AST 注釈
  `annotations["parseOptions"]` を読み取り、parse 時に
  `mergeParseOptions(options, astOptions)` で合成する
- 合成は **AST 注釈が呼び出し側 ParseOptions に勝つ**(第 2 引数が後勝ち)。
  HttpApiBuilder が options なしで decode しても、将来緩い options を渡す
  実装になっても、スキーマに焼き込んだ strict は維持される

### 2-2. 実測結果(bun + effect rc.109)

`Schema.Struct({...}).annotate({ parseOptions: { onExcessProperty: "error" } })`
に対して、HttpApiBuilder と同一の組み立て
(`Schema.decodeUnknownEffect(Schema.Union([schema]))`、options なし)で:

| ケース | 結果 |
|---|---|
| 素の Struct + 未知フィールド | 黙って除去して成功(M1-A2 の既定挙動の再現) |
| 注釈付き + 未知フィールド | `Expected no excess property at ["manifest"]` で拒否 |
| 注釈付き + 正常入力 | 成功 |
| 親にのみ注釈 + ネスト内の未知フィールド | 拒否(**子へ伝播する**) |
| 注釈付き + 呼び出し側が `onExcessProperty: "ignore"` を明示 | 拒否(**注釈が勝つ**) |
| `Schema.Union` ラップ越し(HttpApiBuilder 実経路と同型) | 拒否 |

### 2-3. PR-F1 実装への含意

- 適用点は `packages/api-schema` の security-critical payload schema のみ
  (トップレベル 1 注釈で全ネストに効く)。共有ラッパー(例:
  `strictPayload(...)`)1 つで単一実装点にできる
- HttpApiBuilder のフォーク・手動 decode 層・upstream issue は不要。
  AUTH_SPEC §12-10 (1) の実装注記に反映済み
- エラーは既存の Schema 検証エラー(400)として表面化する(HttpApiSchemaError
  経由)— 新しいエラー面を増やさない

## 3. 裁定待ちの状態(所有者へ)

- 裁定 1: 本 PR のマージ = 承認
- 裁定 2: 2-F(推奨 — re-genesis + データ層全再構築を許容できる場合)/
  2-E(マニフェスト再発行のみ)/ 2-D(ワイヤ変更なし)の選択待ち。
  いずれも公開前限定の選択肢は 2-F / 2-E(session-31 §7 裁定 2)
- 裁定 3: session-31 の最終推奨(意味論 = 3-D 単調 join、保存形 = 3-E
  追記専用ログ、記録規律 = 3-E′ journal-before-release、コンパクション =
  M1 はスナップショット行方式)の確認待ち。承認されれば裁定 2 の確定と
  合わせて §6.3 床節の改訂を起草する
