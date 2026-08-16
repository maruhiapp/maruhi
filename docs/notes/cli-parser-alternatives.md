# CLI 引数パーサの再選定(gunshi の代替調査)

**日付**: 2026-08-16 / **状態**: 調査のみ(実装・ADR 化は未着手。裁定待ち)

## 0. 背景

gunshi 0.37.1 は「宣言と食い違う書き方を黙って通し、**書いたことと逆の結果**になる」形を複数持つ。
maruhi はそれを `apps/cli/src/args.ts`(911 行)+ 各コマンドのテストで外側から塞いでいるが、
レビュー 7〜10 巡目まで新しい抜けが出続けた(コミット 08b8a98 / 0ea3a34 / ef7cba1)。
特に ef7cba1 の形(`maruhi pull --no-show $FLAGS` が **全シークレットを端末へ出す**)は、
パーサの沈黙がそのまま秘密の漏洩に化ける。修正の反復コストが高いため、代替を実測で比較した。

## 1. 測り方

gunshi で実際に踏んだ 12 形を、同じ argv で各候補に食わせて挙動を記録した(2026-08-16 実測)。
比較対象のコマンド定義はいずれも同型: `pull`(boolean `--show` / string `--env`(別名 `-e`)/ integer `--limit`)、
`run`(可変長 positional)、`env create <environment-id>`。

- 環境: Bun 1.3.14 / effect 4.0.0-beta.107(**リポジトリのピンと同一**)/ @stricli/core 1.3.0 / gunshi 0.37.1
- 判定: 「拒否」= パース段階で型付きエラー、「沈黙」= エラーなしで**書いたのと違う値**が通る

## 2. 結果

| # | 形 | gunshi 0.37.1 | effect/unstable/cli | @stricli/core | util.parseArgs(Bun 内蔵) |
|---|---|---|---|---|---|
| 1 | 未宣言オプション `pull --shwo` | 黙って無視(`strict: true` で拒否可) | 拒否 `UnrecognizedOption` | 拒否 + 候補提示 | 拒否 |
| 2 | `--show=false` | **読まずに true** | `false` として解釈 | `false` として解釈 | 拒否(値を取らない) |
| 3 | `--show false` | フラグ true + 余分な位置引数 | `false` として消費 | **拒否** | true + 位置引数 "false" |
| 4 | 同一オプションの重複 `--env prod -e dev` | **last-wins で沈黙** | **first-wins で沈黙** | **拒否** | last-wins で沈黙 |
| 5 | `--` の後ろの空文字列 | rest から落ちる | 保持 | 保持 | 保持 |
| 6 | 先頭の空位置引数 `"" pull` | 読み飛ばし + positionals に残存 | 拒否 `UnknownSubcommand` | 拒否 + 候補提示 | 保持(解決は自前) |
| 7 | `-- run printenv` のコマンド解決 | **`--` を跨いで解決** | 跨がない `UnexpectedArgument` | 跨がない | 該当機構なし |
| 8 | 必須位置引数の欠落 | optional は未検証 | 拒否 `MissingArgument` | 拒否 | 自前 |
| 9 | 値の無い number オプション | **素の TypeError** | 拒否 `InvalidValue`(型付き) | 拒否(型付き) | 拒否(エラーコード付き) |
| 10 | 位置引数名をオプションで書く | 値を捨てる | 拒否 `UnrecognizedOption` | 拒否 | 拒否 |
| 11 | オプションへ空文字列 | undefined に潰れる | `""` を保持 | `""` を保持 | `""` を保持 |
| 12 | stdout 汚染 | ヘッダーが stdout(`renderHeader: null` で停止) | ヘルプが stdout(Console 差し替えで **実測 0B**) | 既定で stderr のみ(**実測 0B**) | 出力機構なし |

補足(実測値):

- effect/unstable/cli は失敗を `ShowHelp` で包み、`ShowHelp.errors` に**型付きエラーを配列で**持つ。
  gunshi のように 1 件ずつではなく、複数の書き方の誤りを一度に返せる。
  exit code は errors 非空で 1(maruhi の usage=2 へは自前写像が必要)
- effect/unstable/cli の `DuplicateOption` は**宣言の衝突**(親子コマンドで同名フラグ)を指すもので、
  ユーザーが同じオプションを 2 回打った場合は発火しない。#4 は「first-wins の沈黙」のまま
- ヘルプは `Console.log` 経由なので、`Console` サービスを差し替えれば stdout を汚さない
  (`pull --shwo` / `pull --help` の両方で stdout 0 バイトを実測。コマンド出力のみ stdout に残る)

### 依存・サイズ・保守

| 候補 | 実行時依存 | 最小 CLI のバンドル | 最終更新 |
|---|---|---|---|
| gunshi 0.37.1 | **0**(全てバンドル済み) | 31 KB | 2026-07-19 |
| effect/unstable/cli | effect 本体に同梱 + `@effect/platform-bun`(→ `@effect/platform-node-shared`)の 2 パッケージ | 274 KB(うち effect 基盤 86 KB = 既に支払済み。実質増分 ≈ 190 KB) | effect と同一リリース |
| @stricli/core 1.3.0 | **0** | 36 KB | 2026-07-16 |
| util.parseArgs | **0**(Bun 内蔵) | — | — |

`@effect/platform-bun` は **4.0.0-beta.107** が存在し、リポジトリがピンしている effect と版が一致する
(`FileSystem` / `Path` / `Stdio` / `Terminal` / `ChildProcessSpawner` を `BunServices.layer` で供給)。
なお effect には既に `4.0.0-rc.109` タグがあり、beta → rc の追随は別途の独立 PR 案件(ADR-0011)。

### エージェント検出は gunshi のロックインではない

`gunshi/agent` の実体は **std-env 4.1.0 の `agentInfo` の薄いラッパ**(`lib/agent.js` は std-env をインライン化したもの)。
検出は環境変数表(`CLAUDECODE` / `CLAUDE_CODE` / `CURSOR_AGENT` / `CODEX_SANDBOX` / `GEMINI_CLI` /
`OPENCODE` / `AUGMENT_AGENT` / `GOOSE_PROVIDER` / `REPL_ID` / `AI_AGENT` ほか)の走査にすぎない。

したがって乗り換え時の選択肢は「std-env を直接依存に入れる」か「同等の表を自前で持つ(30 行程度)」。
後者は**検出規則が上流の更新で黙って変わらなくなる**という利点がある(現状は安全境界の定義が上流依存)。
対価は新しいエージェントへの追随を自前で行うこと。ディスクレス不変条件の実装なので、
どちらを採るかは人間の裁定事項。

## 3. 評価

### 本命: `effect/unstable/cli`(effect v4 同梱)

- gunshi 由来の 12 形のうち **10 形が構造的に消える**。残るのは #4(重複の沈黙)と #12(要 Console 差し替え)
- **Effect ネイティブ**: 現在の `runCli` にある `Execute` ブリッジ、`Effect.runPromise` の往復、
  defect を usage エラーに化けさせない防御(`Effect.catchDefect`)がほぼ不要になる。
  エラーは `Schema.TaggedError` なので `failure.ts` の写像に素直に載る
- 追加依存は `@effect/platform-bun` のみで、版は effect と歩調が揃う。実バイナリ増分はサイズ上ほぼ誤差
- リスク: **unstable モジュール**(effect v4 の位置づけ)。API 変更は beta → rc → stable で起こりうる。
  ただし maruhi は既に `effect/unstable/http` / `effect/unstable/httpapi` で同じリスクを取っている

### 対抗: `@stricli/core`

- **測った中で唯一、#4(重複)と #3(boolean への空白区切り)をパーサ自身が拒否する**。
  診断は既定で stderr のみ、stdout は全形で 0 バイト。依存ゼロ・36 KB
- 弱点: Effect との結線は今と同じく自前(`execute` 相当のブリッジが残る)。
  エラーは Effect の型付きエラーではないので `failure.ts` へ手で写す必要がある
- 「パーサの強さ」だけを見るならこれが最良。「コード全体の単純さ」では effect/unstable/cli が上

### 見送り

- **util.parseArgs**(Bun 内蔵): #2 を拒否するなど素性は良いが、サブコマンド・ヘルプ・補完が全て自前。
  14 サブコマンドの maruhi には土台が薄すぎる。ただし #4 の検査は tokens で容易なので、
  「どの候補を採っても重複検査は自前で書ける」ことの傍証にはなる
- **clipanion**: 4.0.0-rc.4 の最終更新が **2024-09**。安全境界に置く依存としては停滞が重い
- **commander / cac / citty**: 保守は活発だが、上表の #2〜#4 で gunshi 以上の強さを持たず、乗り換える理由がない

## 4. 推奨

1. **`effect/unstable/cli` への移行を第一候補とする**。理由は「gunshi 由来の穴が 10/12 消える」ことに加え、
   引数層が Effect の型付きエラーに統一され、`args.ts` の相当部分と `runCli` のブリッジが不要になること
2. 移行しても**残る自前検査**(これは維持する):
   - 重複オプションの拒否(#4。argv の事前走査 = 宣言名で数える。現行 ef7cba1 の規律をそのまま移植)
   - 平文値・打たれた綴りを診断に出さない規律(`displayText` / 編集距離による候補提示)
   - 空白だけの値の拒否、操作に適用されないオプションの拒否(`optionRestrictedTo`)、`--reason` の長さ検査
   - usage エラー = exit 2 の写像(`ShowHelp.errors` → maruhi の診断 → 2)
   - ヘルプを stdout に出さないための `Console` 差し替え(実測済み)
3. **`@stricli/core` は「Effect 結線より引数の厳密さを優先する」場合の対抗案**として残す
4. エージェント検出は gunshi から切り離せる(std-env 直接依存 or 自前表)。**どちらにするかは要裁定**

### 見積もりと段取り(提案)

- まず `pull` / `run` / `env create`(= 危険な形が集中する 3 コマンド)だけを移植する spike PR で、
  args.ts のどれだけが消えるかを実測する。全 14 サブコマンドの一括移行はレビュー単位として大きすぎる
- ADR 化はその実測の後(ADR-0011「未安定依存」の下に CLI 引数層の決定として追記する形を想定)

## 5. 再現手順

```bash
mkdir probe && cd probe && bun init -y
bun add effect@4.0.0-beta.107 @effect/platform-bun@4.0.0-beta.107 gunshi@0.37.1 @stricli/core@1.3.0
# 各候補に同じ argv(上表の 12 形)を食わせ、値・エラー・stdout バイト数を記録する
```

測定に使ったスクリプトはリポジトリに含めていない(調査用の使い捨て)。
再測が必要なら上表の argv 一覧から組み直せる。
