# CLI 引数パーサの再選定(gunshi の代替調査)

**日付**: 2026-08-16 / **状態**: 決定済み(→ **ADR-0016**)。本メモは実測の記録であり、決定そのものは ADR を正とする

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

- 環境: Bun 1.3.14 / effect 4.0.0-beta.107 と **4.0.0-rc.109 の両方**(下記 §5)/ @stricli/core 1.3.0 / gunshi 0.37.1
- 判定: 「拒否」= パース段階で型付きエラー、「沈黙」= エラーなしで**書いたのと違う値**が通る
- effect は beta.107 と rc.109 で **12 形すべて同一の挙動**。プローブのソースも無改修で通った

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
  exit code は errors 非空で 1(maruhi の usage=2 は `Runtime.errorExitCode` をエラー型に持たせて表す — §7)
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

`@effect/platform-bun` は effect と同じ版番号で出ており(beta.107 / rc.109 の両方が存在)、
`FileSystem` / `Path` / `Stdio` / `Terminal` / `ChildProcessSpawner` を `BunServices.layer` で供給する。

### エージェント検出は gunshi のロックインではない(→ §8 で再設計)

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
2. 検査は**すべて Effect の宣言に載せる**(§6 の 2 巡目で実測)。自前で残るのは
   診断文の組み直し(値を出さないため)と、`maruhi run` の `--` 必須(方針)だけ
3. **`@stricli/core` は「Effect 結線より引数の厳密さを優先する」場合の対抗案**として残す
4. エージェント検出は**一次境界を TTY に置き換える**(§8)。env の名前表は二次層に降り、
   ライブラリ選択は安全境界を決める選択ではなくなる

### 見積もりと段取り(提案)

1. **effect を rc.109 へ上げる**(§5。本メモと同時に実施済み)。移行先を rc の API に固定してから書く
2. `pull` / `run` / `env create`(= 危険な形が集中する 3 コマンド)だけを移植する spike PR で、
   args.ts のどれだけが消えるかを実測する。全 14 サブコマンドの一括移行はレビュー単位として大きすぎる
3. ADR 化はその実測の後(ADR-0011「未安定依存」の下に CLI 引数層の決定として追記する形を想定)

## 5. effect 4.0.0-beta.107 → 4.0.0-rc.109(実測)

effect v4 は 2026-08 に rc へ入った(`rc.108` / `rc.109`。beta の最終は `beta.107` = 本リポジトリのピン)。
CLI 移行を書く前に上げておくべきかを判断するため、全ワークスペースの `effect` を rc.109 に差し替えて品質ゲートを回した。

| 検査 | 結果 |
|---|---|
| `tsc --noEmit`(全 7 ワークスペース) | 通過(**ソース変更ゼロ**) |
| `vitest run`(全体) | 48 ファイル / **1488 件すべて通過**(workerd 実環境のサーバー / DO テストを含む) |
| oxlint / ImportLint / fallow audit | 通過 |
| `effect/unstable/cli` の 12 形プローブ | beta.107 と**完全に同一** |

特筆すべきは `apps/server/test/data-policy.test.ts` の**ドリフト検出器が green のまま通ったこと**。
これは「全 14 エンドポイント × 全エラー種で `Schema.is` / `endpoint.error` 由来の fail/die 判定が宣言と厳密一致するか」を
見るもので、PR #49 で beta.107 に対して手動検証した契約導出の自動再実行にあたる。
つまり **rc.109 でも HttpApi のエラー契約の意味は変わっていない**(手動再検証は不要)。

判断: **rc へ上げてから CLI を移行する**。beta のまま移行すると、移行直後に rc 追随の差分を
同じファイル群へもう一度かける二度手間になる。上げる代償は実測上ゼロだった。

## 6. 移行スパイク(pull / run / env create)の実測

`apps/cli/test/support/effect-cli-spike.ts` に 3 コマンドを effect/unstable/cli で組み、
`apps/cli/test/effect-cli-spike.test.ts`(29 件)で maruhi の規律が保たれるかを固定した。
本番の `src/cli.ts` は gunshi のまま(スパイクは測定用。採用時に src へ昇格させる)。

### 分かったこと

1. **12 形すべてで期待どおりの終了コードと診断になった**(29/29 green)。
   `--show=false` / `--show false` は書いたとおり `false` として読まれ、
   `--` の後ろの空文字列は保たれ、`--no-show --show` は落ちる
2. **`env` が真のサブコマンドになる**。gunshi は 1 段しか組めないため maruhi は
   create / rotate / diff を**位置引数**にしており、1 つの引数表に全操作のフラグが
   同居していた。その結果必要だった「その操作に適用されないオプション」の拒否
   (`cli.ts` の `ENV_ACTION_FLAGS` / `optionRestrictedTo` / `actionFlagRejection` /
   `envActionFlagRejection` / `withoutPositionals`。server / invite / member にも同型が
   ある)は、入れ子のサブコマンドにすると**機構ごと不要**になる
3. **既定の英文をそのまま出してはいけない**(重要)。`UnexpectedArgument.arguments` と
   `InvalidValue.value` は**打たれた値そのもの**を持つ。`maruhi push API_KEY "$SECRET"`
   の余分な位置引数は平文なので、`renderErrors: false` にしたうえで**構造化フィールドの
   うち安全なものだけ**(宣言名・候補・個数)から診断を組み直す必要がある。
   スパイクではこれをテストで固定した(値が stderr に出ないことの検査)
4. `Console` を差し替えるとヘルプ・診断が stdout を汚さない(`--help` でも stdout 0 行)
5. `ShowHelp.errors` は**複数の誤りを配列で**返す。gunshi のように 1 件ずつではない
6. **既定では組み込みグローバルフラグが勝手に生える**(実測): `--help` / `--version` に加えて
   `--wizard` / `--completions` / `--log-level` が全コマンドに付き、**`maruhi pull --wizard` は
   対話ウィザードが実際に起動する**。`CliConfig.layer({ builtIns: [Help, Version] })` で
   絞ると `UnrecognizedOption` になることを確認し、スパイクではそう設定した(ADR-0016 決定 5)

### 残る自前検査 → **ほぼ全部 Effect の宣言に置き換わった**(2 巡目の実測)

1 巡目のスパイクでは重複・空の値・rest 必須を自前の `preflight` で書いていたが、
Effect の機構で宣言できることが分かったので**全部消した**(29 件 green)。

| maruhi の規律 | 1 巡目(自前) | 2 巡目(Effect の宣言) |
|---|---|---|
| 同じオプションの重複 | 宣言名で数える走査 | `Flag.atMost(1)` |
| 空 / 空白だけの値 | `isBlank` の走査 | `Flag.withSchema(NonBlank)`(Schema) |
| 実行対象のない `run` | rest の自前検査 | `Argument.atLeast(1)` |
| 実行対象が空文字列(`run -- "$CMD"` の未設定形) | 同上 | `Argument.filter`(2 つ目以降の空文字列は子プロセスの引数として保つ) |
| usage=2 / 失敗=1 | ランナー内の写像 | `Runtime.errorExitCode` をエラー型が持つ(`runMain` の既定 teardown が読む) |

**診断も `--` 必須も Effect の機構に載せた**(3 巡目):

| 残っていた自前 | Effect の機構 | 置き場所 |
|---|---|---|
| 診断文の組み直し(ランナー内の描画ループ) | **`CliOutput.Formatter`** を実装して `CliOutput.layer` で差し込む | `test/support/cli-formatter.ts` |
| `maruhi run` の `--` 必須(ランナーの事前走査) | **`Stdio.args`** を読む Effect + `Runtime.errorExitCode = 2` を持つ型付きエラー | `TerminatorRequired`(コマンド本体の先頭で `yield*`) |

Formatter にした利点は「文面だけを差し替えて、**描画の呼び出しは上流に残す**」こと。
ランナーに if 文を足す形だと、上流が描画経路を増やしたときに素通りする穴ができる。
`formatHelpDoc` は `--help` を明示した実行では既定フォーマッタの全文、
書き方の誤りに添えるときは使い方の 1 行だけ、と出し分ける。

**自前として残るのは「文面そのもの」だけ**になった(値を出さない語彙は maruhi 固有の要件で、
どのライブラリも肩代わりしない)。

### args.ts 911 行の帰属(関数単位の概算)

| 区分 | 関数数 | 行数 |
|---|---|---|
| パーサが構造的に塞ぐため**不要**(boolean の値・rest の再構築・位置引数の数え直し・候補生成・gunshi のエラー写像) | 27 | **525** |
| maruhi の方針として**残る**(重複・空の値・空の位置引数・rest 必須・値を出さない診断) | 12 | 222 |

`restArguments`(gunshi が `--` の後ろの空文字列を落とす回避)・`editDistance` / `nearest` /
`suggestionText`(候補生成 — effect は `suggestions` を構造化して返す)・
`booleanSpellings` 系 5 関数(boolean への値の検出)・`usageErrorMessages` 系 3 関数
(gunshi の `AggregateError` の解体)がまとめて消える。
これは**関数単位の帰属による概算**であって、実際に削除して測った数字ではない。

## 7. Effect の機構で賄える箇所の棚卸し(CLI 全体)

引数層以外も洗い出した。いずれも実在を確認済み(effect 4.0.0-rc.109 / `@effect/platform-bun`)。

| 今の自前実装 | Effect の機構 | 効果 |
|---|---|---|
| トークン・master 鍵・復号値を素の `string` / `Uint8Array` で持つ | **`Redacted`**(`toString` / `toJSON` が伏字を返す。`Redacted.value` で明示的に取り出す。`wipeUnsafe` で破棄も可) | 「平文をログ・エラーに出さない」が**型で担保**される。今は人手のレビューとテスト頼み。`Flag.redacted` もあるので値を取るフラグは最初から包める |
| `live.ts` の `stdin.setRawMode(true)` 手書きノーエコー入力(リカバリーコード) | **`Prompt.password` / `Prompt.hidden`** | 端末制御を持たなくてよい |
| `run.ts` の `Bun.spawn` ラッパ(`ProcessRunner` サービス) | **`effect/unstable/process`**(`ChildProcess` + `BunChildProcessSpawner`)。`env` / `extendEnv: false` / `stdio: "inherit"` を宣言で持つ | 子プロセス env の注入が Effect の API に載る。`extendEnv: false` は maruhi の denylist の考え方と同型 |
| `config.ts` / `floor.ts` / `pins.ts` の `node:fs/promises` 直呼び | **`FileSystem` / `Path`**(+ `BunFileSystem`) | テストが一時ディレクトリ不要に(`FileSystem.layerNoop`) |
| `io.ts` の `envVar`(`MARUHI_TOKEN` 等の env 読み) | **`Config` / `ConfigProvider`** | 設定の出所が 1 つになる |
| `io.ts` の `stdin.isTTY` 直読み | **`Stdio.stdinIsTerminal` / `stdoutIsTerminal`** | 端末判定がサービス化され、テストで偽装できる(§8 の一次境界) |
| `device-flow.ts` のポーリング間隔(下限固定) | **`Schedule`** | 間隔・上限・ジッタが宣言になる |
| `config.json` のパース | **`Schema`** | api-schema と同じ語彙に揃う |

**置き換わらないもの**(正直に記録する):

- `retry.ts` の `retryOnConflict` — CAS 競合の「分類 → 回復(再同期・再署名の材料づくり)→ 再試行」で、
  回復がドメイン固有。`Effect.retry` + `Schedule` には落ちない。**残す**
- 診断文の組み直し(§6 の 3)
- `keychain.ts`(`Bun.secrets`)— Effect に鍵ストアの抽象はない

## 8. エージェント検出の再設計(徹底調査の結果)

### 8-1. 分かったこと

- **Effect には無い**。effect 4.0.0-rc.109 のソース全体に `CLAUDECODE` / `isAgent` 等は 0 件で、
  CLI モジュールにも該当機能はない。CLI ライブラリ一般の機能でもない
- **Bun の `isAIAgent()` は内部実装(Zig)であって公開 JS API ではない**。
  `src/output.zig` の `Output.isAIAgent()` で、**`bun test` の出力を減らす**ために使われている
  (PR #21135。2025-07-18 マージ。`CLAUDECODE=1` / `REPL_ID=1` / `IS_CODE_AGENT=1` を見る。
  後に `AGENT=1` も追加)。`Bun.isAIAgent` は 1.3.14 で `undefined`(実測)、公式ドキュメントにも記載なし。
  **Bun 1.4 の公開情報は 2026-08-16 時点で見つからない**(npm の latest は 1.3.14 / 2026-05-13、
  canary は 1.3.13-canary。ブログにも 1.4 のアナウンスなし)。
  リリースされたら「JS へ露出したか」を確認する価値はあるが、
  仮に露出しても**検出範囲は std-env より狭い**(Bun は 4 変数、std-env は 12 種)。
  いずれにせよ二次層なので設計は依存しない
- **専用パッケージが複数ある**(いずれも依存ゼロ):
  `@vercel/detect-agent` 1.2.5(cursor / claude / cowork / devin / replit / gemini / codex / antigravity /
  augment-cli / opencode / github-copilot / v0)、`std-env` 4.2.0(`agentInfo`)、`ai-agent-detect`、`is-ai-agent`
- **環境変数の標準化は進行中で未確定**。`AGENT` を推す提案(agentsmd/agents.md #136。Goose / Amp が実装済み)と
  `AI_AGENT`(std-env / @vercel/detect-agent が読む)が併存し、Claude Code は `CLAUDECODE=1`、
  Cursor は `CURSOR_AGENT=1`、Gemini CLI は `GEMINI_CLI=1` と各社独自。
  VS Code / Copilot は「エージェントはユーザーと同一環境で動くべき」として**反対**している
- 各ライブラリの検出範囲は**互いに部分集合ではない**(std-env は kiro / pi / auggie を持ち、
  vercel は cowork / antigravity / v0 / github-copilot を持つ)。`@vercel/detect-agent` は
  `/opt/.devin` のようなファイル存在も見るため **async** で、セキュリティ判定としては重い

### 8-2. 核心: deny-list は fail-open である

現行の `gunshi/agent` は「**既知の**エージェントの環境変数に一致したら拒否」する deny-list で、
**境界の定義が上流のリストに依存**する。リストに無い新しいエージェント・自作ハーネス・
CI・ログ収集経路は**素通り**する。上の調査のとおり標準化は未確定で、各社独自変数が乱立しており、
「リストが常に正しい」という前提自体が持たない。

### 8-3. 再設計: 一次境界を「人間の対話端末か」にする(fail-closed)

maruhi の要件は元々「**値を見てよいのは人間が対話端末で実行したときだけ**」である。
それをそのまま判定にする:

1. **一次境界 = TTY**: `stdin` と `stdout` の**両方**が端末か(`Stdio.stdinIsTerminal` /
   `stdoutIsTerminal`。Effect のサービスなのでテストで偽装できる)。
   エージェント・CI・パイプ・リダイレクトはすべて**既定で拒否**になる
2. **二次層 = 既知エージェントの env**: 名前が分かると診断が親切になり、
   PTY を割り当てて実行するエージェントも捕まえられる

**実測(このセッション = 実際に Claude Code の中)**: `stdin/stdout/stderr の isTTY はすべて false`。
一方で環境変数は `CLAUDECODE` と `AI_AGENT` の両方が立っていた。
つまり**どちらの信号でも捕まる**が、**未知のエージェントを止められるのは TTY 側だけ**である。

副次的な効果として `maruhi pull --show > secrets.txt` も拒否される。
これは平文をディスクへ落とす操作であり、ディスクレス不変条件からは**拒否が正しい**。

スパイクでは `apps/cli/test/support/agent-gate.ts` にこの設計を実装し、
「未知のエージェント(`isAgent: false`)でも stdout が端末でなければ拒否」をテストで固定した。

### 8-4. ライブラリ選択の格が下がる

一次境界が TTY になると、env の名前表は**二次層**に降りる。したがって
「どのライブラリを使うか」はもはや安全境界を決める選択ではなくなり、次の順で薄く扱える:

1. **`@vercel/detect-agent`**(依存ゼロ・検出範囲が広い・Vercel 保守)。ただし
   `determineAgent()` が async でファイル存在も見る
2. **`std-env`**(依存ゼロ・同期・現行 `gunshi/agent` と同一実体 = 挙動が変わらない)
3. 将来 `Bun.isAIAgent()` が入ったら依存ゼロで置き換える

**推奨は 2(std-env・同期・現行と同一挙動)を厳密ピンで直接依存**。二次層なので
検出漏れが即座に境界の穴にはならない。加えて検出表のスナップショットテストを置けば、
上流が縮小したときに CI で気づける。

## 9. 再現手順

```bash
mkdir probe && cd probe && bun init -y
bun add effect@4.0.0-rc.109 @effect/platform-bun@4.0.0-rc.109 gunshi@0.37.1 @stricli/core@1.3.0
# 各候補に同じ argv(上表の 12 形)を食わせ、値・エラー・stdout バイト数を記録する
```

測定に使ったスクリプトはリポジトリに含めていない(調査用の使い捨て)。
再測が必要なら上表の argv 一覧から組み直せる。
