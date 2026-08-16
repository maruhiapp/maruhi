# ADR-0016: CLI 引数層は effect/unstable/cli(gunshi 廃止)+ 値表示の境界は TTY を一次とする

Status: 2026-08-16 提案。移行 PR(スパイクの src 昇格)のマージをもって所有者承認(Accepted)とする。

**Context**: gunshi 0.37.1 は「宣言と食い違う書き方を黙って通し、**書いたことと逆の結果**になる」形を複数持つ(実測 12 形。`docs/notes/cli-parser-alternatives.md` §2)。`--show=false` を読まずに `true` にする、同一オプションの重複を last-wins で沈黙して捨てる、`--` の後ろの空文字列を rest から落とす、`--` を跨いでコマンドを解決する、など。maruhi はこれを `apps/cli/src/args.ts`(911 行)と各コマンドのテストで外側から塞いできたが、レビュー 7〜10 巡目まで新しい抜けが出続けた(08b8a98 / 0ea3a34 / ef7cba1)。特に ef7cba1 の形(`maruhi pull --no-show $FLAGS` の `$FLAGS` に `--show` が混ざると**全シークレットが端末へ出る**)は、パーサの沈黙がそのまま秘密の漏洩に化ける。

一方 effect v4 は CLI を本体同梱の unstable モジュール(`effect/unstable/cli`)として持つ。同じ 12 形を beta.107 / rc.109 の両方で実測したところ **10 形が構造的に消え**、残る 2 形(重複指定の沈黙・ヘルプの出力先)も Effect の機構で塞げることを、3 コマンド(`pull` / `run` / `env create`)のスパイク(`apps/cli/test/support/` + 適合検査 27 件)で確認した。effect は 4.0.0-rc.109 へ追随済み(ADR-0011 の系。ソース変更ゼロ・全ゲート green)。

また `gunshi/agent`(AI エージェント環境の検出)は std-env の `agentInfo` の薄いラッパにすぎず、gunshi 固有のロックインではないことも確認した。

**Decision**:

1. **引数層は `effect/unstable/cli`。gunshi は完全に廃止する**(`gunshi/agent` を含む)。追加依存は `@effect/platform-bun`(`BunServices.layer` が `FileSystem` / `Path` / `Stdio` / `Terminal` / `ChildProcessSpawner` を供給)のみで、版は `effect` と同一(現行 4.0.0-rc.109)に揃えて厳密ピンする
2. **引数の検査に自前の走査を書かない**。すべて宣言で表す: 重複指定 = `Flag.atMost(1)`、空・空白だけの値 = `Flag.withSchema`(Schema)、`maruhi run` の実行対象必須 = `Argument.atLeast(1)` + `Argument.filter`。`args.ts` の走査群(boolean への値の検出・rest の再構築・位置引数の数え直し・候補生成・gunshi のエラー写像)は削除する(関数単位の概算で 525 行 / 911 行)
3. **診断は `CliOutput.Formatter` を実装して `CliOutput.layer` で差し込む**。`renderErrors` は既定のままとし、**描画の呼び出しは上流(`showHelp` → `Console`)に残す** — ランナー側に描画の分岐を書き足す形にすると、上流が経路を増やしたときに素通りする穴ができる。文面に出してよいのは**宣言名・候補・個数・期待する型のみ**。`UnexpectedArgument.arguments` と `InvalidValue.value` は**打たれた値そのもの**(平文でありうる)なので出さない。`formatHelpDoc` は `--help` を明示した実行のみ全文、誤りに添えるときは使い方 1 行
4. **終了コードはエラー型が `Runtime.errorExitCode` で持つ**(`runMain` の既定 teardown が読む)。ランナーに写像表を置かない。例外は `ShowHelp`(errors 非空)だけで、effect の 1 を maruhi の **2(書き方の誤り)** に読み替える
5. **`env` / `server` / `invite` / `member` は真の入れ子サブコマンドにする**。gunshi の 1 段制約のために操作を位置引数にしていた結果必要だった「その操作に適用されないオプション」の拒否機構(`ENV_ACTION_FLAGS` / `optionRestrictedTo` / `actionFlagRejection` / `withoutPositionals`)は廃止する
6. **値表示(`pull --show`)の境界は fail-closed の 2 層にする**。一次境界 = `stdin` と `stdout` の**両方が端末**か(`Stdio.stdinIsTerminal` / `stdoutIsTerminal`)。二次層 = 既知エージェントの環境変数(**std-env を直接依存**・厳密ピン・同期 API)。判定材料はいずれも Effect のサービス経由で取り、`process.*` を直に読まない
7. **`maruhi run` は `--` を必須のままとする**。判定は `Stdio.args` を読む Effect(`TerminatorRequired`、exit 2)で行う
8. **stdout はコマンドの出力だけ**。ヘルプ・診断は `Console` を差し替えて stderr へ寄せる
9. **移行は段階的に行う**。スパイクの 3 コマンド(`pull` / `run` / `env create`)を src へ昇格させる PR を先頭に、操作フラグ機構を持つコマンド(`env rotate` / `diff`、`server`、`invite`、`member`)、残りの順で進める。全 14 サブコマンドの一括移行は行わない

**Rationale**: (1) gunshi 由来の危険な形が**構造的に**消える — 外側で塞ぎ続ける方式は、レビュー 4 巡ぶんの実績が示すとおり抜けが尽きない。(2) 引数層が Effect の型付きエラー(`Schema.TaggedError`)に統一され、現行 `runCli` の `Execute` ブリッジ・`Effect.runPromise` の往復・defect を usage エラーに化けさせない防御が不要になる。(3) 検査・診断・終了コード・端末判定がすべて Effect の差し替え点に載るため、自前実装が「文面そのもの」だけに縮む。(4) エージェント検出の deny-list は **fail-open** である — 環境変数の標準化は未確定(`AGENT` と `AI_AGENT` が併存、Claude Code / Cursor / Gemini CLI は各社独自、VS Code / Copilot は反対の立場)で、検出ライブラリの範囲も互いに部分集合ではない。「知っているものを止める」から「人間の端末だけ通す」へ反転させれば、**未知のエージェントも既定で止まる**。実測でも Claude Code 実行下は `stdin/stdout/stderr` の `isTTY` がすべて false だった。

**Consequences**: `effect/unstable/cli` は unstable モジュールであり rc → stable で API が動きうる(ADR-0011 の系: 厳密ピン + 更新は独立 PR。beta.107 → rc.109 では 12 形の挙動もプローブのソースも無改修だった)。UX の変更点は 2 つ: **`maruhi pull --show > secrets.txt` が拒否される**(平文をディスクへ落とす操作であり、ディスクレス不変条件からは拒否が正しい)、**引数の誤りに添えるヘルプが使い方 1 行になる**。依存は `@effect/platform-bun`(+ `@effect/platform-node-shared`)と `std-env` が増え、`gunshi` が消える。バンドルの実質増分は約 190KB(単体バイナリ 62〜96MB に対して誤差)。退避経路: パーサだけを `@stricli/core`(依存ゼロ・重複指定と boolean への値をパーサ自身が拒否する唯一の候補)へ差し替える — その場合 Effect との結線は現行と同じく自前に戻る。`Bun.isAIAgent()` は Zig の内部実装で公開 JS API ではないため採用しない(Bun 1.4 で JS へ露出したら二次層の実装として再判断する。検出範囲は std-env より狭い)。
