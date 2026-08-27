# ADR-0016: CLI 引数層は effect/unstable/cli(gunshi 廃止)+ 値表示の境界は TTY を一次とする

Status: 2026-08-16 提案。移行 PR(スパイクの src 昇格)のマージをもって所有者承認(Accepted)とする。

**Context**: gunshi 0.37.1 は「宣言と食い違う書き方を黙って通し、**書いたことと逆の結果**になる」形を複数持つ(実測 12 形。`docs/notes/cli-parser-alternatives.md` §2)。`--show=false` を読まずに `true` にする、同一オプションの重複を last-wins で沈黙して捨てる、`--` の後ろの空文字列を rest から落とす、`--` を跨いでコマンドを解決する、など。maruhi はこれを `apps/cli/src/args.ts`(911 行)と各コマンドのテストで外側から塞いできたが、レビュー 7〜10 巡目まで新しい抜けが出続けた(08b8a98 / 0ea3a34 / ef7cba1)。特に ef7cba1 の形(`maruhi pull --no-show $FLAGS` の `$FLAGS` に `--show` が混ざると**全シークレットが端末へ出る**)は、パーサの沈黙がそのまま秘密の漏洩に化ける。

一方 effect v4 は CLI を本体同梱の unstable モジュール(`effect/unstable/cli`)として持つ。同じ 12 形を beta.107 / rc.109 の両方で実測したところ **10 形が構造的に消え**、残る 2 形(重複指定の沈黙・ヘルプの出力先)も Effect の機構で塞げることを、3 コマンド(`pull` / `run` / `env create`)のスパイク(`apps/cli/test/support/` + 適合検査 32 件)で確認した。effect は 4.0.0-rc.109 へ追随済み(ADR-0011 の系。ソース変更ゼロ・全ゲート green)。

また `gunshi/agent`(AI エージェント環境の検出)は std-env の `agentInfo` の薄いラッパにすぎず、gunshi 固有のロックインではないことも確認した。

**Decision**:

1. **引数層は `effect/unstable/cli`。gunshi は完全に廃止する**(`gunshi/agent` を含む)。追加依存は `@effect/platform-bun`(`BunServices.layer` が `FileSystem` / `Path` / `Stdio` / `Terminal` / `Crypto` / `ChildProcessSpawner` を供給)のみで、版は `effect` と同一(現行 4.0.0-rc.109)に揃えて厳密ピンする
2. **引数の検査に自前の走査を書かない**。すべて宣言で表す: 重複指定 = `Flag.atMost(1)`(**boolean にも必ず付ける** — 素の `Flag.boolean` は重複を沈黙で解決し、打った順で結果が変わる)、空・空白だけの値 = `Flag.withSchema`(Schema)、`maruhi run` の実行対象必須 = `Argument.atLeast(1)` + `Argument.filter`。`args.ts` の走査群(boolean への値の検出・rest の再構築・位置引数の数え直し・候補生成・gunshi のエラー写像)は削除する(関数単位の概算で 525 行 / 911 行)
3. **診断は `CliOutput.Formatter` を実装して `CliOutput.layer` で差し込む**。`renderErrors` は既定のままとし、**描画の呼び出しは上流(`showHelp` → `Console`)に残す** — ランナー側に描画の分岐を書き足す形にすると、上流が経路を増やしたときに素通りする穴ができる。文面に出してよいのは**宣言名・候補・個数・期待する型のみ**。`UnexpectedArgument.arguments` / `InvalidValue.value` に加えて **`InvalidValue.expected`**(上流の `Param.filter` が `onNone(a)` をそのまま入れる)も打たれた値を含みうるので、`expected` は**こちらが書いた文面と一致したときだけ**出す。`formatHelpDoc` は `--help` を明示した実行のみ全文、誤りに添えるときは使い方 1 行
4. **終了コードはエラー型が `Runtime.errorExitCode` で持つ**。ランナーに写像表を置かない。例外は `ShowHelp` だけで、上流が `errors.length ? 1 : 0` を宣言している(= **書き方の誤りが exit 1 になる**)ため、`makeRunMain({ teardown })` に渡す **teardown で 2 へ読み替える**(`CliConfig` には終了コードの設定が無く、上流が用意しているフックはこれだけ)。ハーネス側で手計算すると本番の起動経路を検査できないので、テストも同じ teardown を通す
5. **組み込みグローバルフラグは `CliConfig` で `--help` / `--version` だけに絞る**。既定では `--wizard` / `--completions` / `--log-level` が全コマンドへ生え、**`maruhi pull --wizard` は対話ウィザードが実際に起動する**(実測)。宣言していない対話経路・出力経路を secrets ツールに持たせない。シェル補完が必要になったら明示コマンド(`maruhi completions`)として別途決める
6. **`env` / `server` / `invite` / `member` は真の入れ子サブコマンドにする**。gunshi の 1 段制約のために操作を位置引数にしていた結果必要だった「その操作に適用されないオプション」の拒否機構(`ENV_ACTION_FLAGS` / `optionRestrictedTo` / `actionFlagRejection` / `withoutPositionals`)は廃止する
7. **値表示(`pull --show`)の境界は fail-closed の 2 層にする**。一次境界 = `stdin` と `stdout` の**両方が端末**か(`Stdio.stdinIsTerminal` / `stdoutIsTerminal`)。二次層 = 既知エージェントの環境変数(**std-env を直接依存**・厳密ピン・同期 API)。判定材料はいずれも Effect のサービス経由で取り、`process.*` を直に読まない。

   **適用範囲(2026-08-16 所有者裁定)**: CLI には他に `isAgent` を見るゲートが 9 か所ある。
   **儀式系と鍵素材の表示・入力を一次境界へ移し、残りは deny-list のまま据え置く**:

   | 移す(TTY 一次境界) | 据え置く(deny-list) |
   |---|---|
   | `invite.ts` 招待リンクの生値表示(stdin / stdout / stderr 全て TTY) | |
   | `invite.ts:321` 招待者 FP 確認の儀式 | |
   | `member.ts:302` 受諾鍵 FP 確認の儀式 | `invite.ts:361` エージェント環境での鍵新規生成 |
   | `server-grant.ts:218` サーバー鍵確認の儀式 | `invite.ts:597` 生トークンでの受諾 |
   | `recovery.ts` リカバリーコードの表示・入力(stdin / stdout / stderr 全て TTY) | `recovery.ts` 鍵生成後の既知エージェントでの発行スキップ |

   儀式系は「人間が指紋を目視で照合する」ことが要件そのものなので、TTY 必須は要件の言い換えになる。
   リカバリーコードは master 秘密鍵を開く鍵素材で、stderr も `2>` / CI capture で
   永続化できるため、2026-08-27 deepsec S2 対応で表示・入力を同じ一次境界へ移す。
   コードは stderr に表示するので、ここだけは stdin / stdout に加えて
   **stderr も TTY**であることを要求する。既知エージェント判定は二次層として残す。

   招待リンクの raw token も単回使用・7日expiry・受諾後のFP確認があるとはいえ
   capability であり、stdout redirect / CI capture へ永続化できる。2026-08-27 の
   deepsec 追加 finding 対応で recovery と同じ3チャネルTTY境界へ移す。
   鍵生成後の既知エージェント向け recovery skip は表示自体を行わないため据え置く。
   未知エージェント / CI は TTY 一次境界で失敗し、master key の生成自体が完了したことと
   後から `maruhi key recovery` を実行できることを既存の型付きエラーで案内する。

8. **`maruhi run` は `--` を必須のままとする**。判定は `Stdio.args` を読む Effect(`TerminatorRequired`、exit 2)で行う
9. **stdout はコマンドの出力だけ**。ヘルプ・診断は `Console` を差し替えて stderr へ寄せる。これは規律ではなく**機構**として持つ: コマンド本体の出力は `Stdio` の stdout Sink へ流し、描画は `Console`(stderr)へ、どちらも通さない実 fd への書き込みは安全網で捕まえる — 3 経路が分離しているので、混線をテストで検出できる
10. **移行は段階的に行う**。スパイクの 3 コマンド(`pull` / `run` / `env create`)を src へ昇格させる PR を先頭に、操作フラグ機構を持つコマンド(`env rotate` / `diff`、`server`、`invite`、`member`)、残りの順で進める。全 14 サブコマンドの一括移行は行わない
11. **`maruhi run` の子プロセスへ `MARUHI_*` 環境変数を継承しない**(2026-08-27 deepsec S6)。keychain-less / CI の `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN` は親 CLI がセッションを解決するための入力であり、run の消費対象ではない。これを子へ渡すと、注入した値より長寿命・広スコープな PAT を依存コードが読み、run 終了後も利用できる。親の一般環境と復号済み `extraEnv` は従来どおり渡すが、両方から case-insensitive に `MARUHI_` prefix を除く。**入れ子の maruhi は親の env token を暗黙継承しない**: OS keychain が使える対話環境では keychain から独立に解決できるが、keychain-less / CI で `maruhi run -- make` 内から再び maruhi を呼ぶ構成はサポートしない。必要な maruhi 操作は run の外で行い、run の子には実際の消費値だけを渡す

**Rationale**: (1) gunshi 由来の危険な形が**構造的に**消える — 外側で塞ぎ続ける方式は、レビュー 4 巡ぶんの実績が示すとおり抜けが尽きない。(2) 引数層が Effect の型付きエラー(`Schema.TaggedError`)に統一され、現行 `runCli` の `Execute` ブリッジ・`Effect.runPromise` の往復・defect を usage エラーに化けさせない防御が不要になる。(3) 検査・診断・終了コード・端末判定がすべて Effect の差し替え点に載るため、自前実装が「文面そのもの」だけに縮む。(4) エージェント検出の deny-list は **fail-open** である — 環境変数の標準化は未確定(`AGENT` と `AI_AGENT` が併存、Claude Code / Cursor / Gemini CLI は各社独自、VS Code / Copilot は反対の立場)で、検出ライブラリの範囲も互いに部分集合ではない。「知っているものを止める」から「人間の端末だけ通す」へ反転させれば、**未知のエージェントも既定で止まる**。実測でも Claude Code 実行下は `stdin/stdout/stderr` の `isTTY` がすべて false だった。

**Consequences**: 既存の CLI テストは**引数の書き方を検査するもの(`args.test.ts` と各コマンドの同型ケース)が大半不要になる**。移行 PR では削除ではなく「宣言(`Flag` / `Argument`)で同じ形が落ちること」を確かめる検査へ置き換え、危険な形(重複指定・空の値・`--` の後ろの空文字列・値の表示可否)は必ず残す。ADR-0015 の npm 配布バンドルには `@effect/platform-bun` も畳まれる(利用者の依存グラフへ伝播させない方針は変わらない)。`Bun.secrets` / `Bun.spawn` は引き続き `live.ts` にのみ置く(ADR-0004 の範囲内)。`effect/unstable/cli` は unstable モジュールであり rc → stable で API が動きうる(ADR-0011 の系: 厳密ピン + 更新は独立 PR。beta.107 → rc.109 では 12 形の挙動もプローブのソースも無改修だった)。UX の変更点は 6 つ:

1. **`maruhi pull --show > secrets.txt` が拒否される**(平文をディスクへ落とす操作であり、ディスクレス不変条件からは拒否が正しい)
2. **引数の誤りに添えるヘルプが使い方 1 行になる**
3. **儀式系 3 か所で「stdin は端末だが stdout をパイプする」形が拒否される**(決定 7 の裁定分)。一次境界は stdin と stdout の**両方**が端末であることを要求するため。影響を受けるのは指紋の帯域外照合を CLI に任せる経路だけで、**フラグを渡す CI 経路は影響を受けない**(儀式は指紋フラグが無いときにのみ到達する):

   | コマンド | 影響を受ける形 | 回避 |
   |---|---|---|
   | `maruhi invite accept <link>` | `\| tee audit.log` のように stdout をパイプ | `--inviter-fingerprint <fp>` を渡す |
   | `maruhi member add` | 同上 | `--expect-fingerprint <fp>` を渡す |
   | `maruhi server grant` | 同上 | `--expect-fingerprint <fp>` を渡す |

   指紋を目視照合する儀式で stdout をパイプされると人間が語を読めないため、拒否が正しい。
4. **リカバリーコードの表示・入力は stdin / stdout / stderr の全てが TTY のときだけ通る**。`2>` や CI capture はコードを永続化しうるため拒否する。非 TTY での `key recovery` / `key recover` は exit 1。`key generate` からの自動発行で同じ拒否に当たった場合は、master key の生成自体は完了済みで、後から対話端末で発行できることを案内する
5. **`maruhi run` の子は親の `MARUHI_*` を受け取らない**。keychain-less / CI で入れ子の maruhi が親 PAT を暗黙利用する構成は動かなくなる。一般環境と実際の注入値は従来どおり継承する
6. **`maruhi invite create` は3チャネル全てがTTYでなければ発行しない**。stdoutへのリンク出力をスクリプトで捕捉する運用は廃止し、人間が対話端末から person-to-person channel へ渡す経路だけを許可する

依存は `@effect/platform-bun`(+ `@effect/platform-node-shared`)と `std-env` が増え、`gunshi` が消える。バンドルの実質増分は約 190KB(単体バイナリ 62〜96MB に対して誤差)。退避経路: パーサだけを `@stricli/core`(依存ゼロ・重複指定と boolean への値をパーサ自身が拒否する唯一の候補)へ差し替える — その場合 Effect との結線は現行と同じく自前に戻る。`Bun.isAIAgent()` は Zig の内部実装で公開 JS API ではないため採用しない(Bun 1.4 で JS へ露出したら二次層の実装として再判断する。検出範囲は std-env より狭い)。

---

**追記(2026-08-17 — 第 3 段階の完了と裁定)**: 全コマンドの移行が完了し、gunshi は依存から削除した(決定 1・2 の実施)。移行中に必要になった裁定を記録する:

1. **bare `maruhi audit` = list を維持**。実測により、ハンドラ付き親(`Command.make(name, config, handler)` + `Command.withSubcommands`)は bare 実行でハンドラを実行し、サブコマンド指定時は子だけが走り、不明なサブコマンドは `UnknownSubcommand`(teardown で exit 2)になることを確認した。親は list と同じ宣言を持つので `maruhi audit --limit 5` も従来どおり通る(診断用の COMMAND_SPECS にも親の宣言を流し込む — effect-cli.ts の GROUP_PARENT_CONFIGS)
2. **bare `maruhi`(引数なし)は exit 0 のまま、出力は stdout → stderr へ変更**。bare root はヘルプ要求として扱う(`maruhi --help` と同じ)。gunshi 時代の exit 0 と「使い方 + コマンド一覧」を保ちつつ、出力先は決定 9(stdout はコマンドの出力だけ)に合わせる。bare の**サブコマンド段**(`maruhi env` 単体)は従来どおり書き方の誤り(exit 2)。例外として **`--version` の出力だけは stdout**(`V=$(maruhi --version)` はコマンドの出力であり、gunshi 時代からの契約 — version.test.ts)
3. **hidden フラグ**(login の `--github-base-url` / `--github-poll-interval`)は `Param.makeSingle({ hidden: true })` で構築する。実測: 上流のヘルプ描画・typo 候補の両方が hidden を除外する。maruhi 側の診断一覧(specOf)もラッパ(Map / Variadic / Transform / Optional)を葉まで辿って hidden を除外する
4. **`--` より前にコマンド名が無い実行の専用診断は残す**(`maruhi -- run printenv`)。effect 側の診断は「余分な引数」としか言えず、直し方(コマンド名を前に出す)を伝えられないため。gunshi の `parseArgs` に依存していた走査(旧 args.ts の `commandTokens` / `commandNameAfterTerminator`)は、runCli 内の最小の自前字句(`--` までのトークン分類のみ。決定 2 の禁じる「検査の走査」ではなく振り分けの材料)へ置き換えた
5. **args.ts は全体を削除した**。notes/cli-parser-alternatives.md §6 の帰属表は「12 関数 / 222 行が方針として残る」と概算していたが、スパイク 2〜3 巡目の実測どおり全てが宣言(`Flag.atMost(1)` / `withSchema` / `Argument.atLeast(1)`)と Formatter に置き換わり、残ったのは上記 4 の最小字句(約 30 行、cli.ts)だけだった
6. 決定 6 の拒否機構の残り(audit の `AUDIT_ACTION_FLAGS` / `optionRestrictedTo` / `actionFlagRejection`)も宣言の分離で不要になり削除した
7. **挙動の変更点**: 値の無い / 数として読めない number フラグは gunshi の内部エラー(exit 1)から `InvalidValue`(usage = exit 2)へ。`rotation dismiss --all=false` は「値を読まずに true」から「書いたとおり false」へ(12 形の #2)。先頭の空引数(`maruhi "" pull`)は読み飛ばしから root の `UnknownSubcommand`(exit 2)へ。`maruhi maruhi` はただの未知のコマンドになった。`maruhi audit --limit 5 list` のように **audit のフラグをサブコマンドより前に書いた形は exit 2** になる(上流は親のローカルフラグをサブコマンドへ継承しない)— 診断は置き場所(サブコマンドの後ろ、または bare `maruhi audit`)を案内する。また **`--version` / `--help` はビルトインとして最優先で短絡する**(上流仕様): 同じ argv に混ざった書き方の誤り(`maruhi --version --bogus`)は報告されず exit 0 になる。値を書き込む経路には到達しないため受容する(テストで固定)
8. **`--` の後ろのトークンは位置引数の空きを埋める**(上流実測: パーサが `[...result.arguments, ...afterEndOfOptions]` へ畳む — 決定 8 の実装コメントに記載済みの同じ性質)。`maruhi config set -- defaultEnvironment dev` は exit 0 で通り、`maruhi member remove -- -user-with-dash` のように **`-` で始まる位置引数を書く POSIX の逃げ道**として機能する。黙って捨てられるトークンは無い — 位置引数の空きを超える分は従来どおり余分な位置引数(exit 2)。`run` だけは決定 8 のとおり `--` の後ろを実行コマンド列として特別扱いする(effect-cli.ts の commandAfterTerminator)。この畳み込みは受容し、テストで固定する(Pullfrog レビューの指摘を受けた裁定)
