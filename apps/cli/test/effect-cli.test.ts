// `effect/unstable/cli` へ移した引数層(pull / run / env create / env rotate /
// env diff)の適合検査。
//
// gunshi で実際に踏んだ形(docs/notes/cli-parser-alternatives.md の 12 形)を
// 同じ argv で流し、maruhi の規律が保たれることを固定する: 書き方の誤り =
// exit 2 / 診断は stderr / stdout は汚さない / 打たれた値は診断に出さない /
// 値の表示は人間の対話端末だけ。
//
// スパイク(PR #72 の apps/cli/test/support/)の置き換え。あちらは測定用に
// オペレーションをスタブしていたが、ここは**本番の runCli** を通す。

import { Exit, Runtime } from "effect";
import { CliError as EffectCliError } from "effect/unstable/cli";
import { afterEach, describe, expect, it, vi } from "vitest";

import { describeError } from "../src/cli-formatter.ts";
import { maruhiTeardown } from "../src/cli-teardown.ts";
import { runCli } from "../src/cli.ts";
import { cliError, usageError } from "../src/errors.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { MockServer } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
  vi.restoreAllMocks();
});

/**
 * ログイン済み + 既定のプロジェクト / 環境を持つ環境。サーバーは**何も応答
 * しない**(全リクエスト 404)が、記録は取る — 拒否がコマンド本体より前で
 * 起きたことを「リクエストが 1 件も無い」で確かめるため。
 */
async function startEnv(): Promise<{ env: TestEnv; server: MockServer }> {
  const owner = await makeTestUser("user-owner-1111");
  const server = await MockServer.start([]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: "1111111111111111111111111111111111111111111111111111111111111111",
    defaultEnvironment: "prod",
  });
  return { env, server };
}

/** 診断に平文が混ざっていないことの共通検査(打たれた値を語彙にしない)。 */
function expectNoLeak(env: TestEnv, secrets: readonly string[]): void {
  const output = [...env.logs, ...env.errors].join("\n");
  for (const secret of secrets) {
    expect(output).not.toContain(secret);
  }
}

describe("gunshi で踏んだ形が effect/unstable/cli で落ちる", () => {
  it("1. 未宣言のオプションは実行前に落ちる(gunshi は黙って無視していた)", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    // 候補は**宣言名**から出す(打たれた綴りは返さない)。部分一致だと
    // `----show`(接頭辞の二重付与)を見逃すので完全一致で固定する
    expect(env.errors.join("\n")).toContain("maruhi: Unknown flag (did you mean --show?)");
    expectNoLeak(env, ["--shwo"]);
    expect(server.requests).toHaveLength(0);
  });

  it("2 / 3. boolean への値は書いたとおりに読まれる(gunshi は true に化けた)", async () => {
    // `--show=false` / `--show false` を通信より前に測るため、環境 ID を
    // 壊して落とす(値の表示に進んでいないことは pull-run.test.ts が固定)
    for (const argv of [
      ["pull", "--show=false", "--env", "!bad"],
      ["pull", "--show", "false", "--env", "!bad"],
    ]) {
      const { env, server } = await startEnv();
      // 引数層は通り、環境 ID の形式検査(コマンド本体)で落ちる = `--show` は
      // 値を取るオプションとして読まれている
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Invalid environment ID");
      expect(server.requests).toHaveLength(0);
    }
  });

  it("4. 同じオプションの重複は落ちる(勝つ側を語らずに拒否する)", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--env", "prod", "--env", "dev"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Flag --env was specified more than once");
    expectNoLeak(env, ["prod", "dev"]);
    expect(server.requests).toHaveLength(0);
  });

  it("4b. boolean の重複も落とす(順序に依存させない — ef7cba1 の形)", async () => {
    // `maruhi pull --no-show $FLAGS`($FLAGS に --show)= 全シークレットの表示。
    // 素の Flag.boolean は重複を沈黙で解決し、**打った順で結果が変わる**
    for (const argv of [
      ["pull", "--show", "--no-show"],
      ["pull", "--no-show", "--show"],
      ["pull", "--show", "--show"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Flag --show was specified more than once");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("5. `--` の後ろの空文字列は落ちない(gunshi は rest から落としていた)", async () => {
    // 実行対象は保たれ、通信(pull)まで進む = 引数層は受理している
    const { env, server } = await startEnv();

    expect(await runCli(["run", "--", "printenv", "", "x"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Specify the command to run");
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("6. 先頭の空の位置引数は落ちる(gunshi は読み飛ばして段がずれた)", async () => {
    const { env, server } = await startEnv();

    // gunshi は falsy な位置引数を読み飛ばして 1 段ずれたまま実行していた。
    // 移行先は空のトークンをコマンド名として解決しようとして落ちる
    expect(await runCli(["", "pull"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown subcommand");
    expect(env.logs).toEqual([]);
    expect(server.requests).toHaveLength(0);
  });

  it("7. `--` を跨いでコマンドを解決しない", async () => {
    const { env, server } = await startEnv();

    // gunshi は `--` を跨いで run として解決し、`--` の後ろの先頭
    // (= コマンド名そのもの)を実行対象として渡していた
    expect(await runCli(["--", "run", "printenv"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Write the command name before `--`");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("8. 必須の位置引数の欠落が落ちる", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument environment-id");
    expect(server.requests).toHaveLength(0);
  });

  it("10. 位置引数の名前をオプションとして書いた形は直し方まで案内する", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--environment-id is a positional argument");
    expect(errors).toContain("Write the value as a positional argument instead");
    expectNoLeak(env, ["prod"]);
    expect(server.requests).toHaveLength(0);
  });

  it("段の 2 つ目が `--` の後ろにある形は、解決済みのふりをした診断を出さない", async () => {
    // `maruhi env -- create dev`: 上流の lexer は最初の `--` で切るので
    // `create` はサブコマンドとして解決されない(= `env` 段の余りになる)。
    // 振り分けが `--` を跨いで「env create」と決めると、診断が
    // 「操作は認識されていて位置引数が多い」という**嘘**になる
    const { env, server } = await startEnv();
    expect(await runCli(["env", "--", "create", "dev"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    // 実際の形(`env` 段が取らない引数)を言う
    expect(errors).toContain("maruhi env takes no positional arguments");
    // 「操作は認識されている」という嘘をつかない
    expect(errors).not.toContain("maruhi env create");
    expect(server.requests).toHaveLength(0);
  });

  it("11. オプションへの空 / 空白だけの値は落ちる(既定へ黙って落ちない)", async () => {
    // `maruhi push API_KEY --env "$ENV"` で ENV が未設定のとき、既定環境へ
    // 黙って書き込む事故と同じ形。Schema の宣言 1 つで両方を落とす
    const empty = await startEnv();
    expect(await runCli(["pull", "--env", ""], empty.env.layer)).toBe(2);
    expect(empty.env.errors.join("\n")).toContain("Unacceptable value for flag --env");
    expect(empty.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["pull", "--env", "  "], blank.env.layer)).toBe(2);
    // 許可リスト(SAFE_EXPECTATIONS)が生きていることを**陽性側でも**固定する:
    // 文面を片側だけ直すと括弧が黙って落ちるだけになり、診断が静かに劣化する
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for flag --env (expected: a non-empty value",
    );
    // 打たれた値(空白)は診断に出さない
    expect(blank.env.errors.join("\n")).not.toContain('"  "');
  });

  it("12. 余分な位置引数は個数だけを言い、中身は出さない", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "SUPER_SECRET_VALUE"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("contents not shown");
    expect(errors).toContain("maruhi pull takes no positional arguments");
    expectNoLeak(env, ["SUPER_SECRET_VALUE"]);
    expect(server.requests).toHaveLength(0);
  });
});

describe("maruhi 固有の規律", () => {
  it("宣言していない組み込みフラグは生やさない(--wizard / --completions / --log-level)", async () => {
    // effect/unstable/cli の既定は help / version / wizard / completions /
    // log-level を全コマンドへ足す。`maruhi pull --wizard` は**対話ウィザードが
    // 起動する**(実測)。宣言していない対話経路・出力経路を secrets ツールに
    // 持たせないため CliConfig で help / version だけに絞る
    for (const argv of [
      ["pull", "--wizard"],
      ["pull", "--completions", "bash"],
      ["pull", "--log-level", "all"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("ヘルプ・診断は stdout を汚さない(コマンドの出力とは別経路)", async () => {
    const { env } = await startEnv();
    // Console / CliIo を迂回して実 stdout へ書くコードがあれば捕まえる
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // `--help` は誤りではない(exit 0)。本文が stdout へ出ないことが要点 —
    // `V=$(maruhi config get server)` がバナーを捕まえた事故と同じ形を塞ぐ
    expect(await runCli(["pull", "--help"], env.layer)).toBe(0);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("maruhi pull");
    expect(stdout).not.toHaveBeenCalled();

    const rejected = await startEnv();
    expect(await runCli(["pull", "--shwo"], rejected.env.layer)).toBe(2);
    expect(rejected.env.logs).toEqual([]);
    expect(rejected.env.errors.length).toBeGreaterThan(0);
    expect(stdout).not.toHaveBeenCalled();
  });

  it("**迂回された書き込み**の安全網(Console も CliIo も通さない実 fd 書き込み)", async () => {
    // `console.log` の spy だけでは、`Console` を経由せず実 fd へ書く経路
    // (上流が描画メソッドを増やす・Stdio の Sink が実 stdout を掴む)を
    // 捕まえられない。collectingConsole は Console の**全メソッド**を潰す
    // 設計だが、塞げていることを確かめる側の網もここに要る
    const bypassed: string[] = [];
    // 束縛ラッパー(`bind`)ではなく**元のメソッドそのもの**を控える: bind した
    // ものを戻すと呼ぶたびに 1 段ずつ積まれ、プロトタイプ上の write を隠す
    const realWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      bypassed.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      // 診断(exit 2)・ヘルプ(exit 0)・実行の失敗(exit 1 — このハーネスの
      // サーバーは何も応答しない)の 3 経路すべてで実 fd を触らない
      const rejected = await startEnv();
      expect(await runCli(["pull", "--shwo"], rejected.env.layer)).toBe(2);
      const help = await startEnv();
      expect(await runCli(["pull", "--help"], help.env.layer)).toBe(0);
      const failed = await startEnv();
      expect(await runCli(["pull"], failed.env.layer)).toBe(1);
    } finally {
      process.stdout.write = realWrite;
    }
    // この窓には vitest のレポータ出力も混ざる(await を挟むため)。**maruhi の
    // 語が実 fd に現れないこと**で判定する — 検査したい性質はそちらで、
    // 「誰も書かないこと」ではない
    const written = bypassed.join("");
    for (const marker of ["Usage: maruhi", "Unknown flag", "FLAGS", "maruhi:"]) {
      expect(written, marker).not.toContain(marker);
    }
  });

  it("誤りに添えるヘルプは使い方 1 行だけ(--help は全文)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    const brief = env.errors.join("\n");
    expect(brief).toContain("Usage: maruhi pull");
    // 全文にだけ現れる節(FLAGS 等)は誤りの診断に混ぜない
    expect(brief).not.toContain("FLAGS");

    const help = await startEnv();
    expect(await runCli(["pull", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("FLAGS");
    // 宣言の説明文はヘルプに出る(gunshi 側の各コマンドと同じ水準を保つ —
    // 昇格時に説明を落とすと、ヘルプが名前と型だけの一覧に痩せる)
    expect(full).toContain("Server URL (defaults to config server)");
    expect(full).toContain("Print values to the terminal");
  });

  it("`--` の後ろの `-h` は子プロセスの引数(ヘルプ要求として読まない)", async () => {
    // 全 argv を見ると、maruhi の書き方の誤りに**子プロセス向けのフラグ**が
    // 混ざっただけで全文ヘルプが出てしまい、肝心の診断が埋もれる
    const { env } = await startEnv();
    expect(await runCli(["run", "stray", "--", "printenv", "-h"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).not.toContain("FLAGS");
  });

  it("内部エラー(defect)は message を出さず、型の名前だけを添える", async () => {
    // 上流・未知の Error の message は打たれた値を埋め込んだ文面でも到達しうる
    // (`Invalid value: <平文>`)。制御文字の中和だけでは規律を守れないので、
    // 素通しにしない。無言でも飲まない(型の名前は argv から作れない語彙)
    const { env } = await startEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi: internal error (Error)");
    expect(errors).not.toContain("config load defect");
  });

  it("`maruhi run` は `--` の後ろからしか実行対象を取らない", async () => {
    const missing = await startEnv();
    expect(await runCli(["run"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(missing.server.requests).toHaveLength(0);

    // `--` はあるが実行対象が空(`maruhi run -- "$CMD"` の未設定形)
    const empty = await startEnv();
    expect(await runCli(["run", "--", ""], empty.env.layer)).toBe(2);
    expect(empty.env.runnerCalls).toHaveLength(0);
    expect(empty.server.requests).toHaveLength(0);

    // `--` の後ろの先頭が空でも、余分な位置引数という**書いてある誤り**を
    // 先に報告する(汎用の「実行対象が無い」で上書きしない)
    const strayWithEmpty = await startEnv();
    expect(await runCli(["run", "stray", "--", "", "printenv"], strayWithEmpty.env.layer)).toBe(2);
    const strayErrors = strayWithEmpty.env.errors.join("\n");
    expect(strayErrors).toContain("Unexpected extra arguments (1;");
    expect(strayErrors).not.toContain("Specify the command to run after `--`");
    expect(strayWithEmpty.env.runnerCalls).toHaveLength(0);
    expect(strayWithEmpty.server.requests).toHaveLength(0);

    // `--` の書き忘れ。個数はパーサが解決した配列から出す(宣言の写しを
    // 持たない)ので、フラグの値は数に入らず、位置が前後しても同じ数になる
    for (const argv of [
      ["run", "npm", "test"],
      ["run", "--env", "prod", "npm", "test"],
      ["run", "npm", "test", "--env", "prod"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unexpected extra arguments (2;");
      expect(env.errors.join("\n")).toContain("Write the command to run after `--`");
      expectNoLeak(env, ["npm", "test", "prod"]);
      expect(env.runnerCalls, argv.join(" ")).toHaveLength(0);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });
});

describe("診断の写像(構造化フィールドからの組み直し)", () => {
  it("InvalidValue は打たれた値を出さない", () => {
    // effect/unstable/cli の既定の文面は value を含む(`Invalid value ...`)。
    // maruhi は宣言名と期待する型だけを出す
    const message = describeError(
      new EffectCliError.InvalidValue({
        option: "limit",
        value: "SUPER_SECRET_VALUE",
        expected: "integer",
        kind: "flag",
      }),
      "pull",
      { pull: { flags: ["limit"], positionals: [] } },
    );
    expect(message).toContain("Unacceptable value for flag --limit");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("**expected** に埋め込まれた値も出さない(filter の onNone 経由の漏れ)", () => {
    // 上流の Param.filter は `expected: onNone(a)` を組み立てるので、
    // `(n) => \`Expected even number, got ${n}\`` のような onNone を書くと
    // 期待値の側から平文が漏れる。こちらが書いた文面と一致しない expected は出さない
    const message = describeError(
      new EffectCliError.InvalidValue({
        option: "env",
        value: "SUPER_SECRET_VALUE",
        expected: "Expected even number, got SUPER_SECRET_VALUE",
        kind: "flag",
      }),
      "pull",
      { pull: { flags: ["env"], positionals: [] } },
    );
    expect(message).toBe("Unacceptable value for flag --env");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("UnexpectedArgument は個数だけを出す", () => {
    const message = describeError(
      new EffectCliError.UnexpectedArgument({ arguments: ["SECRET_A", "SECRET_B"] }),
      "pull",
      { pull: { flags: [], positionals: [] } },
    );
    expect(message).toContain("(2;");
    expect(message).not.toContain("SECRET_A");
    expect(message).not.toContain("SECRET_B");
  });
});

describe("終了コードは Effect の機構に載る", () => {
  it("エラー型が Runtime.errorExitCode を持つ(ランナーに写像表を書かない)", () => {
    // Runtime.defaultTeardown = BunRuntime.runMain が使う既定の teardown
    const failure: number[] = [];
    Runtime.defaultTeardown(Exit.fail(cliError("実行に失敗しました")), (code) =>
      failure.push(code),
    );
    expect(failure).toEqual([1]);

    const usage: number[] = [];
    Runtime.defaultTeardown(Exit.fail(usageError("書き方が違います")), (code) => usage.push(code));
    expect(usage).toEqual([2]);
  });

  it("ShowHelp は上流が exit 1 を宣言するので teardown で 2 へ読み替える", () => {
    // 上流: ShowHelp[Runtime.errorExitCode] = errors.length ? 1 : 0。
    // 既定の teardown のままだと**書き方の誤りが exit 1** になり、
    // maruhi の 0/1/2 契約が崩れる
    const withErrors = Exit.fail(
      new EffectCliError.ShowHelp({
        commandPath: ["maruhi", "pull"],
        errors: [new EffectCliError.UnrecognizedOption({ option: "--shwo", suggestions: [] })],
      }),
    );
    const defaultCodes: number[] = [];
    Runtime.defaultTeardown(withErrors, (code) => defaultCodes.push(code));
    expect(defaultCodes).toEqual([1]);

    const codes: number[] = [];
    maruhiTeardown(false)(withErrors, (code) => codes.push(code));
    expect(codes).toEqual([2]);

    // `--help` / `--version` を明示した実行(errors 空)は誤りではない
    const helpCodes: number[] = [];
    maruhiTeardown(true)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi"], errors: [] })),
      (code) => helpCodes.push(code),
    );
    expect(helpCodes).toEqual([0]);

    // errors 空でもヘルプ・バージョンを明示していない実行 = サブコマンド必須の
    // 親コマンド単体(`maruhi env`)。gunshi 時代と同じく書き方の誤り(2)
    const bareCodes: number[] = [];
    maruhiTeardown(false)(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi", "env"], errors: [] })),
      (code) => bareCodes.push(code),
    );
    expect(bareCodes).toEqual([2]);
  });
});

describe("env の入れ子サブコマンド(ADR-0016 決定 6 — 第 2 段階)", () => {
  it("その操作に無いフラグは usage エラー(2)で落ちる(拒否機構の置き換え)", async () => {
    // gunshi 時代の ENV_ACTION_FLAGS / optionRestrictedTo が受け持っていた形。
    // 宣言が操作ごとに分かれたので、未宣言フラグとして構造的に落ちる
    for (const argv of [
      ["env", "rotate", "dev", "--name", "x"],
      ["env", "diff", "dev", "prod", "--reason", "x"],
      ["env", "diff", "dev", "prod", "--new-epoch"],
      ["env", "diff", "dev", "prod", "--no-new-epoch"],
      ["env", "create", "dev", "--reason", "x"],
    ]) {
      const { env, server } = await startEnv();
      // 実行の失敗(1)と混ざるとスクリプトが打ち間違いを実行失敗として扱う
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("不明な操作は取りうる操作の一覧か候補を出す(打たれた語は出さない)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["env", "bogus", "dev"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: create | rotate | diff)",
    );
    expectNoLeak(bogus.env, ["bogus"]);
    expect(bogus.server.requests).toHaveLength(0);

    const typo = await startEnv();
    expect(await runCli(["env", "rotat", "dev"], typo.env.layer)).toBe(2);
    expect(typo.env.errors.join("\n")).toContain("Unknown subcommand (did you mean rotate?)");
    expect(typo.server.requests).toHaveLength(0);
  });

  it("rotate の重複指定は落ちる(値・boolean とも。順序に依存させない)", async () => {
    for (const argv of [
      ["env", "rotate", "dev", "--reason", "reason-alpha", "--reason", "reason-beta"],
      ["env", "rotate", "dev", "--new-epoch", "--no-new-epoch"],
      ["env", "rotate", "dev", "--no-new-epoch", "--new-epoch"],
      ["env", "rotate", "dev", "--new-epoch", "--new-epoch"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("was specified more than once");
      expectNoLeak(env, ["reason-alpha", "reason-beta"]);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("rotate: 空 / 空白だけの --reason は既定へ潰さず落とす(打たれた値は出さない)", async () => {
    // `--reason "$REASON"` の未設定形。gunshi 時代は args.ts の走査、いまは宣言
    // (NonBlank)が受け持つ — 空の理由がチェーンへ記録される形を塞ぐ
    for (const reason of ["", "  "]) {
      const { env, server } = await startEnv();
      expect(await runCli(["env", "rotate", "dev", "--reason", reason], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain(
        "Unacceptable value for flag --reason (expected: a non-empty value",
      );
      expect(server.requests).toHaveLength(0);
    }
  });

  it("rotate: boolean フラグの後ろに置いた位置引数は消費されない(順序の固定)", async () => {
    // 上流は boolean の直後のトークンを **真偽値リテラルのときだけ**値として
    // 消費する(asBooleanLiteral)。通常の環境 ID はストリームに残るので、
    // フラグを先に書いた形も引数層を通る(Pullfrog 指摘のテスト固定)
    const ordered = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "dev", "--reason", "x"], ordered.env.layer),
    ).toBe(1);
    expect(ordered.env.errors.join("\n")).not.toContain("Missing positional argument");
    expect(ordered.server.requests.length).toBeGreaterThan(0);

    // 残余: 環境 ID が真偽値リテラルと同形(`on` / `off` 等)だと boolean の
    // 値として消費され、必須位置引数の欠落として**大きな音で**落ちる
    // (gunshi は消費しなかった形。黙って別環境を回すのではなく exit 2)
    const literal = await startEnv();
    expect(
      await runCli(["env", "rotate", "--new-epoch", "on", "--reason", "x"], literal.env.layer),
    ).toBe(2);
    expect(literal.env.errors.join("\n")).toContain("Missing positional argument environment-id");
    expect(literal.server.requests).toHaveLength(0);
  });

  it("rotate: boolean への値は書いたとおりに読まれる(gunshi は読まずに true にした)", async () => {
    // `--new-epoch=false` は effect では **false として解釈される**(12 形の #2)。
    // 引数層は通り、コマンド本体(通信)まで進む = 拒否ではなく正しい解釈
    const { env, server } = await startEnv();
    expect(await runCli(["env", "rotate", "dev", "--new-epoch=false"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Unknown flag");
    expect(server.requests.length).toBeGreaterThan(0);

    // 否定形(`--no-new-epoch`)も宣言済みの綴り(案内先が実在する)
    const negated = await startEnv();
    expect(await runCli(["env", "rotate", "dev", "--no-new-epoch"], negated.env.layer)).toBe(1);
    expect(negated.env.errors.join("\n")).not.toContain("Unknown flag");
    expect(negated.server.requests.length).toBeGreaterThan(0);
  });

  it("rotate: 位置引数の名前をオプションとして書いた形は直し方まで案内する", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["env", "rotate", "--environment-id", "prod"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--environment-id is a positional argument");
    expectNoLeak(env, ["prod"]);
    expect(server.requests).toHaveLength(0);
  });

  it("環境 ID の形式検査は指定値を出さずに落とす(create / rotate 共通)", async () => {
    for (const argv of [
      ["env", "create", "sk-live-topsecret!"],
      ["env", "rotate", "sk-live-topsecret!"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors).toContain("Invalid environment ID");
      expect(errors).not.toContain("topsecret");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("diff: 2 つ目の環境 ID は必須(gunshi の optional 位置引数 + 本体検査の置き換え)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["env", "diff", "dev"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument other-environment-id");
    expect(server.requests).toHaveLength(0);
  });

  it("diff: 空の位置引数・同一環境の比較は落ちる", async () => {
    const blank = await startEnv();
    expect(await runCli(["env", "diff", "dev", ""], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument other-environment-id",
    );
    expect(blank.server.requests).toHaveLength(0);

    const same = await startEnv();
    expect(await runCli(["env", "diff", "dev", "dev"], same.env.layer)).toBe(2);
    expect(same.env.errors.join("\n")).toContain("The same environment ID was written twice");
    expect(same.server.requests).toHaveLength(0);
  });

  it("先頭の空引数は不明なコマンドとして落ち、無関係なフラグの指摘を重ねない", async () => {
    // 先頭の "" はコマンド名として解決できない(root の UnknownSubcommand)。
    // このときフラグは root の宣言と突き合わされているので、後続のフラグを
    // 不明扱いで並べない(formatErrors の畳み込み — 第 3 段階 ④ で、gunshi の
    // 読み飛ばしに合わせていた旧挙動から「空のトークンも 1 つの引数」へ揃えた)
    const { env } = await startEnv();
    expect(await runCli(["", "env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(
      2,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("Unknown flag");
    expectNoLeak(env, ["prod"]);
  });

  it("`maruhi env` 単体は usage エラー(2)で、env 段の使い方を stderr へ出す", async () => {
    // 上流は「サブコマンド未指定」を errors 空の ShowHelp(exit 0)にするが、
    // maruhi では書き方の誤り(gunshi 時代の「不明な操作です」も exit 2)。
    // teardown が「ヘルプ・バージョンの明示なし」で読み分ける(cli-teardown.ts)。
    // stdout は汚さない(コマンドの出力だけ — 決定 9)
    const { env, server } = await startEnv();
    expect(await runCli(["env"], env.layer)).toBe(2);
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("maruhi env");
    expect(server.requests).toHaveLength(0);

    // `--help` の明示は誤りではない(exit 0 のまま)
    const help = await startEnv();
    expect(await runCli(["env", "--help"], help.env.layer)).toBe(0);
    expect(help.env.errors.join("\n")).toContain("maruhi env");
    expect(help.server.requests).toHaveLength(0);
  });

  it("親の段に書いたフラグは、置き場所(サブコマンドの後ろ)を案内して落ちる", async () => {
    // gunshi は操作名より前のフラグも通した(1 つの引数表)。effect の入れ子
    // では親の段のフラグは未宣言になる — 「フラグが存在しない」と嘘をつかず、
    // 直し方を言う
    const { env, server } = await startEnv();
    expect(
      await runCli(["server", "--project", "abc", "grant", "--environments", "dev"], env.layer),
    ).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("write the subcommand first and its flags after it");
    expect(errors).toContain("maruhi server grant");
    expect(server.requests).toHaveLength(0);
  });

  it("振り分けが葉まで解決した実行でも、親の段のフラグには置き場所を案内する", async () => {
    // `--new-epoch rotate` / `--project=abc grant` はサブコマンド名が argv に
    // 残るため、診断の宛先(commandKey)は葉へ解決する。宣言の選択を
    // commandKey で行うと、拒否したフラグを「このコマンドが受け付ける一覧」に
    // 載せる自己矛盾の診断になる — 上流が報告する段(UnrecognizedOption.command)
    // で選ぶことを固定する(Bugbot 指摘)
    const envRotate = await startEnv();
    expect(await runCli(["env", "--new-epoch", "rotate", "dev"], envRotate.env.layer)).toBe(2);
    const rotateErrors = envRotate.env.errors.join("\n");
    expect(rotateErrors).toContain("write the subcommand first and its flags after it");
    expect(rotateErrors).not.toContain("flags this command accepts");
    expect(envRotate.server.requests).toHaveLength(0);

    const grant = await startEnv();
    expect(
      await runCli(["server", "--project=abc", "grant", "--environments", "dev"], grant.env.layer),
    ).toBe(2);
    const grantErrors = grant.env.errors.join("\n");
    expect(grantErrors).toContain("write the subcommand first and its flags after it");
    expect(grantErrors).not.toContain("flags this command accepts");
    expect(grant.server.requests).toHaveLength(0);
  });
});

describe("server の入れ子サブコマンド(ADR-0016 決定 6 — 第 2 段階 ②)", () => {
  it("その操作に無いフラグは usage エラー(2)で落ちる(拒否機構の置き換え)", async () => {
    // gunshi 時代の SERVER_ACTION_FLAGS / serverActionFlagRejection の置き換え
    for (const argv of [
      ["server", "revoke", "--environments", "dev"],
      ["server", "revoke", "--lease-policy", "policy.json"],
      ["server", "revoke", "--expect-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      [
        "server",
        "grant",
        "--environments",
        "dev",
        "--fingerprint",
        "aaaabbbbccccddddeeeeffff00001111",
      ],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("不明な操作は取りうる操作の一覧を出す", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["server", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown subcommand (expected one of: grant | revoke)");
    expect(server.requests).toHaveLength(0);
  });

  it("重複指定・空 / 空白だけの値は落ちる(宣言による拒否)", async () => {
    for (const argv of [
      ["server", "grant", "--environments", "dev", "--environments", "prod"],
      ["server", "revoke", "--fingerprint", "aaaa", "--fingerprint", "bbbb"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("was specified more than once");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
    for (const value of ["", "  "]) {
      const { env, server } = await startEnv();
      expect(await runCli(["server", "grant", "--environments", value], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain(
        "Unacceptable value for flag --environments (expected: a non-empty value",
      );
      expect(server.requests).toHaveLength(0);
    }
  });

  it("grant は --environments 必須・FP フラグは形式検査で落ちる(値は出さない)", async () => {
    const missing = await startEnv();
    expect(await runCli(["server", "grant"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("grant requires --environments");
    expect(missing.server.requests).toHaveLength(0);

    // FP の形式検査は宣言(NonBlank)を通った後の共用パーサ(fingerprint-flag.ts)。
    // 打たれた値そのものは診断に出さない
    const badFp = await startEnv();
    expect(
      await runCli(
        ["server", "grant", "--environments", "dev", "--expect-fingerprint", "sk-live-hunter2"],
        badFp.env.layer,
      ),
    ).toBe(2);
    const errors = badFp.env.errors.join("\n");
    expect(errors).toContain("--expect-fingerprint is malformed");
    expectNoLeak(badFp.env, ["sk-live-hunter2"]);
    expect(badFp.server.requests).toHaveLength(0);

    const badRevoke = await startEnv();
    expect(
      await runCli(["server", "revoke", "--fingerprint", "sk-live-hunter2"], badRevoke.env.layer),
    ).toBe(2);
    expect(badRevoke.env.errors.join("\n")).toContain("--fingerprint is malformed");
    expectNoLeak(badRevoke.env, ["sk-live-hunter2"]);
    expect(badRevoke.server.requests).toHaveLength(0);
  });

  it("--environments の形式検査は通信より前に落ちる", async () => {
    for (const value of ["dev,,prod", "dev,!bad"]) {
      const { env, server } = await startEnv();
      expect(await runCli(["server", "grant", "--environments", value], env.layer), value).toBe(2);
      expect(server.requests, value).toHaveLength(0);
    }
  });

  it("server は位置引数を取らない(操作を位置引数で書いた旧形は落ちる)", async () => {
    const { env, server } = await startEnv();
    // 旧 gunshi 形の名残(`server grant extra`)= grant 段の余分な位置引数
    expect(await runCli(["server", "grant", "extra", "--environments", "dev"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi server grant takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });
});

describe("invite の入れ子サブコマンド(ADR-0016 決定 6 — 第 2 段階 ③)", () => {
  it("その操作に無いフラグは usage エラー(2)で落ちる(拒否機構の置き換え)", async () => {
    for (const argv of [
      ["invite", "list", "--role", "member"],
      ["invite", "create", "--inviter-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      ["invite", "revoke", "inv-1", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("不明な操作は取りうる操作の一覧を出す", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["invite", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: create | accept | list | revoke)",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("create は --role 必須・重複指定は落ちる", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "create"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify --role");
    expect(missing.server.requests).toHaveLength(0);

    const dup = await startEnv();
    expect(
      await runCli(["invite", "create", "--role", "member", "--role", "admin"], dup.env.layer),
    ).toBe(2);
    expect(dup.env.errors.join("\n")).toContain("Flag --role was specified more than once");
    expect(dup.server.requests).toHaveLength(0);
  });

  it("accept の対象は必須で、解釈できない入力は中身を出さずに落ちる", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "accept"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument target");
    expect(missing.server.requests).toHaveLength(0);

    // リンクでもトークンでもない入力(平文の値でありうる)は診断に出さない。
    // 対象は Argument.redacted で受けている(トークン生値を内包しうるため)
    const garbage = await startEnv();
    const typed = "sk-live-hunter2-plaintext";
    expect(await runCli(["invite", "accept", typed], garbage.env.layer)).toBe(2);
    const errors = garbage.env.errors.join("\n");
    expect(errors).toContain("Specify an invite link");
    expectNoLeak(garbage.env, [typed]);
    expect(garbage.server.requests).toHaveLength(0);
  });

  it("生トークンの受諾は --project 必須(既定プロジェクトへ黙って署名しない)", async () => {
    const { env, server } = await startEnv();
    const token = "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01";
    expect(await runCli(["invite", "accept", token], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Accepting with a raw token requires --project");
    // トークン生値は診断に出さない
    expectNoLeak(env, [token]);
    expect(server.requests).toHaveLength(0);
  });

  it("revoke の招待 id は必須・空を受け付けない", async () => {
    const missing = await startEnv();
    expect(await runCli(["invite", "revoke"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument invite-id");
    expect(missing.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["invite", "revoke", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument invite-id",
    );
    expect(blank.server.requests).toHaveLength(0);
  });
});

describe("member の入れ子サブコマンド(ADR-0016 決定 6 — 第 2 段階 ④)", () => {
  it("その操作に無いフラグは usage エラー(2)で落ちる(拒否機構の置き換え)", async () => {
    for (const argv of [
      ["member", "remove", "user-1", "--role", "member"],
      ["member", "remove", "user-1", "--expect-fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
      [
        "member",
        "change-role",
        "user-1",
        "--expect-fingerprint",
        "aaaabbbbccccddddeeeeffff00001111",
      ],
      ["member", "add", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("不明な操作は取りうる操作の一覧を出す", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["member", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: add | remove | change-role)",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("remove / change-role の対象 user_id は必須・空を受け付けない", async () => {
    for (const argv of [
      ["member", "remove"],
      ["member", "change-role", "--role", "member"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain(
        "Missing positional argument user-id",
      );
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
    const blank = await startEnv();
    expect(await runCli(["member", "remove", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument user-id",
    );
    expect(blank.server.requests).toHaveLength(0);
  });

  it("change-role は --role 必須・重複指定と FP の形式は宣言と共用パーサで落ちる", async () => {
    const missing = await startEnv();
    expect(await runCli(["member", "change-role", "user-1"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Specify --role");
    expect(missing.server.requests).toHaveLength(0);

    const dup = await startEnv();
    expect(
      await runCli(
        ["member", "change-role", "user-1", "--role", "admin", "--role", "reader"],
        dup.env.layer,
      ),
    ).toBe(2);
    expect(dup.env.errors.join("\n")).toContain("Flag --role was specified more than once");
    expect(dup.server.requests).toHaveLength(0);

    // FP の形式検査は共用パーサ(fingerprint-flag.ts)。打たれた値は出さない
    const badFp = await startEnv();
    expect(
      await runCli(["member", "add", "--expect-fingerprint", "sk-live-hunter2"], badFp.env.layer),
    ).toBe(2);
    expect(badFp.env.errors.join("\n")).toContain("--expect-fingerprint is malformed");
    expectNoLeak(badFp.env, ["sk-live-hunter2"]);
    expect(badFp.server.requests).toHaveLength(0);
  });

  it("add の招待 id は省略可・2 つ以上は余分な引数として落ちる", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["member", "add", "inv-1", "inv-2"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(server.requests).toHaveLength(0);
  });
});

describe("key / project の入れ子サブコマンド(ADR-0016 第 3 段階 ②)", () => {
  it("不明な操作は取りうる操作の一覧を出し、ログインやサーバー接続より前に落ちる", async () => {
    // セッション解決の後ろに置くと、`key bogus` が「Not logged in」で
    // 落ちて打ち間違いが伝わらない(しかも exit 1)。effect ではサブコマンド
    // 解決がハンドラより前 = 構造的にセッションへ到達しない
    const key = await makeTestEnv();
    expect(await runCli(["key", "bogus"], key.layer)).toBe(2);
    expect(key.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: generate | show | recover | recovery)",
    );
    expect(key.errors.join("\n")).not.toContain("Not logged in");

    const project = await makeTestEnv();
    expect(await runCli(["project", "bogus"], project.layer)).toBe(2);
    expect(project.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: init | list | verify | anchor | checkpoint)",
    );
  });

  it("操作名は打たれた語を返さない(制御文字も値も端末へ流さない)", async () => {
    // 行を消して偽の成功行を書くような ANSI 列を含む語。文面は取りうる操作の
    // 一覧だけで、打たれた語は出さない(位置引数には値が書かれうる)
    const evil = "[2K\rmaruhi: OK";
    for (const command of ["key", "project"]) {
      const { env } = await startEnv();
      expect(await runCli([command, evil], env.layer), command).toBe(2);
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output, command).toContain("Unknown subcommand");
      expect(output, command).not.toContain("");
      expect(output, command).not.toContain("\r");
    }
  });

  it("葉は位置引数を取らない(`key generate extra` は余分な引数として落ちる)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["key", "generate", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi key generate takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });

  it("bare `maruhi key` / `maruhi project` は usage エラー(2)", async () => {
    for (const command of ["key", "project"]) {
      const { env, server } = await startEnv();
      expect(await runCli([command], env.layer), command).toBe(2);
      expect(env.logs, command).toEqual([]);
      expect(env.errors.join("\n"), command).toContain(`maruhi ${command}`);
      expect(server.requests, command).toHaveLength(0);
    }
  });
});

describe("未知のコマンドの診断(第 3 段階 ④ — root の UnknownSubcommand)", () => {
  it("コマンド名の綴り間違いでは、正しく綴られたオプションを不明扱いしない", async () => {
    // 未解決のコマンドではフラグが root の宣言と突き合わされるため、綴りの
    // 合っている --show まで不明として並ぶ(探させない — formatErrors が
    // UnknownSubcommand と同時の UnrecognizedOption を畳む)
    const { env } = await startEnv();
    expect(await runCli(["pul", "--show"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand (did you mean pull?)");
    expect(errors).not.toContain("Unknown flag");
  });

  it("未知のコマンドは取りうるコマンドの一覧を出す", async () => {
    const { env } = await startEnv();
    expect(await runCli(["bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: login | logout | pull | run | push | env | server | invite | member | key | project | ci | rotation | audit | config | schema | var)",
    );
  });

  it("コマンド名の位置に値を書いた形も綴りを出さない", async () => {
    const { env } = await startEnv();
    expect(await runCli(["s3cr3t/value=with-symbols"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("s3cr3t");
  });

  it("コマンド名より前に書いたフラグは、自己矛盾せず置き場所を案内する", async () => {
    // `maruhi --show pull`(gunshi が通していた形)。振り分けの葉(pull)の
    // 宣言で診断を組むと「--show を拒否しつつ受け付ける一覧に --show を載せる」
    // 自己矛盾になる — root の宣言(置き場所の案内)で組む(レビュー指摘)
    const { env, server } = await startEnv();
    expect(await runCli(["--show", "pull"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("write the subcommand first and its flags after it");
    expect(errors).not.toContain("flags this command accepts");
    expect(server.requests).toHaveLength(0);
  });

  it("`--version` の出力は stdout、`--help` 併記時はヘルプが勝ち stderr へ出る", async () => {
    // `V=$(maruhi --version)` はコマンドの出力(gunshi 時代からの契約)。
    // `--help --version` は上流で Help が勝つ = 集めた行はヘルプ本文なので
    // stdout へ流さない(決定 9 / ADR-0016 追記 2)
    const version = await startEnv();
    expect(await runCli(["--version"], version.env.layer)).toBe(0);
    expect(version.env.logs.join("\n")).toMatch(/^\d+\.\d+\.\d+/);
    expect(version.env.errors).toEqual([]);

    const both = await startEnv();
    expect(await runCli(["--help", "--version"], both.env.layer)).toBe(0);
    expect(both.env.logs).toEqual([]);
    expect(both.env.errors.join("\n")).toContain("maruhi");

    // ビルトインは最優先で短絡する(上流仕様)= 同じ argv の書き方の誤りは
    // 報告されない。値を書き込む経路には到達しないため受容し、挙動として固定
    // する(ADR-0016 追記 7)
    const swallowed = await startEnv();
    expect(await runCli(["--version", "--bogus"], swallowed.env.layer)).toBe(0);
    expect(swallowed.env.logs.join("\n")).toMatch(/^\d+\.\d+\.\d+/);
    expect(swallowed.server.requests).toHaveLength(0);
  });

  it("エントリコマンドの二重名(`maruhi maruhi`)をコマンドとして勧めない", async () => {
    // gunshi はエントリコマンドを自分自身の名前でも登録していた。effect の
    // root に `maruhi` サブコマンドは無い = ただの未知のコマンド
    const { env } = await startEnv();
    expect(await runCli(["maruhi", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unknown subcommand");
    expect(errors).not.toContain("maruhi maruhi");
  });
});

describe("login / logout の移行(ADR-0016 第 3 段階 ④)", () => {
  it("型の合わない値は、与えられた値を出さずに拒否する", async () => {
    // 期待する型は宣言由来なので出してよいが、与えられた値は平文が混ざりうる
    // ので出さない
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--poll-interval", "s3cr3t"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Unacceptable value for flag --poll-interval");
    expectNoLeak(env, ["s3cr3t"]);
    expect(server.requests).toHaveLength(0);
  });

  it("値の無い number は usage エラー(2)になる(gunshi は内部エラー = 1 だった)", async () => {
    // gunshi では値の無い number オプションで gunshi 自身が TypeError を投げ、
    // 内部エラー(exit 1)として報告していた(args.test.ts の旧ケース)。
    // effect では InvalidValue = 書き方の誤り(exit 2)— 移行後の正へ更新
    const { env, server } = await startEnv();
    expect(await runCli(["login", "--token-ttl-days"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --token-ttl-days");
    expect(server.requests).toHaveLength(0);
  });

  it("長いオプション名の打ち間違いも候補として案内する", async () => {
    const { env } = await startEnv();
    expect(await runCli(["login", "--token-namee", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag (did you mean --token-name?)");
  });

  it("隠しオプション(hidden)はヘルプにも候補にも出さない", async () => {
    // 内部向けの綴り(--poll-interval)を広めない。上流の typo 候補は hidden を
    // 除外し(実測)、こちらの一覧(specOf)も hidden を除外する
    const typo = await startEnv();
    expect(await runCli(["login", "--poll-intervall", "3"], typo.env.layer)).toBe(2);
    const errors = typo.env.errors.join("\n");
    expect(errors).not.toContain("--poll-interval");
    expect(errors).toContain("Unknown flag");

    const help = await startEnv();
    expect(await runCli(["login", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("--token-name");
    expect(full).not.toContain("--poll-interval");
  });

  it("logout は位置引数を取らない", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["logout", "extra"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("maruhi logout takes no positional arguments");
    expect(server.requests).toHaveLength(0);
  });
});

describe("rotation / audit の入れ子サブコマンド(ADR-0016 第 3 段階 ③)", () => {
  it("bare `maruhi audit` は list として実行される(現行仕様の維持)", async () => {
    // ハンドラ付き親(実測済み): bare 親は list を実行し、コマンド本体
    // (通信)まで進む = usage エラー(2)にならない
    const { env, server } = await startEnv();
    expect(await runCli(["audit"], env.layer)).toBe(1);
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("bare `maruhi audit` でも list のフラグが使える(`audit --limit 5`)", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--limit", "5"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Unknown flag");
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("`audit --help` の usage はサブコマンドを任意(`[subcommand]`)と描く", async () => {
    // bare `maruhi audit` = list が動く以上、上流の一律 `<subcommand>`(必須)
    // は嘘になる(Pullfrog レビューの指摘)。判定は宣言駆動 — フラグと
    // サブコマンドの両方を持つ段(ハンドラ付き親)だけを直す
    const help = await startEnv();
    expect(await runCli(["audit", "--help"], help.env.layer)).toBe(0);
    const full = help.env.errors.join("\n");
    expect(full).toContain("maruhi audit [subcommand]");
    expect(full).not.toContain("<subcommand>");

    // 通常の親(bare がエラーになる段)は従来どおり必須と描く
    const env = await startEnv();
    expect(await runCli(["env", "--help"], env.env.layer)).toBe(0);
    expect(env.env.errors.join("\n")).toContain("maruhi env <subcommand>");
  });

  it("audit の書き方の誤りは通信より前に落ちる(範囲外・型違い・不明な操作)", async () => {
    const range = await startEnv();
    expect(await runCli(["audit", "--limit", "0"], range.env.layer)).toBe(2);
    expect(range.env.errors.join("\n")).toContain("--limit must be an integer between 1 and 200");
    expect(range.server.requests).toHaveLength(0);

    // 値の無い / 数として読めない number は gunshi では内部エラー(exit 1)
    // だったが、effect では InvalidValue = usage エラー(exit 2)になる
    const typed = await startEnv();
    expect(await runCli(["audit", "--limit", "s3cr3t"], typed.env.layer)).toBe(2);
    const typedErrors = typed.env.errors.join("\n");
    expect(typedErrors).toContain("Unacceptable value for flag --limit");
    expectNoLeak(typed.env, ["s3cr3t"]);
    expect(typed.server.requests).toHaveLength(0);

    const bogus = await startEnv();
    expect(await runCli(["audit", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: list | invites | self | verify | reconcile)",
    );
    expect(bogus.server.requests).toHaveLength(0);
  });

  it("自段のフラグをサブコマンドより前に書いた形は、自己矛盾せず置き場所を案内する", async () => {
    // `audit --limit 5 list`(gunshi が通していた形)。上流は親のローカル
    // フラグをサブコマンドへ継承しない = 未宣言として報告するが、bare 親
    // (= list)の宣言に同じフラグがあるため、「受け付ける一覧」に載せると
    // 自己矛盾になる(レビュー第 2 巡の指摘)
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--limit", "5", "list"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--limit belongs after the subcommand");
    expect(errors).not.toContain("flags this command accepts");
    expect(server.requests).toHaveLength(0);
  });

  it("その操作に無いフラグは usage エラー(2)で落ちる(AUDIT_ACTION_FLAGS の置き換え)", async () => {
    // gunshi 時代の optionRestrictedTo / auditActionFlagRejection が受け持って
    // いた形。宣言が操作ごとに分かれたので、未宣言フラグとして構造的に落ちる
    for (const argv of [
      ["audit", "verify", "--limit", "5"],
      ["audit", "self", "--project", "x"],
      ["audit", "invites", "--event", "var.version_pushed"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain("Unknown flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("audit list のフィルタの形式検査は通信より前に落ちる", async () => {
    const { env, server } = await startEnv();
    expect(await runCli(["audit", "--env", "!bad"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Invalid environment ID for --env");
    expect(server.requests).toHaveLength(0);
  });

  it("bare `maruhi rotation` / 不明な操作は usage エラー(2)", async () => {
    const bare = await startEnv();
    expect(await runCli(["rotation"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi rotation");

    const bogus = await startEnv();
    expect(await runCli(["rotation", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: list | dismiss)",
    );
  });

  it("rotation dismiss の boolean(--all)は重複を拒否し、値は書いたとおりに読む", async () => {
    // gunshi に最後まで残っていた boolean。`--all=false` は gunshi では
    // **値を読まずに true**(全フラグの取り下げに化ける)だったが、effect は
    // 書いたとおり false として読む(12 形の #2)。重複は atMost(1) が落とす
    for (const argv of [
      ["rotation", "dismiss", "--all", "--no-all"],
      ["rotation", "dismiss", "--all", "--all"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n"), argv.join(" ")).toContain(
        "Flag --all was specified more than once",
      );
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }

    // `--all=false` は「--all を書いていない」実行として読まれ、引数層は通る
    // (対象未指定はコマンド本体が exit 1 で報告する — 書いたことと逆にならない)。
    // 退行(true に化ける)と resolveAllTargets が必ず通信するので、
    // 「対象未指定の案内 + 通信ゼロ」で判別する(Pullfrog 指摘のテスト強化)
    const explicit = await startEnv();
    expect(await runCli(["rotation", "dismiss", "--all=false"], explicit.env.layer)).toBe(1);
    expect(explicit.env.errors.join("\n")).not.toContain("Unknown flag");
    expect(explicit.env.errors.join("\n")).toContain("Specify what to dismiss");
    expect(explicit.server.requests).toHaveLength(0);
  });

  it("rotation dismiss の対象の欠落・--all との矛盾は通信より前に落ちる", async () => {
    // 前段の同期より後ろに置くと、案内が接続エラーに隠れる(このハーネスの
    // サーバーは 404 しか返さない)うえ往復が無駄になる
    const missing = await startEnv();
    expect(await runCli(["rotation", "dismiss"], missing.env.layer)).toBe(1);
    expect(missing.env.errors.join("\n")).toContain("Specify what to dismiss");
    expect(missing.server.requests).toHaveLength(0);

    const contradictory = await startEnv();
    expect(
      await runCli(
        ["rotation", "dismiss", "--all", "va1234567890123456789012", "--env", "prod"],
        contradictory.env.layer,
      ),
    ).toBe(1);
    expect(contradictory.env.errors.join("\n")).toContain(
      "--all cannot be combined with a variableId",
    );
    expect(contradictory.server.requests).toHaveLength(0);
  });

  it("rotation dismiss の対象の形式検査は通信より前に落ちる(値は出さない)", async () => {
    const env1 = await startEnv();
    expect(
      await runCli(["rotation", "dismiss", "sk-live-x!", "--env", "prod"], env1.env.layer),
    ).toBe(2);
    expect(env1.env.errors.join("\n")).toContain("Invalid variableId");
    expectNoLeak(env1.env, ["sk-live-x!"]);
    expect(env1.server.requests).toHaveLength(0);

    const env2 = await startEnv();
    expect(await runCli(["rotation", "dismiss", "--all", "--env", "!bad"], env2.env.layer)).toBe(2);
    expect(env2.env.errors.join("\n")).toContain("Invalid environment ID for --env");
    expect(env2.server.requests).toHaveLength(0);
  });
});

describe("push の移行(ADR-0016 第 3 段階 ①)", () => {
  it("余分な引数は中身を出さず、値の渡し方(stdin)を必ず添える", async () => {
    // `maruhi push API_KEY "$SECRET"` は最も起こりやすい書き間違い。拒否した
    // 引数の中身は出さない(平文でありうる)代わりに、直し方を必ず添える —
    // でないと直しようがない(args.test.ts の旧ケースの規律)
    const secret = "hunter2-plaintext-value";
    for (const argv of [
      ["push", "API_KEY", secret],
      // `--` の後ろも push は読まない(読むのは run だけ)。黙って捨てずに落とす
      ["push", "API_KEY", "--", secret],
      ["push", "API_KEY", "--", ""],
    ]) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors).toContain("Unexpected extra arguments (1;");
      expect(errors).toContain("contents not shown");
      expect(errors).toContain("Values are read from stdin");
      expectNoLeak(env, [secret]);
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("変数名の欠落・空 / 空白だけの変数名は宣言で落ちる", async () => {
    const missing = await startEnv();
    expect(await runCli(["push"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain("Missing positional argument name");
    expect(missing.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["push", "  "], blank.env.layer)).toBe(2);
    expect(blank.env.errors.join("\n")).toContain(
      "Unacceptable value for positional argument name",
    );
    expect(blank.server.requests).toHaveLength(0);
  });

  it("位置引数の名前をオプションとして書いた形(`--name`)は直し方まで案内する", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));
    expect(await runCli(["push", "--name", "API_KEY"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--name is a positional argument");
    expect(server.requests).toHaveLength(0);
  });

  it("空 / 空白だけのオプション値は既定へ潰さず落とす(既定環境への書き込み事故)", async () => {
    // gunshi は空の値を「未指定」に潰すため、`--env "$ENV"` の未設定形が
    // **既定環境への書き込み**に化けた(取り消せない)。宣言(NonBlank)が塞ぐ
    for (const argv of [
      ["push", "API_KEY", "--env", ""],
      ["push", "API_KEY", "--env", "  "],
      ["push", "API_KEY", "--project="],
    ]) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("値がオプションに化けた形は綴りを復元して出さない(平文の漏洩経路)", async () => {
    // `-hunter2`(短縮グループ)・`--sk_live_ab12`・`-----BEGIN...`(長い綴り)
    // のような「値のつもりの語」を、拒否の診断が書き出さないこと。候補は
    // **宣言名**からしか出さない(cli-formatter.ts の規律)
    // `-hunter2` は使わない: 短縮グループの先頭 `-h` は組み込みの help に
    // 解決され、ヘルプ表示(exit 0)になる — 何も漏れないが拒否の検査には
    // ならないため、help に当たらない先頭文字で同じ形を固定する
    for (const [typed, fragment] of [
      ["-xunter2", "unter2"],
      ["--sk_live_ab12", "sk_live"],
      ["-----BEGIN-RSA-PRIVATE-KEY-hunter2", "BEGIN"],
      ["--constructor=x", "constructor"],
    ] as const) {
      const { env, server } = await startEnv();
      env.setStdin(new TextEncoder().encode("secret-value"));
      expect(await runCli(["push", "API_KEY", typed], env.layer), typed).toBe(2);
      const errors = env.errors.join("\n");
      expect(errors, typed).toContain("Unknown flag");
      expect(errors, typed).not.toContain(fragment);
      expect(server.requests, typed).toHaveLength(0);
    }
  });
});

describe("config の入れ子サブコマンド(ADR-0016 第 3 段階 ①)", () => {
  it("不明な操作・bare `maruhi config` は usage エラー(2)", async () => {
    const bogus = await startEnv();
    expect(await runCli(["config", "bogus"], bogus.env.layer)).toBe(2);
    expect(bogus.env.errors.join("\n")).toContain(
      "Unknown subcommand (expected one of: get | set)",
    );

    const bare = await startEnv();
    expect(await runCli(["config"], bare.env.layer)).toBe(2);
    expect(bare.env.logs).toEqual([]);
    expect(bare.env.errors.join("\n")).toContain("maruhi config");
  });

  it("不明な設定キーは打たれた語を返さず、取りうるキーの一覧を出す", async () => {
    // 行を消して偽の成功行を書くような ANSI 列を含む語。文面は取りうる値の
    // 一覧だけで、打たれた語は出さない(位置引数には値が書かれうる)
    const evil = "[2K\rmaruhi: OK";
    const get = await startEnv();
    expect(await runCli(["config", "get", evil], get.env.layer)).toBe(2);
    const getOutput = [...get.env.logs, ...get.env.errors].join("\n");
    expect(getOutput).toContain("Unknown config key (server | defaultProject");
    expect(getOutput).not.toContain("");
    expect(getOutput).not.toContain("\r");

    // 操作名の位置に書かれた語も返さない(不明なサブコマンドの診断)
    const action = await startEnv();
    expect(await runCli(["config", evil, "server"], action.env.layer)).toBe(2);
    const actionOutput = [...action.env.logs, ...action.env.errors].join("\n");
    expect(actionOutput).toContain("Unknown subcommand");
    expect(actionOutput).not.toContain("");
    expect(actionOutput).not.toContain("\r");
  });

  it("`config set` の空 / 空白だけの値は既存の設定を上書きせずに落ちる", async () => {
    // `config set defaultProject "$PROJ"` の未設定形が既存の設定を空で
    // 上書きして成功を報告する事故(gunshi 時代は args.ts の走査、いまは宣言)
    for (const value of ["", "  "]) {
      const { env } = await startEnv();
      expect(await runCli(["config", "set", "defaultEnvironment", value], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for positional argument value");
      expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
      expect(env.logs).toContain("prod");
    }
  });

  it("値の無い `config set` は宣言(必須位置引数)で落ちる", async () => {
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "defaultEnvironment"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Missing positional argument value");
  });

  it("`--` の後ろのトークンは位置引数の空きを埋める(ADR-0016 追記 8)", async () => {
    // 上流はパーサが `--` の前後の位置引数を 1 つの配列に畳む。`-` で始まる
    // 値を位置引数として書く POSIX の逃げ道として機能し、黙って捨てられる
    // トークンは無い(空きを超える分は余分な位置引数 = exit 2 のまま)
    const { env } = await startEnv();
    expect(await runCli(["config", "set", "--", "defaultEnvironment", "dev"], env.layer)).toBe(0);
    expect(env.logs).toContain("Set defaultEnvironment");
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(env.logs).toContain("dev");
  });

  it("`config get` の余分な引数は落ち、設定も読み出しも壊さない", async () => {
    const single = await startEnv();
    expect(await runCli(["config", "get", "defaultEnvironment", "dev"], single.env.layer)).toBe(2);
    const errors = single.env.errors.join("\n");
    expect(errors).toContain("Unexpected extra arguments (1;");
    expect(errors).toContain("maruhi config get only takes these positional arguments: key");
    expect(single.env.logs).toHaveLength(0);

    // 個数は過少報告しない(gunshi 時代は optional スロットが 1 つ吸っていた)
    const multiple = await startEnv();
    expect(
      await runCli(["config", "get", "defaultEnvironment", "a", "b"], multiple.env.layer),
    ).toBe(2);
    expect(multiple.env.errors.join("\n")).toContain("Unexpected extra arguments (2;");

    // set の余分な引数も設定を書き換えない
    const set = await startEnv();
    expect(
      await runCli(["config", "set", "defaultEnvironment", "dev", "extra"], set.env.layer),
    ).toBe(2);
    expect(set.env.errors.join("\n")).toContain("Unexpected extra arguments (1;");
    expect(await runCli(["config", "get", "defaultEnvironment"], set.env.layer)).toBe(0);
    expect(set.env.logs).toContain("prod");
  });

  it("成功した実行の stdout はコマンドの出力(値)だけ", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // `V=$(maruhi config get server)` が値以外を捕まえないこと
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.logs).toEqual(["prod"]);
  });
});
