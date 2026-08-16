// `effect/unstable/cli` へ移した引数層(pull / run / env create)の適合検査。
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
    expect(env.errors.join("\n")).toContain("maruhi: 不明なオプションです(--show のことですか?)");
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
      expect(env.errors.join("\n")).toContain("環境 ID の形式が正しくありません");
      expect(server.requests).toHaveLength(0);
    }
  });

  it("4. 同じオプションの重複は落ちる(勝つ側を語らずに拒否する)", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--env", "prod", "--env", "dev"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("オプション --env を複数回指定しています");
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
      expect(env.errors.join("\n")).toContain("オプション --show を複数回指定しています");
      expect(server.requests, argv.join(" ")).toHaveLength(0);
    }
  });

  it("5. `--` の後ろの空文字列は落ちない(gunshi は rest から落としていた)", async () => {
    // 実行対象は保たれ、通信(pull)まで進む = 引数層は受理している
    const { env, server } = await startEnv();

    expect(await runCli(["run", "--", "printenv", "", "x"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("実行するコマンドを");
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("6. 先頭の空の位置引数は落ちる(gunshi は読み飛ばして段がずれた)", async () => {
    const { env, server } = await startEnv();

    // gunshi は falsy な位置引数を読み飛ばして 1 段ずれたまま実行していた。
    // 移行先は空のトークンをコマンド名として解決しようとして落ちる
    expect(await runCli(["", "pull"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なコマンドです");
    expect(env.logs).toEqual([]);
    expect(server.requests).toHaveLength(0);
  });

  it("7. `--` を跨いでコマンドを解決しない", async () => {
    const { env, server } = await startEnv();

    // gunshi は `--` を跨いで run として解決し、`--` の後ろの先頭
    // (= コマンド名そのもの)を実行対象として渡していた
    expect(await runCli(["--", "run", "printenv"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("コマンド名は `--` より前に書いてください");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("8. 必須の位置引数の欠落が落ちる", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("位置引数 environment-id を指定してください");
    expect(server.requests).toHaveLength(0);
  });

  it("10. 位置引数の名前をオプションとして書いた形は直し方まで案内する", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--environment-id は位置引数です");
    expect(errors).toContain("値は位置引数として並べてください");
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
    // 実際に足りないもの(`--` より前の位置引数)を言う
    expect(errors).toContain("位置引数 action を指定してください");
    // 「操作は認識されていて位置引数が多い」という嘘をつかない
    expect(errors).not.toContain("maruhi env create");
    expect(errors).not.toContain("余分な引数です");
    expect(server.requests).toHaveLength(0);
  });

  it("11. オプションへの空 / 空白だけの値は落ちる(既定へ黙って落ちない)", async () => {
    // `maruhi push API_KEY --env "$ENV"` で ENV が未設定のとき、既定環境へ
    // 黙って書き込む事故と同じ形。Schema の宣言 1 つで両方を落とす
    const empty = await startEnv();
    expect(await runCli(["pull", "--env", ""], empty.env.layer)).toBe(2);
    expect(empty.env.errors.join("\n")).toContain("オプション --env の値が受け付けられません");
    expect(empty.server.requests).toHaveLength(0);

    const blank = await startEnv();
    expect(await runCli(["pull", "--env", "  "], blank.env.layer)).toBe(2);
    // 許可リスト(SAFE_EXPECTATIONS)が生きていることを**陽性側でも**固定する:
    // 文面を片側だけ直すと括弧が黙って落ちるだけになり、診断が静かに劣化する
    expect(blank.env.errors.join("\n")).toContain(
      "オプション --env の値が受け付けられません(空でない値",
    );
    // 打たれた値(空白)は診断に出さない
    expect(blank.env.errors.join("\n")).not.toContain('"  "');
  });

  it("12. 余分な位置引数は個数だけを言い、中身は出さない", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "SUPER_SECRET_VALUE"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("中身は表示しません");
    expect(errors).toContain("maruhi pull は位置引数を取りません");
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
      expect(env.errors.join("\n")).toContain("不明なオプションです");
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
    for (const marker of ["使い方: maruhi", "不明なオプション", "FLAGS", "maruhi:"]) {
      expect(written, marker).not.toContain(marker);
    }
  });

  it("誤りに添えるヘルプは使い方 1 行だけ(--help は全文)", async () => {
    const { env } = await startEnv();
    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    const brief = env.errors.join("\n");
    expect(brief).toContain("使い方: maruhi pull");
    // 全文にだけ現れる節(FLAGS 等)は誤りの診断に混ぜない
    expect(brief).not.toContain("FLAGS");

    const help = await startEnv();
    expect(await runCli(["pull", "--help"], help.env.layer)).toBe(0);
    expect(help.env.errors.join("\n")).toContain("FLAGS");
  });

  it("`--` の後ろの `-h` は子プロセスの引数(ヘルプ要求として読まない)", async () => {
    // 全 argv を見ると、maruhi の書き方の誤りに**子プロセス向けのフラグ**が
    // 混ざっただけで全文ヘルプが出てしまい、肝心の診断が埋もれる
    const { env } = await startEnv();
    expect(await runCli(["run", "stray", "--", "printenv", "-h"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
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
    expect(errors).toContain("maruhi: 内部エラー(Error)");
    expect(errors).not.toContain("config load defect");
  });

  it("`maruhi run` は `--` の後ろからしか実行対象を取らない", async () => {
    const missing = await startEnv();
    expect(await runCli(["run"], missing.env.layer)).toBe(2);
    expect(missing.env.errors.join("\n")).toContain(
      "実行するコマンドを `--` の後に指定してください",
    );
    expect(missing.server.requests).toHaveLength(0);

    // `--` はあるが実行対象が空(`maruhi run -- "$CMD"` の未設定形)
    const empty = await startEnv();
    expect(await runCli(["run", "--", ""], empty.env.layer)).toBe(2);
    expect(empty.env.runnerCalls).toHaveLength(0);
    expect(empty.server.requests).toHaveLength(0);

    // `--` の書き忘れ。個数はパーサが解決した配列から出す(宣言の写しを
    // 持たない)ので、フラグの値は数に入らず、位置が前後しても同じ数になる
    for (const argv of [
      ["run", "npm", "test"],
      ["run", "--env", "prod", "npm", "test"],
      ["run", "npm", "test", "--env", "prod"],
    ]) {
      const { env, server } = await startEnv();
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("余分な引数です(2 個");
      expect(env.errors.join("\n")).toContain("`--` の後に並べてください");
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
    expect(message).toContain("オプション --limit の値が受け付けられません");
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
    expect(message).toBe("オプション --env の値が受け付けられません");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("UnexpectedArgument は個数だけを出す", () => {
    const message = describeError(
      new EffectCliError.UnexpectedArgument({ arguments: ["SECRET_A", "SECRET_B"] }),
      "pull",
      { pull: { flags: [], positionals: [] } },
    );
    expect(message).toContain("2 個");
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
    maruhiTeardown(withErrors, (code) => codes.push(code));
    expect(codes).toEqual([2]);

    // `--help` / `--version`(errors 空)は誤りではない
    const helpCodes: number[] = [];
    maruhiTeardown(
      Exit.fail(new EffectCliError.ShowHelp({ commandPath: ["maruhi"], errors: [] })),
      (code) => helpCodes.push(code),
    );
    expect(helpCodes).toEqual([0]);
  });
});
