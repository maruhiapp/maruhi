// effect/unstable/cli 移行スパイクの適合検査(pull / run / env create)。
//
// gunshi で実際に踏んだ形(docs/notes/cli-parser-alternatives.md の 12 形)を
// 同じ argv で流し、maruhi の規律が保たれることを固定する:
// 書き方の誤り = exit 2 / 診断は stderr / stdout は汚さない / 打たれた値は
// 診断に出さない。
//
// 本番の CLI(src/cli.ts)は gunshi のまま。ここが green であることは
// 「移行しても失われる規律が無い」ことの根拠になる。

import { Exit, Runtime } from "effect";
import { CliError } from "effect/unstable/cli";
import { describe, expect, it } from "vitest";

import { ValueDisplayRefused } from "./support/agent-gate.ts";
import { describeError, runSpikeCli } from "./support/effect-cli-spike.ts";

/** 診断に平文が混ざっていないことの共通検査(打たれた値を語彙にしない)。 */
function expectNoSecretLeak(stderr: readonly string[], secrets: readonly string[]): void {
  for (const secret of secrets) {
    expect(stderr.join("\n")).not.toContain(secret);
  }
}

describe("gunshi で踏んだ形が effect/unstable/cli で落ちる", () => {
  it("1. 未宣言のオプションは実行前に落ちる(gunshi は黙って無視していた)", async () => {
    const outcome = await runSpikeCli(["pull", "--shwo"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
    // 候補は**宣言名**から出す(打たれた綴りは返さない)。部分一致だと
    // `----show`(接頭辞の二重付与)を見逃すので完全一致で固定する
    expect(outcome.stderr).toContain("maruhi: 不明なオプションです(--show のことですか?)");
    expectNoSecretLeak(outcome.stderr, ["--shwo"]);
  });

  it("2. boolean へのインライン値は書いたとおりに読まれる(gunshi は true に化けた)", async () => {
    const outcome = await runSpikeCli(["pull", "--show=false"]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.values["show"]).toBe(false);
  });

  it("3. boolean への空白区切りの値も書いたとおりに読まれる", async () => {
    const outcome = await runSpikeCli(["pull", "--show", "false"]);
    expect(outcome.exitCode).toBe(0);
    // gunshi は「フラグ有効 + 余分な位置引数」にしていた(= 表示に化ける)
    expect(outcome.invoked?.values["show"]).toBe(false);
  });

  it("4. 同じオプションの重複は落ちる(勝つ側を語らずに拒否する)", async () => {
    const outcome = await runSpikeCli(["pull", "--env", "prod", "--env", "dev"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
    expect(outcome.stderr.join("\n")).toContain("オプション --env を複数回指定しています");
    expectNoSecretLeak(outcome.stderr, ["prod", "dev"]);
  });

  it("4b. 値を取るオプションの重複は Flag.atMost(1) が落とす(自前の走査なし)", async () => {
    // `maruhi push K --env prod --env dev` は書いた 2 つのうち片方だけへ
    // 書き込む(取り消せない)。宣言で落とす
    const outcome = await runSpikeCli(["run", "--env", "prod", "--env", "dev", "--", "printenv"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
    expect(outcome.stderr.join("\n")).toContain("オプション --env を複数回指定しています");
  });

  it("5. `--` の後ろの空文字列が落ちない(gunshi は rest から落としていた)", async () => {
    const outcome = await runSpikeCli(["run", "--", "printenv", "", "x"]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.rest).toEqual(["printenv", "", "x"]);
  });

  it("6. 先頭の空の位置引数は落ちる(gunshi は読み飛ばして段がずれた)", async () => {
    const outcome = await runSpikeCli(["", "pull"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
  });

  it("7. `--` を跨いでコマンドを解決しない", async () => {
    const outcome = await runSpikeCli(["--", "run", "printenv"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
  });

  it("8. 必須の位置引数の欠落が落ちる", async () => {
    const outcome = await runSpikeCli(["env", "create"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr.join("\n")).toContain("位置引数 environment-id を指定してください");
  });

  it("10. 位置引数の名前をオプションとして書いた形は直し方まで案内する", async () => {
    const outcome = await runSpikeCli(["env", "create", "dev", "--environment-id", "prod"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.invoked).toBeNull();
    expect(outcome.stderr.join("\n")).toContain("--environment-id は位置引数です");
    expectNoSecretLeak(outcome.stderr, ["prod"]);
  });

  it("11. オプションへの空の値は落ちる(既定へ黙って落ちない)", async () => {
    const outcome = await runSpikeCli(["pull", "--env", ""]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr.join("\n")).toContain("オプション --env の値が受け付けられません");
  });

  it("11b. 空白だけの値も落ちる(Schema の宣言 1 つで両方)", async () => {
    const outcome = await runSpikeCli(["pull", "--env", "  "]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr.join("\n")).toContain("オプション --env の値が受け付けられません");
    // 打たれた値(空白)は診断に出さない
    expect(outcome.stderr.join("\n")).not.toContain('"  "');
  });

  it("12. 余分な位置引数は個数だけを言い、中身は出さない", async () => {
    const outcome = await runSpikeCli(["pull", "SUPER_SECRET_VALUE"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr.join("\n")).toContain("余分な引数です(1 個");
    expect(outcome.stderr.join("\n")).toContain("中身は表示しません");
    expectNoSecretLeak(outcome.stderr, ["SUPER_SECRET_VALUE"]);
  });
});

describe("maruhi 固有の規律", () => {
  it("stdout はコマンドの出力だけ(診断もヘルプも stderr)", async () => {
    const rejected = await runSpikeCli(["pull", "--shwo"]);
    expect(rejected.stdout).toEqual([]);
    expect(rejected.stderr.length).toBeGreaterThan(0);

    const help = await runSpikeCli(["pull", "--help"]);
    // ヘルプ要求は誤りではない(exit 0)。本文が stdout へ出ないことが要点 —
    // `V=$(maruhi config get server)` がバナーを捕まえた事故と同じ形を塞ぐ
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toEqual([]);
    expect(help.stderr.join("\n")).toContain("maruhi pull");
  });

  it("`maruhi run` は `--` の後ろからしか実行対象を取らない", async () => {
    const missing = await runSpikeCli(["run"]);
    expect(missing.exitCode).toBe(2);
    expect(missing.stderr.join("\n")).toContain("実行するコマンドを `--` の後に指定してください");

    const empty = await runSpikeCli(["run", "--", ""]);
    expect(empty.exitCode).toBe(2);
    expect(empty.invoked).toBeNull();

    const strayed = await runSpikeCli(["run", "npm", "test"]);
    expect(strayed.exitCode).toBe(2);
    expect(strayed.stderr.join("\n")).toContain("実行するコマンドは `--` の後に並べてください");
    expectNoSecretLeak(strayed.stderr, ["npm", "test"]);
  });

  it("既知の AI エージェントでは pull --show を拒否する(復号より前・exit 1)", async () => {
    const outcome = await runSpikeCli(["pull", "--show"], {
      agent: { isAgent: true, name: "claude" },
    });
    // 終了コードはエラー型が持つ(Runtime.errorExitCode = 1)。
    // 書き方の誤り(2)ではなく実行の拒否(1)
    expect(outcome.exitCode).toBe(1);
    expect(outcome.stderr.join("\n")).toContain("AI エージェント環境を検出したため");
    // 迂回レシピ(run -- printenv)を案内しない
    expect(outcome.stderr.join("\n")).not.toContain("run --");
  });

  it("**未知**のエージェントでも拒否する(TTY が一次境界 = fail-closed)", async () => {
    // エージェント検出のリストに載っていない = isAgent: false でも、
    // 出力がパイプ・リダイレクトなら値は見せない。deny-list では素通りしていた形
    const outcome = await runSpikeCli(["pull", "--show"], {
      agent: { isAgent: false },
      stdoutIsTerminal: false,
    });
    expect(outcome.exitCode).toBe(1);
    expect(outcome.stderr.join("\n")).toContain("値の表示は対話端末でのみ許可されます");
  });

  it("stdin が端末でない実行(CI・ヒアドキュメント)も拒否する", async () => {
    const outcome = await runSpikeCli(["pull", "--show"], {
      agent: { isAgent: false },
      stdinIsTerminal: false,
    });
    expect(outcome.exitCode).toBe(1);
  });

  it("人間の対話端末では通る", async () => {
    const outcome = await runSpikeCli(["pull", "--show"], {
      agent: { isAgent: false },
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.values["show"]).toBe(true);
  });

  it("エージェント環境でも値を表示しない実行は通る(run への注入は許可のまま)", async () => {
    const outcome = await runSpikeCli(["pull"], { agent: { isAgent: true, name: "claude" } });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.command).toBe("pull");

    const injected = await runSpikeCli(["run", "--", "printenv", "MY_VAR"], {
      agent: { isAgent: true, name: "claude" },
      stdoutIsTerminal: false,
    });
    expect(injected.exitCode).toBe(0);
    expect(injected.invoked?.rest).toEqual(["printenv", "MY_VAR"]);
  });
});

describe("正常系(引数層が解決した値)", () => {
  it("pull はフラグをそのまま解決する", async () => {
    const outcome = await runSpikeCli(["pull", "--env", "prod", "--show"]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.values["show"]).toBe(true);
  });

  it("env create は入れ子のサブコマンドとして解決する", async () => {
    const outcome = await runSpikeCli(["env", "create", "dev", "--name", "開発"]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.command).toBe("env create");
  });

  it("run は `--` の後ろをそのまま子プロセスの引数として渡す", async () => {
    const outcome = await runSpikeCli(["run", "--env", "prod", "--", "printenv", "MY_VAR"]);
    expect(outcome.exitCode).toBe(0);
    expect(outcome.invoked?.rest).toEqual(["printenv", "MY_VAR"]);
  });
});

describe("診断の写像(構造化フィールドからの組み直し)", () => {
  it("InvalidValue は打たれた値を出さない", () => {
    // effect/unstable/cli の既定の文面は value を含む(`Invalid value ...`)。
    // maruhi は宣言名と期待する型だけを出す
    const message = describeError(
      new CliError.InvalidValue({
        option: "limit",
        value: "SUPER_SECRET_VALUE",
        expected: "integer",
        kind: "flag",
      }),
      "pull",
    );
    expect(message).toContain("オプション --limit の値が受け付けられません");
    expect(message).not.toContain("SUPER_SECRET_VALUE");
  });

  it("UnexpectedArgument は個数だけを出す", () => {
    const message = describeError(
      new CliError.UnexpectedArgument({ arguments: ["SECRET_A", "SECRET_B"] }),
      "pull",
    );
    expect(message).toContain("2 個");
    expect(message).not.toContain("SECRET_A");
    expect(message).not.toContain("SECRET_B");
  });
});

describe("Effect の機構に載せた部分", () => {
  it("終了コードはエラー型が持つ(runMain の既定 teardown が読む値と同じ)", () => {
    // ランナー側に「usage は 2、失敗は 1」の写像表を書かないための機構。
    // Runtime.defaultTeardown = BunRuntime.runMain が使う既定の teardown
    const codes: number[] = [];
    Runtime.defaultTeardown(
      Exit.fail(new ValueDisplayRefused({ message: "値の表示は拒否されました" })),
      (code) => codes.push(code),
    );
    expect(codes).toEqual([1]);
  });
});
