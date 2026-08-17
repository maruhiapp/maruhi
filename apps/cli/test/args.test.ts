// 引数の**書き方**の検査(src/args.ts + gunshi の `CliOptions.strict`)。
//
// **対象は gunshi に残っているコマンド**(ADR-0016 の第 1〜2 段階で
// pull / run / env は effect/unstable/cli へ移した。移行先の同型検査は
// effect-cli.test.ts)。
//
// gunshi 0.37.1 が黙って通し、**書いたことと逆の結果**になる 4 形を塞ぐ:
//
// 1. 未宣言オプション(`push --enve prod` が既定環境への書き込みに化ける)
// 2. boolean へのインライン値(`--new-epoch=false` は値を読まずに true)
// 3. boolean への空白区切りの値(`--new-epoch false` = フラグ有効 + 位置引数)
// 4. 位置引数の名前のオプション化(`env rotate --environment-id prod` は
//    値が捨てられる)
//
// いずれも**コマンド本体より前**に落ちること(通信も復号も設定書き込みも
// 起きないこと)まで固定する — 最悪形は `env rotate --new-epoch false` で、
// 通すと環境 `false` に対する取り消せないローテーションが走る。

import { afterEach, describe, expect, it, vi } from "vitest";

import { argsRejection } from "../src/args.ts";
import { runCli } from "../src/cli.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
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
async function startEnv(): Promise<{ env: TestEnv; server: MockServer; owner: TestUser }> {
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
  return { env, server, owner };
}

describe("boolean オプションへの値の指定", () => {
  // 移行前は `env rotate --new-epoch` が主な車両だったが、env は
  // effect/unstable/cli へ移した(effect-cli.test.ts が同じ形を宣言で固定する)。
  // gunshi に残る boolean は rotation dismiss の --all だけなので、以降の
  // CLI 水準の検査は rotation を車両にする(negatable の綴りは単体検査で固定)
  it("`rotation dismiss --all=false` は値を読まずに true へ化けるため拒否する", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["rotation", "dismiss", "--all=false"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--all は値を取りません");
    expect(server.requests).toHaveLength(0);
    expect(env.logs).toHaveLength(0);
  });

  it("`rotation dismiss --all false` は「フラグ有効 + 位置引数」なので値の指定として拒否する", async () => {
    const { env, server } = await startEnv();

    // 空白区切りの値は gunshi が消費しない(--all は true のまま、"false" が
    // 位置引数として残る = 全フラグの取り下げに化ける)
    expect(await runCli(["rotation", "dismiss", "--all", "false"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--all は値を取りません");
    expect(server.requests).toHaveLength(0);
    expect(env.logs).toHaveLength(0);
  });

  it("boolean の直後でも、真偽値として読めない語は位置引数として扱う", async () => {
    const { env } = await startEnv();

    // `--all garbage` の garbage は真偽値らしくないので位置引数として扱う。
    // ここでは位置引数の数を超えるので余分な引数として落ちる = boolean の
    // 文面にはならないが、boolean を書いた実行なので助言は添える
    expect(await runCli(["rotation", "dismiss", "var-1", "--all", "garbage"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("boolean オプションに値は付けられません");
  });

  it("位置引数が空いていると、boolean の値がそこへ吸い込まれる形も拒否する", async () => {
    const { env, server } = await startEnv();

    // `rotation dismiss --all false` は variable を書いていないため、余った
    // "false" が optional スロットへ入って個数検査を素通りする。通すと
    // **変数 `false` の取り下げ**(書いたことと逆 = --all は有効のまま)になる
    expect(
      await runCli(["rotation", "dismiss", "--env", "prod", "--all", "false"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--all は値を取りません");
    expect(server.requests).toHaveLength(0);
  });

  it("真偽値リテラルは `false` 以外の書き方も拾い、正しい書き方を案内する", async () => {
    const { env, server } = await startEnv();

    // 網羅は原理的に無理なので、**正しい書き方**を必ず添える。`n` / `off` も
    // 同じ吸い込みを起こす
    for (const literal of ["n", "off", "disable", "0"]) {
      expect(await runCli(["rotation", "dismiss", "--all", literal], env.layer)).toBe(2);
    }
    const literalErrors = env.errors.join("\n");
    expect(literalErrors).toContain(
      "有効にするなら値なしで --all と書き、無効にするならオプション自体を外してください",
    );
    // 変数 ID が本当にその語である可能性は残るので、逃げ道を示す
    expect(literalErrors).toContain("その語が本当に位置引数なら、オプションより前に書いてください");
    expect(server.requests).toHaveLength(0);
  });

  it("boolean フラグとリテラルの間に別のオプションが挟まっても拾う", async () => {
    const { env, server } = await startEnv();

    // 直前のトークンだけを見ると、`--env prod` の値を挟んだ形を取り逃がす
    // (余った literal が空の optional スロットへ入り、変数 `false` を取り下げる)
    expect(
      await runCli(["rotation", "dismiss", "--all", "--env", "prod", "false"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--all は値を取りません");
    expect(server.requests).toHaveLength(0);
  });

  it("挟まったオプションがインライン値(`--env=prod`)でも拾う", async () => {
    const { env, server } = await startEnv();

    // インライン値を持つトークンは**次の位置引数を消費しない**。「値を取る
    // オプションか」だけで判定すると、直後の literal を `--env` の値と
    // 見なして素通りする
    expect(await runCli(["rotation", "dismiss", "--all", "--env=prod", "false"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("--all は値を取りません");
    expect(server.requests).toHaveLength(0);
  });

  it("boolean フラグより**前**に置いた位置引数は通す(案内した逃げ道)", async () => {
    const { env } = await startEnv();

    // 「オプションより前に書いてください」と案内する以上、その形は引数層を通す
    // (コマンド本体 = 通信まで進み、実行の失敗(1)になる)
    expect(await runCli(["rotation", "dismiss", "false", "--all"], env.layer)).not.toBe(2);
    expect(env.errors.join("\n")).not.toContain("値を取りません");
  });

  it("string オプションのインライン値(`--env=prod`)は拒否しない", async () => {
    const { env } = await startEnv();

    // boolean だけの検査であることの確認(= 誤検知で正当な書き方を塞がない)。
    // 引数層は通り、コマンド本体(通信)まで進んで別の理由で落ちる
    expect(await runCli(["rotation", "dismiss", "--env=prod", "--all"], env.layer)).not.toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("値を取りません");
    expect(errors).not.toContain("余分な引数です");
  });
});

describe("未宣言オプション(strict)", () => {
  it("エントリコマンド(`maruhi --shwo`)でも落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["--shwo"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです");
    expect(env.logs).toHaveLength(0);
  });

  it("コマンド名の綴り間違いでは、正しく綴られたオプションを不明扱いしない", async () => {
    const { env } = await startEnv();

    // 未解決のコマンドではエントリコマンドの引数表と突き合わされるため、
    // 綴りの合っている --show まで不明として並ぶ(探させない)
    expect(await runCli(["pul", "--show"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なコマンドです(pull のことですか?)");
    expect(errors).not.toContain("不明なオプションです");
  });
});

describe("操作に適用されないオプション(gunshi に残るコマンド)", () => {
  // env は effect/unstable/cli の入れ子サブコマンドへ移したので、この機構
  // (actionFlagRejection)を通らない — あちらでは「そのコマンドが取らない
  // オプション」= 未宣言として構造的に落ちる(effect-cli.test.ts)。
  // gunshi に残るコマンドのうち、車両には audit を使う(server / invite は移行済み)
  it("相手の操作専用のオプションは黙って捨てずに落ちる", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["audit", "verify", "--limit", "5"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--limit は audit verify では使えません");
    expect(server.requests).toHaveLength(0);
  });

  it("操作が不明なら適用可否は語らない(操作の誤りをコマンド本体が報告する)", async () => {
    const { env } = await startEnv();

    // 打ち間違いは実行の失敗(1)ではなく usage エラー(2)
    expect(await runCli(["audit", "bogus", "--event", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明な操作です");
  });
});

describe("空の値", () => {
  it("`default` を付けても空の値の検知が消えない(トークンで判定する)", () => {
    // `ctx.values` が undefined かどうかで見ると、そのオプションに default を
    // 足した瞬間に空の値が既定へ解決され、検知が黙って消える
    const rejection = argsRejection(
      checkContext({
        args: { env: { type: "string" } },
        tokens: [
          { kind: "option", name: "env", rawName: "--env" },
          { kind: "positional", value: "" },
        ],
        values: { env: "dev" },
      }),
    );
    expect(rejection).toContain("オプション --env の値が空です");
  });
  it("構造的な誤りは、その操作で使えるかより先に言う", async () => {
    const { env } = await startEnv();

    // 適用可否(--limit は verify 用ではない)を先に出すと、そこを直した次の
    // 実行で「空の引数」で落ちる = 2 度手間になる
    expect(await runCli(["audit", "verify", "", "--limit", "5"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("空の引数があります");
    expect(errors).not.toContain("使えません");
  });

  it("`--` より前にコマンド名が無い実行は、pull も復号もせずに落ちる", async () => {
    const { env, server } = await startEnv();

    // gunshi は `--` を跨いでコマンドを解決するため、`maruhi -- run printenv`
    // は run として解決され、コマンド名そのものが実行対象として渡る
    expect(await runCli(["--", "run", "printenv"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("コマンド名は `--` より前に書いてください");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });
});

describe("gunshi 由来の usage エラー", () => {
  it("型の合わない値は、与えられた値を出さずに拒否する", async () => {
    const { env } = await startEnv();

    // 期待する型は宣言(引数表)由来なので出してよいが、与えられた値
    // (values.actual)は平文が混ざりうるので出さない
    expect(await runCli(["login", "--github-poll-interval", "s3cr3t"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("オプション --github-poll-interval の値が number として読めません");
    expect(errors).not.toContain("s3cr3t");
  });

  it("パーサ内部の例外は打ち間違いとして報告しない", async () => {
    const { env } = await startEnv();

    // 値の無い number オプションで gunshi 自身が TypeError を投げる。これは
    // バグであって書き方の誤りではないので、usage エラー(2)に化けさせず
    // 内部エラー(1)として報告する(無言で飲まない — CLAUDE.md)
    expect(await runCli(["login", "--github-poll-interval"], env.layer)).toBe(1);
    // 型の名前だけを添える(message は出さない)。部分一致だと元の
    // `内部エラー: <上流の message>` にも当たってしまうので厳密に固定する
    expect(env.errors.join("\n")).toContain("内部エラー(TypeError)");
  });

  it("未知のコマンドは日本語で落ち、使えるコマンドを示す", async () => {
    const { env } = await startEnv();

    expect(await runCli(["bogus"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なコマンドです(使えるコマンド:");
    // エントリコマンドは自分自身の名前でも登録されている。`maruhi maruhi` を
    // サブコマンドとして勧めない(余分な引数の文面と揃える)
    expect(errors).not.toContain("maruhi project");
  });

  it("コマンド名の位置に値を書いた形も綴りを出さない", async () => {
    const { env } = await startEnv();

    expect(await runCli(["s3cr3t/value=with-symbols"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なコマンドです");
    expect(errors).not.toContain("s3cr3t");
  });

  it("長いオプション名の打ち間違いも候補として案内する", async () => {
    const { env } = await startEnv();

    // `--github-client-id` の 1 字違い。候補の語彙に長さの上限を設けると、
    // 自分のオプションの打ち間違いが案内できなくなる
    expect(await runCli(["login", "--github-client-idd", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "不明なオプションです(--github-client-id のことですか?)",
    );
  });

  it("隠しオプション(hidden)は候補に出さない", async () => {
    const { env } = await startEnv();

    // gunshi の usage が出さない内部向けの綴りを、打ち間違いの案内で広めない
    expect(await runCli(["login", "--github-poll-intervall", "3"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("--github-poll-interval");
    expect(errors).not.toContain("--github-base-url");
    expect(errors).toContain("このコマンドが取るオプション:");
  });

  it("エントリコマンドの二重名(`maruhi maruhi`)を文面に出さない", async () => {
    const { env } = await startEnv();

    // エントリコマンドは自分自身の名前でもサブコマンドとして登録されている
    expect(await runCli(["maruhi", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi は位置引数を取りません");
    expect(errors).not.toContain("maruhi maruhi");
  });
});

/** gunshi の CommandContext のうち、検査が見る部分だけを組む(単体検査用)。 */
function checkContext(input: {
  readonly args: Record<
    string,
    { readonly type?: string; readonly short?: string; readonly negatable?: boolean }
  >;
  readonly tokens: readonly {
    kind: string;
    name?: string;
    rawName?: string;
    value?: string;
    inlineValue?: boolean;
  }[];
  readonly positionals?: readonly string[];
  readonly values?: Readonly<Record<string, unknown>>;
}) {
  return {
    args: input.args,
    tokens: input.tokens,
    positionals: input.positionals ?? ["demo"],
    values: input.values ?? {},
    commandPath: ["demo"],
  };
}

describe("引数検査の単体(CLI に短縮形が現れる前の防衛)", () => {
  it("短縮形 boolean へのインライン値(`-s=false`)も拒否する", () => {
    // args-tokens は `-s=false` を「名前つきトークン」+「**名前なしの**
    // インライン値トークン」に割る(実測)。名前で引くだけの検査は素通りし、
    // `--show=false` と同じ「書いたことと逆」がそのまま通る
    const rejection = argsRejection(
      checkContext({
        args: { show: { type: "boolean", short: "s" } },
        tokens: [
          { kind: "option", name: "s", rawName: "-s" },
          { kind: "option", inlineValue: true },
        ],
      }),
    );
    expect(rejection).toContain("-s は値を取りません");
  });

  it("negatable な boolean は有効 / 無効の両方の書き方を案内する", () => {
    // CLI 水準の車両(env rotate --new-epoch)は effect/unstable/cli へ移った
    // ので、negatable の文面と否定形の綴りは単体で固定する(gunshi へ negatable
    // を再導入したときに案内が欠ける形を防ぐ)
    const inline = argsRejection(
      checkContext({
        args: { "new-epoch": { type: "boolean", negatable: true } },
        tokens: [
          {
            kind: "option",
            name: "new-epoch",
            rawName: "--new-epoch",
            value: "false",
            inlineValue: true,
          },
        ],
      }),
    );
    expect(inline).toContain("--new-epoch は値を取りません");
    expect(inline).toContain("無効にするなら --no-new-epoch と、いずれも値なしで");
  });

  it("否定形の綴り(`--no-x=false` / `--no-x off`)も boolean の検査に掛かる", () => {
    // negatable を宣言すると綴りが増える。増えた綴りを検査の表へ入れ忘れると、
    // 塞いだはずの形(値の指定・空きスロットへの吸い込み)がそこから復活する
    const inline = argsRejection(
      checkContext({
        args: { "new-epoch": { type: "boolean", negatable: true } },
        tokens: [
          {
            kind: "option",
            name: "no-new-epoch",
            rawName: "--no-new-epoch",
            value: "false",
            inlineValue: true,
          },
        ],
      }),
    );
    expect(inline).toContain("--no-new-epoch は値を取りません");
    const spaced = argsRejection(
      checkContext({
        args: { "new-epoch": { type: "boolean", negatable: true } },
        tokens: [
          { kind: "option", name: "no-new-epoch", rawName: "--no-new-epoch" },
          { kind: "positional", value: "off" },
        ],
      }),
    );
    expect(spaced).toContain("--no-new-epoch は値を取りません");
  });

  it("boolean の短縮形と同じ名前を持つ別のオプションを boolean 扱いしない", () => {
    // 長い名前と短縮形を 1 つの集合に混ぜると、`--h=x`(string の長い名前が
    // `h`)が boolean `--help` の短縮形 `-h` と衝突して誤って拒否される
    const rejection = argsRejection(
      checkContext({
        args: { h: { type: "string" }, help: { type: "boolean", short: "h" } },
        tokens: [{ kind: "option", name: "h", rawName: "--h", value: "x", inlineValue: true }],
      }),
    );
    expect(rejection).toBeNull();
  });

  it("短縮形 boolean の空白区切りの値も余分な位置引数として拒否する", () => {
    const rejection = argsRejection(
      checkContext({
        args: { show: { type: "boolean", short: "s" } },
        tokens: [{ kind: "option", name: "s", rawName: "-s" }],
        positionals: ["demo", "false"],
      }),
    );
    expect(rejection).toContain("余分な引数です(1 個");
    expect(rejection).toContain("boolean オプションに値は付けられません");
  });

  it("同じオプションの重複は、綴りが違っても(短縮形・否定形)拾う", () => {
    // 短縮形と長い綴りは同じオプション。別物として数えると、
    // `maruhi push K -e prod --env dev` が黙って片方だけへ書き込む
    const short = argsRejection(
      checkContext({
        args: { env: { type: "string", short: "e" } },
        tokens: [
          { kind: "option", name: "e", rawName: "-e", value: "prod" },
          { kind: "option", name: "env", rawName: "--env", value: "dev" },
        ],
      }),
    );
    expect(short).toContain("オプション --env を複数回指定しています");
    // 打たれた値は診断に出さない
    expect(short).not.toContain("prod");

    const negated = argsRejection(
      checkContext({
        args: { show: { type: "boolean", negatable: true } },
        tokens: [
          { kind: "option", name: "no-show", rawName: "--no-show" },
          { kind: "option", name: "show", rawName: "--show" },
        ],
      }),
    );
    expect(negated).toContain("否定形 --no-show も同じオプションです");
  });

  it("同じ値の重複でも落とす(値を判断材料にしない)", () => {
    // 「同じ値なら通す」にすると、打たれた値によって結果が変わる検査になる。
    // 重複していること自体を言えば、どちらを消しても直る
    const rejection = argsRejection(
      checkContext({
        args: { env: { type: "string" } },
        tokens: [
          { kind: "option", name: "env", rawName: "--env", value: "dev" },
          { kind: "option", name: "env", rawName: "--env", value: "dev" },
        ],
      }),
    );
    expect(rejection).toContain("オプション --env を複数回指定しています");
  });

  it("重複の検査は `--` の手前で打ち切る(その先は子プロセスの引数)", () => {
    // gunshi 側に残るコマンドは `--` の後ろを読まないので、この形は
    // 「`--` の後ろの引数を取りません」で落ちる。**重複の指摘にはならない**
    // (打ち切りを忘れると、子プロセスへ渡すつもりの引数を maruhi のものとして
    // 数えることになる)
    const rejection = argsRejection(
      checkContext({
        args: { env: { type: "string" } },
        tokens: [
          { kind: "positional", value: "demo" },
          { kind: "option-terminator" },
          { kind: "positional", value: "cmd" },
          { kind: "option", name: "env", rawName: "--env", value: "a" },
          { kind: "option", name: "env", rawName: "--env", value: "b" },
        ],
      }),
    );
    expect(rejection).toContain("`--` の後ろの引数を取りません");
    expect(rejection).not.toContain("複数回指定");
  });

  it("未宣言の綴り(グローバル含む)の重複はこの検査の担当外", () => {
    // `--help` / `--version` は引数表に無い(gunshi が実行時に混ぜる)。
    // 宣言名で引けない綴りを数えると、綴りごとに別物として数えることになり
    // 一貫しない — 未宣言は strict と gunshi の担当
    const rejection = argsRejection(
      checkContext({
        args: { env: { type: "string" } },
        tokens: [
          { kind: "option", name: "help", rawName: "--help" },
          { kind: "option", name: "help", rawName: "--help" },
        ],
      }),
    );
    expect(rejection).toBeNull();
  });
});
