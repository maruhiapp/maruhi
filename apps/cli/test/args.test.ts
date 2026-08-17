// 引数の**書き方**の検査(src/args.ts + gunshi の `CliOptions.strict`)。
//
// **対象は gunshi に残っているコマンド = login / logout とエントリコマンド**
// (ADR-0016 の第 1〜3 段階で他の全コマンドは effect/unstable/cli へ移した。
// 移行先の同型検査は effect-cli.test.ts)。CLI 水準で残るのは未宣言オプション・
// 未知コマンドの診断と、hidden オプションの扱い。boolean・重複・空の値の
// 検査は args.ts の単体検査で固定する(gunshi 廃止まで規則が生きていることの
// 確認 — 最終コミットで effect 側の宣言由来の検査だけが残る)。

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
