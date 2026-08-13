// 引数の**書き方**の検査(src/args.ts + gunshi の `CliOptions.strict`)。
//
// gunshi 0.37.1 が黙って通し、**書いたことと逆の結果**になる 4 形を全コマンドで
// 塞ぐ:
//
// 1. 未宣言オプション(`pull --shwo` が `--show` なしで実行される)
// 2. boolean へのインライン値(`--show=false` は値を読まずに true)
// 3. boolean への空白区切りの値(`--show false` = フラグ有効 + 余分な位置引数)
// 4. 位置引数の名前のオプション化(`env create dev --environment-id prod` は
//    値が捨てられ dev を作る)
//
// いずれも**コマンド本体より前**に落ちること(通信も復号も設定書き込みも
// 起きないこと)まで固定する — 最悪形は `pull --show=false` で、通してしまうと
// 全シークレットが端末に出る。

import { afterEach, describe, expect, it, vi } from "vitest";

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
  it("`pull --show=false` は値を表示せず usage エラーで落ちる(復号にも通信にも進まない)", async () => {
    const { env, server } = await startEnv();

    // gunshi は boolean のインライン値を**読まずに true** にするため、
    // 通すと「表示しない」と書いた実行が全シークレットを端末に出す
    expect(await runCli(["pull", "--show=false"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--show は値を取りません");
    expect(env.errors.join("\n")).toContain("無効にするならオプション自体を外してください");
    expect(server.requests).toHaveLength(0);
    expect(env.logs).toHaveLength(0);
  });

  it("`pull --show false` は「フラグ有効 + 余分な位置引数」なので余分な引数として落ちる", async () => {
    const { env, server } = await startEnv();

    // 空白区切りの値は gunshi が消費しない(--show は true のまま、"false" が
    // 位置引数として残る)
    expect(await runCli(["pull", "--show", "false"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です: false");
    expect(errors).toContain("maruhi pull は位置引数を取りません");
    // boolean を書いた実行なので、値を付けられない旨の助言を添える
    expect(errors).toContain("boolean オプションに値は付けられません");
    expect(server.requests).toHaveLength(0);
    expect(env.logs).toHaveLength(0);
  });

  it("string オプションのインライン値(`--env=ghost`)は拒否しない", async () => {
    const { env } = await startEnv();

    // boolean だけの検査であることの確認(= 誤検知で正当な書き方を塞がない)。
    // 環境 ID の形式検査(コマンド本体)まで進んで別の理由で落ちる
    expect(await runCli(["pull", "--env=ghost"], env.layer)).not.toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("値を取りません");
    expect(errors).not.toContain("余分な引数です");
  });
});

describe("未宣言オプション(strict)", () => {
  it("`pull --shwo` は黙って `--show` なしで実行されず、usage エラーになる", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです: --shwo");
    expect(server.requests).toHaveLength(0);
  });

  it("`push --enve prod` は既定環境への書き込みに化けず、usage エラーになる", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // 綴り間違いを無視すると、prod のつもりの push が既定環境(config の
    // defaultEnvironment)へ入る。書き込みは取り消せない
    expect(await runCli(["push", "API_KEY", "--enve", "prod"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです: --enve");
    expect(server.requests).toHaveLength(0);
  });

  it("短縮形は打ったとおりの綴りで返す(`-q` を `--q` と書き換えない)", async () => {
    const { env } = await startEnv();

    expect(await runCli(["pull", "-q"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです: -q");
    expect(env.errors.join("\n")).not.toContain("--q");
  });

  it("プロトタイプ由来の名前(`--constructor`)でも未宣言として落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["pull", "--constructor=x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです: --constructor");
  });

  it("未宣言オプションが複数あればすべて報告する", async () => {
    const { env } = await startEnv();

    expect(await runCli(["pull", "--shwo", "--prj", "x"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なオプションです: --shwo");
    expect(errors).toContain("不明なオプションです: --prj");
  });

  it("エントリコマンド(`maruhi --shwo`)でも落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["--shwo"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです: --shwo");
    expect(env.logs).toHaveLength(0);
  });

  it("gunshi 自身の描画は使わない(診断は stdout ではなく stderr の 1 経路)", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.errors.join("\n")).toContain("不明なオプションです: --shwo");
  });
});

describe("位置引数の名前のオプション化", () => {
  it("`env create dev --environment-id prod` は値を捨てずに落ち、専用の案内を出す", async () => {
    const { env, server } = await startEnv();

    // gunshi は値を捨てるため、通すと dev が作られる。環境 ID は
    // チェーン履歴全体で一意(§6.2)なので取り違えは永久に焼き付く
    expect(await runCli(["env", "create", "dev", "--environment-id", "prod"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id は位置引数です");
    expect(env.errors.join("\n")).toContain("値は位置引数として並べてください");
    expect(server.requests).toHaveLength(0);
  });

  it("env 以外でも同じ(`push --name API_KEY` は変数名の取り違えとして落ちる)", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    expect(await runCli(["push", "--name", "API_KEY"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--name は位置引数です");
    expect(server.requests).toHaveLength(0);
  });

  it("位置引数を書かずにオプションだけで渡した実行も落ちる(既定環境へ滑り込まない)", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["env", "rotate", "--environment-id", "prod"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id は位置引数です");
    expect(server.requests).toHaveLength(0);
  });
});

describe("操作に適用されないオプション(env 固有)", () => {
  it("相手の操作専用のオプションは黙って捨てずに落ちる(両方向)", async () => {
    const { env, server } = await startEnv();

    // gunshi は 1 コマンド 1 引数表なので create / rotate 両方のフラグが常に
    // 受理される。指定した意図が無視されたことに気付けるようにする
    expect(await runCli(["env", "create", "dev", "--reason", "x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--reason は env create では使えません");
    expect(await runCli(["env", "create", "dev", "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--new-epoch は env create では使えません");
    expect(await runCli(["env", "rotate", "dev", "--name", "n"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--name は env rotate では使えません");
    expect(server.requests).toHaveLength(0);
  });

  it("操作が不明なら適用可否は語らない(操作の誤りをコマンド本体が報告する)", async () => {
    const { env } = await startEnv();

    expect(await runCli(["env", "bogus", "dev", "--reason", "x"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("不明な操作です: bogus");
  });
});

describe("余分な位置引数", () => {
  it("位置引数を取るコマンド(`key generate extra`)は宣言名を示して落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["key", "generate", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です: extra");
    expect(errors).toContain("maruhi key が取る位置引数は action だけです");
    // boolean を書いていない実行に boolean の助言は添えない(コマンドラインに
    // 無いオプションを探させることになる)
    expect(errors).not.toContain("boolean オプションに値は付けられません");
  });

  it("`maruhi run npm test`(`--` 忘れ)は書き方を案内して落ち、子プロセスを起動しない", async () => {
    const { env, server } = await startEnv();

    expect(await runCli(["run", "npm", "test"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です: npm test");
    expect(errors).toContain("`--` の後に並べてください");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("`--` の後ろを読まないコマンドでは、その引数も黙って捨てずに落ちる", async () => {
    const { env, server } = await startEnv();

    // `ctx.rest` を読むのは run だけ。他コマンドでは位置引数にも values にも
    // 現れないまま消えるので、余分な引数として扱う
    expect(await runCli(["push", "API_KEY", "--", "value"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です: value");
    expect(errors).toContain("maruhi push は `--` の後ろの引数を取りません");
    expect(server.requests).toHaveLength(0);
  });

  it("`config set` の余分な引数は設定を書き換えずに落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["config", "set", "defaultEnvironment", "dev", "extra"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("余分な引数です: extra");
    // 設定は書き換わっていない(検査がコマンド本体より前で効いている)
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(env.logs).toContain("prod");
  });
});

describe("gunshi 由来の usage エラー", () => {
  it("必須位置引数の欠落は空メッセージにならない(内訳を stderr へ出す)", async () => {
    const { env } = await startEnv();

    expect(await runCli(["env", "rotate"], env.layer)).toBe(2);
    // AggregateError.message は空になりうるので、内訳から作る
    expect(env.errors.join("\n").trim()).not.toBe("maruhi:");
    expect(env.errors.join("\n")).toContain("environment-id");
  });

  it("未知のコマンドは gunshi のメッセージで落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("bogus");
  });
});
