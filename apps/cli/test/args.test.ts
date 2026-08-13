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
    expect(errors).toContain("余分な引数です(1 個");
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

    // 未宣言オプションは priority エラー(ヘッダ描画より前に throw する)
    expect(await runCli(["pull", "--shwo"], env.layer)).toBe(2);
    // 必須位置引数の欠落は priority ではない = ヘッダ描画の経路を通る
    expect(await runCli(["env", "rotate"], env.layer)).toBe(2);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.errors.join("\n")).toContain("不明なオプションです: --shwo");
  });

  it("成功した実行の stdout はコマンドの出力だけ(バナーを混ぜない)", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // `V=$(maruhi config get server)` がバナーを捕まえないこと
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.logs).toEqual(["prod"]);
  });

  it("値がオプションに化けた形は綴りを復元して出さない(短縮グループの展開)", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // `-hunter2` は短縮オプションのグループとして 1 文字ずつのトークンへ
    // 展開される(`-h -u -n -t -e -r -2`)。綴りをそのまま返すと、拒否の診断が
    // 平文を 1 文字ずつ並べて書き出すことになる
    expect(await runCli(["push", "API_KEY", "-hunter2"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("綴りは表示しません");
    expect(errors).not.toContain("-u");
    expect(errors).not.toContain("-n");
    expect(errors).not.toContain("-2");
    // 同じ伏せ字が 7 行並ばないこと(重複は畳む)
    expect(errors.split("\n").filter((line) => line.includes("不明なオプション"))).toHaveLength(1);
  });

  it("値らしい綴り(数字や _ を含む)は、`--` を付けて書かれても出さない", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // 診断へ返してよいのは maruhi のオプション名の語彙(英字とハイフン)だけ。
    // `--sk_live_ab12` のような綴りは打ち間違いではなく値である可能性が高い
    expect(await runCli(["push", "API_KEY", "--sk_live_ab12"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("綴りは表示しません");
    expect(errors).not.toContain("sk_live");
  });

  it("値がオプションに化けた形は綴りを復元して出さない(長いオプション名)", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // `-----BEGIN...` は 1 つの長いオプション名として読まれる
    expect(await runCli(["push", "API_KEY", "-----BEGIN-RSA-PRIVATE-KEY-hunter2"], env.layer)).toBe(
      2,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("綴りは表示しません");
    expect(errors).not.toContain("BEGIN");
    expect(errors).not.toContain("hunter2");
  });

  it("コマンド名の綴り間違いでは、正しく綴られたオプションを不明扱いしない", async () => {
    const { env } = await startEnv();

    // 未解決のコマンドではエントリコマンドの引数表と突き合わされるため、
    // 綴りの合っている --show まで不明として並ぶ(探させない)
    expect(await runCli(["pul", "--show"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なコマンドです: pul");
    expect(errors).not.toContain("不明なオプションです");
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

  it("その操作で使えないオプションは、書き方の助言より先に言う", async () => {
    const { env } = await startEnv();

    // 綴りの助言(値なしで --new-epoch と書け)を先に出すと、そのとおり直した
    // 次の実行が「create では使えません」で落ちる = 2 度手間になる
    expect(await runCli(["env", "create", "dev", "--new-epoch=false"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("--new-epoch は env create では使えません");
    expect(errors).not.toContain("値を取りません");
  });
});

describe("端末出力の中和", () => {
  it("設定キー・操作名の制御文字は表示前に中和する", async () => {
    const { env } = await startEnv();

    // 行を消して偽の成功行を書くような ANSI 列を、そのまま端末へ流さない
    const evil = "[2K\rmaruhi: OK";
    expect(await runCli(["config", "get", evil], env.layer)).toBe(1);
    expect(await runCli(["config", evil, "server"], env.layer)).toBe(1);
    expect(await runCli(["key", evil], env.layer)).toBe(1);
    expect(await runCli(["project", evil], env.layer)).toBe(1);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("");
    expect(output).not.toContain("\r");
  });
});

describe("余分な位置引数", () => {
  it("拒否した引数の**中身**は診断に出さない(平文の値が混ざりうる)", async () => {
    const { env } = await startEnv();
    // `push` の値は stdin から読むので、コマンドラインに書いた値は「余分な
    // 引数」になる。打ち間違いを教えるために平文を書き出すと、CI や
    // エージェントのログへ残る = この PR が塞ぐ漏洩と同種になる
    const secret = "hunter2-plaintext-value";
    env.setStdin(new TextEncoder().encode("secret-value"));

    expect(await runCli(["push", "API_KEY", secret], env.layer)).toBe(2);
    expect(await runCli(["push", "API_KEY", "--", secret], env.layer)).toBe(2);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain(secret);
    // 個数と形は出す(打ち間違いの位置は分かる)
    expect(output).toContain("余分な引数です(1 個");
    expect(output).toContain("中身は表示しません");
  });

  it("位置引数を取るコマンド(`key generate extra`)は宣言名を示して落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["key", "generate", "extra"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("maruhi key が取る位置引数は action だけです");
    // boolean を書いていない実行に boolean の助言は添えない(コマンドラインに
    // 無いオプションを探させることになる)
    expect(errors).not.toContain("boolean オプションに値は付けられません");
  });

  it("`maruhi run npm test`(`--` 忘れ)は書き方を案内して落ち、子プロセスを起動しない", async () => {
    const { env, server } = await startEnv();

    // 実行対象が `--` の後ろに無いので、まず「どこへ書くか」を案内する
    expect(await runCli(["run", "npm", "test"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("実行するコマンドを `--` の後に指定してください");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("`--` の前に置いた余分な引数は、実行対象があっても落とす", async () => {
    const { env, server } = await startEnv();

    // 実行対象はあるので「`--` の後に書け」ではなく、余分な引数として拒否する
    expect(await runCli(["run", "stray", "--", "printenv"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("`--` の後に並べてください");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server.requests).toHaveLength(0);
  });

  it("`push` の余分な引数には値の渡し方を添える(中身を出さない代わりの案内)", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    expect(await runCli(["push", "API_KEY", "plaintext"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("値は stdin から読みます");
    expect(errors).not.toContain("plaintext");
  });

  it("`--` の後ろの空文字列は余分な引数として数えない", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // gunshi は `--` の後ろの空文字列を rest ではなく positionals へ入れる。
    // 素直に数えると `run -- cmd ""` のような正当な実行を誤って拒否する
    expect(await runCli(["push", "API_KEY", "--", ""], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi push は `--` の後ろの引数を取りません");
    expect(errors).not.toContain("位置引数は name だけです");
    expect(server.requests).toHaveLength(0);
  });

  it("`--` の後ろを読まないコマンドでは、その引数も黙って捨てずに落ちる", async () => {
    const { env, server } = await startEnv();

    // `ctx.rest` を読むのは run だけ。他コマンドでは位置引数にも values にも
    // 現れないまま消えるので、余分な引数として扱う
    expect(await runCli(["push", "API_KEY", "--", "value"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("maruhi push は `--` の後ろの引数を取りません");
    expect(server.requests).toHaveLength(0);
  });

  it("`config get` の余分な引数は optional の value に吸われずに落ちる", async () => {
    const { env } = await startEnv();

    // value は set 専用の optional positional。共通検査は引数表の**最大数**しか
    // 知らないため、get への余分なトークンはそこへ黙って束縛される
    expect(await runCli(["config", "get", "defaultEnvironment", "dev"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("maruhi config が取る位置引数は action key だけです");
    expect(env.logs).toHaveLength(0);
  });

  it("余分な引数が複数でも、個数と get の取る形を正しく言う", async () => {
    const { env } = await startEnv();

    // 操作ごとの差を共通検査へ伝えていないと、引数表の最大数で数えた結果
    // 「1 個」と過少報告し、get が取らない value を取れるかのように案内する
    expect(await runCli(["config", "get", "defaultEnvironment", "a", "b"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(2 個");
    expect(errors).toContain("maruhi config が取る位置引数は action key だけです");
    expect(errors).not.toContain("value");
  });

  it("`config set` の余分な引数は設定を書き換えずに落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["config", "set", "defaultEnvironment", "dev", "extra"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("余分な引数です(1 個");
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
    expect(env.errors.join("\n")).toContain("位置引数 environment-id を指定してください");
  });

  it("型の合わない値は、与えられた値を出さずに拒否する", async () => {
    const { env } = await startEnv();

    // 期待する型は宣言(引数表)由来なので出してよいが、与えられた値
    // (values.actual)は平文が混ざりうるので出さない
    expect(await runCli(["login", "--github-poll-interval", "s3cr3t"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("オプション --github-poll-interval の値が number として読めません");
    expect(errors).not.toContain("s3cr3t");
  });

  it("未知のコマンドは日本語で落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なコマンドです: bogus");
  });

  it("コマンド名の位置に値を書いた形は綴りを出さない", async () => {
    const { env } = await startEnv();

    expect(await runCli(["s3cr3t/value=with-symbols"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なコマンドです(綴りは表示しません");
    expect(errors).not.toContain("s3cr3t");
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
  readonly args: Record<string, { readonly type?: string; readonly short?: string }>;
  readonly tokens: readonly {
    kind: string;
    name?: string;
    rawName?: string;
    inlineValue?: boolean;
  }[];
  readonly positionals?: readonly string[];
}) {
  return {
    args: input.args,
    tokens: input.tokens,
    positionals: input.positionals ?? ["demo"],
    rest: [],
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

  it("boolean の短縮形と同じ名前を持つ別のオプションを boolean 扱いしない", () => {
    // 長い名前と短縮形を 1 つの集合に混ぜると、`--h=x`(string の長い名前が
    // `h`)が boolean `--help` の短縮形 `-h` と衝突して誤って拒否される
    const rejection = argsRejection(
      checkContext({
        args: { h: { type: "string" }, help: { type: "boolean", short: "h" } },
        tokens: [{ kind: "option", name: "h", rawName: "--h", inlineValue: true }],
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
});
