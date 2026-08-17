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
  it("`push --enve prod` は既定環境への書き込みに化けず、usage エラーになる", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // 綴り間違いを無視すると、prod のつもりの push が既定環境(config の
    // defaultEnvironment)へ入る。書き込みは取り消せない
    expect(await runCli(["push", "API_KEY", "--enve", "prod"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです(--env のことですか?)");
    expect(server.requests).toHaveLength(0);
  });

  it("短縮形には見当違いの「もしかして」を出さず、取りうるオプションを示す", async () => {
    const { env } = await startEnv();

    // `-q` を `--q` に見立てて距離を測ると、無関係な長いオプションが候補に出る
    expect(await runCli(["push", "API_KEY", "-q"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    // 一覧には実行時のグローバル(引数表に現れない `--help` / `--version`)も含める
    expect(errors).toContain(
      "このコマンドが取るオプション: --env --help --project --server --version",
    );
    expect(errors).not.toContain("のことですか?");
  });

  it("候補にはグローバル(`--help`)も含める", async () => {
    const { env } = await startEnv();

    // 引数表(define の args)にはグローバルが現れない。gunshi がエラーへ
    // 載せた候補を使わないと、実在するオプションが候補から抜ける
    expect(await runCli(["push", "API_KEY", "--hepl"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--help のことですか?");
  });

  it("プロトタイプ由来の名前(`--constructor`)でも未宣言として落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["push", "API_KEY", "--constructor=x"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです");
    expect(env.errors.join("\n")).not.toContain("--constructor");
  });

  it("未宣言オプションが複数あれば、それぞれの候補を報告する", async () => {
    const { env } = await startEnv();

    expect(await runCli(["push", "API_KEY", "--enve", "x", "--prj", "y"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    // 近い綴りには候補を、遠い綴りには一覧を出す(それぞれ別の行になる)
    expect(errors).toContain("--env のことですか?");
    expect(errors).toContain("このコマンドが取るオプション:");
    expect(errors.split("\n")).toHaveLength(2);
  });

  it("エントリコマンド(`maruhi --shwo`)でも落ちる", async () => {
    const { env } = await startEnv();

    expect(await runCli(["--shwo"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプションです");
    expect(env.logs).toHaveLength(0);
  });

  it("gunshi 自身の描画は使わない(診断は stdout ではなく stderr の 1 経路)", async () => {
    const { env } = await startEnv();
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});

    // 未宣言オプションは priority エラー(ヘッダ描画より前に throw する)
    expect(await runCli(["push", "API_KEY", "--enve", "x"], env.layer)).toBe(2);
    // 必須位置引数の欠落は priority ではない = ヘッダ描画の経路を通る
    expect(await runCli(["env", "rotate"], env.layer)).toBe(2);
    expect(stdout).not.toHaveBeenCalled();
    expect(env.errors.join("\n")).toContain("不明なオプションです");
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
    expect(errors).toContain("不明なオプションです");
    expect(errors).not.toContain("-u");
    expect(errors).not.toContain("-n");
    expect(errors).not.toContain("-2");
    // 同じ文面が 7 行並ばないこと(重複は畳む)
    expect(errors.split("\n").filter((line) => line.includes("不明なオプション"))).toHaveLength(1);
  });

  it("値らしい綴り(数字や _ を含む)は、`--` を付けて書かれても出さない", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // 診断へ返してよいのは maruhi のオプション名の語彙(英字とハイフン)だけ。
    // `--sk_live_ab12` のような綴りは打ち間違いではなく値である可能性が高い
    expect(await runCli(["push", "API_KEY", "--sk_live_ab12"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("不明なオプションです");
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
    expect(errors).toContain("不明なオプションです");
    expect(errors).not.toContain("BEGIN");
    expect(errors).not.toContain("hunter2");
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

describe("位置引数の名前のオプション化", () => {
  it("`push --name API_KEY` は変数名の取り違えとして落ちる", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    expect(await runCli(["push", "--name", "API_KEY"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--name は位置引数です");
    expect(server.requests).toHaveLength(0);
  });
});

describe("操作に適用されないオプション(gunshi に残るコマンド)", () => {
  // env は effect/unstable/cli の入れ子サブコマンドへ移したので、この機構
  // (actionFlagRejection)を通らない — あちらでは「そのコマンドが取らない
  // オプション」= 未宣言として構造的に落ちる(effect-cli.test.ts)。
  // gunshi に残る server / invite / member / audit のうち、車両には audit を使う
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
  it('空のオプション値(`--env ""`)は既定へフォールバックさせず落とす', async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // gunshi は空の値を「未指定」に潰すため、`--env "$ENV"` の未設定形が
    // **既定環境への書き込み**に化ける(取り消せない)
    expect(await runCli(["push", "API_KEY", "--env", ""], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("オプション --env の値が空です");
    expect(await runCli(["push", "API_KEY", "--project="], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("オプション --project の値が空です");
    expect(server.requests).toHaveLength(0);
  });

  it('空の位置引数(`config set server ""`)は設定を空で上書きしない', async () => {
    const { env } = await startEnv();

    // 位置引数は空文字列のまま束縛される(オプションと違って undefined へ
    // 落ちない)ため、`config set defaultProject "$PROJ"` の未設定形が
    // 既存の設定を消して成功を報告していた
    expect(await runCli(["config", "set", "defaultEnvironment", ""], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("位置引数 value が空です");
    expect(await runCli(["config", "get", "defaultEnvironment"], env.layer)).toBe(0);
    expect(env.logs).toContain("prod");
  });

  it("空白だけのオプション値も空として扱う", async () => {
    const { env, server } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // 位置引数側だけ trim していると、`--env "$ENV"` の未設定形が空白だけの
    // 環境指定として既定へ潰れず、誤った先へ書き込まれる(取り消せない)
    expect(await runCli(["push", "API_KEY", "--env", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("オプション --env の値が空です");
    expect(server.requests).toHaveLength(0);
  });

  it("空白だけの値も空として扱う(設定の上書き)", async () => {
    const { env, server } = await startEnv();

    // `"$PROJ"` の未設定形は `""` にも `" "` にもなる。片方だけ塞ぐと
    // 設定が空白で上書きされ、以後のコマンドが無関係なエラーで落ち続ける
    // (実行対象側の空白は units.test.ts の runOp と effect-cli.test.ts が固定)
    expect(await runCli(["config", "set", "defaultEnvironment", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("位置引数 value が空です");
    expect(server.requests).toHaveLength(0);
  });

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

  it("先頭の空引数は、書いていない位置引数のせいにせず空として指摘する", async () => {
    const { env } = await startEnv();

    // gunshi はコマンド解決で falsy な位置引数を読み飛ばす。そのまま数えると
    // 全体が 1 つずれて「key は位置引数を取りません」と無関係な指摘になる
    expect(await runCli(["", "key", "show"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("空の引数があります");
    expect(errors).not.toContain("位置引数を取りません");
  });

  it("この実行が取らない位置引数(`config get` の value)を名指ししない", async () => {
    const { env } = await startEnv();

    // 空の値の指摘でも、その操作が取らない位置引数の名前を出さない
    expect(await runCli(["config", "get", "defaultEnvironment", ""], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("位置引数 value が空です");
    expect(errors).toContain("空の引数があります");
  });

  it("`--` の後ろの空文字列は、書いていない位置引数のせいにしない", async () => {
    const { env } = await startEnv();
    env.setStdin(new TextEncoder().encode("secret-value"));

    // `push -- ""` の "" は位置引数 name として束縛されるが、ユーザーが
    // 書いたのは `--` の後ろ。そちらを指摘する
    expect(await runCli(["push", "--", ""], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("maruhi push は `--` の後ろの引数を取りません");
    expect(errors).not.toContain("位置引数 name が空です");
  });

  it("構造的な誤りは、その操作で使えるかより先に言う", async () => {
    const { env } = await startEnv();

    // 適用可否(--fingerprint は revoke 用)を先に出すと、そこを直した次の
    // 実行で「空の引数」で落ちる = 2 度手間になる
    expect(
      await runCli(
        ["server", "grant", "", "--fingerprint", "aaaabbbbccccddddeeeeffff00001111"],
        env.layer,
      ),
    ).toBe(2);
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

describe("終了コードの一貫性", () => {
  it("操作の綴り間違いは、ログインやサーバー接続より前に落とす", async () => {
    // セッション解決の後ろに置くと、`key bogus` が「ログインしていません」で
    // 落ちて打ち間違いが伝わらない(しかも exit 1)
    const env = await makeTestEnv();
    expect(await runCli(["key", "bogus"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("不明な操作です(generate | show | recover | recovery)");
    expect(env.errors.join("\n")).not.toContain("ログインしていません");
  });

  it("値の無い `config set` も usage エラー(2)", async () => {
    const { env } = await startEnv();

    // gunshi は optional な positional の欠落を検証しない(コマンド本体が見る)。
    // 「書き方の誤りは 2」を、パーサが落とした場合と揃える
    expect(await runCli(["config", "set", "defaultEnvironment"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("設定する値を指定してください");
  });
});

describe("端末出力の中和", () => {
  it("設定キー・操作名は打たれた語を返さない(制御文字も値も端末へ流さない)", async () => {
    const { env } = await startEnv();

    // 行を消して偽の成功行を書くような ANSI 列を含む語。文面は取りうる値の
    // 一覧だけで、打たれた語は出さない(位置引数には値が書かれうる)
    const evil = "\u001b[2K\rmaruhi: OK";
    // 打ち間違い(語が何も指していない)は usage エラー(2)
    expect(await runCli(["config", "get", evil], env.layer)).toBe(2);
    expect(await runCli(["config", evil, "server"], env.layer)).toBe(2);
    expect(await runCli(["key", evil], env.layer)).toBe(2);
    expect(await runCli(["project", evil], env.layer)).toBe(2);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\r");
    expect(output).toContain("不明な設定キーです(server | githubClientId");
    expect(output).toContain("不明な操作です(get | set)");
    expect(output).toContain("不明な操作です(generate | show | recover | recovery)");
    expect(output).toContain("不明な操作です(init | verify)");
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
    // 中身を伏せる以上、直し方は `--` の形でも添える
    expect(errors).toContain("値は stdin から読みます");
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

    expect(await runCli(["push"], env.layer)).toBe(2);
    // AggregateError.message は空になりうるので、内訳から作る
    expect(env.errors.join("\n").trim()).not.toBe("maruhi:");
    expect(env.errors.join("\n")).toContain("位置引数 name を指定してください");
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
