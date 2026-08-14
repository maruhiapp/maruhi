// 環境間パリティチェック(`maruhi env diff`)のテスト。
//
// 固定する不変条件:
//  1. **値を取得しない**: 叩くのは §12-7 のメタデータのみ pull だけで、値 pull
//     (`/pull`)と DEK 配布(`/deks`)には 1 度も触れない(サーバーは
//     `var.read` を記録しない — AUDIT_SPEC §3.3)
//  2. 差分の内容と件数、および**名前でソートされた安定な出力順**
//     (ワイヤの並びを変えても出力が変わらない)
//  3. 変数名は他メンバーが書いた平文メタデータなので ANSI / BEL / 改行を中和し、
//     視覚的に同名でも正規化形が違えば別物として報告する(NFC / NFD)
//  4. 2 環境ぶんの警告は環境 ID でラベルする(文面まで同一の警告が畳まれて
//     片方の事実が消えない)
//  5. **前段は 1 回だけ**(チェーン同期は 1 回)で、1 つ目の pull が有界再同期で
//     前進させたビューを 2 つ目の pull が引き継ぐ
//  6. 環境のメタ水準の床はコミットしない(チェーン床のヘッドだけ前進する)。
//     差分があるときだけ、順に読むことによる標本のずれを stderr で注意書きする
//  7. **master 鍵を要求しない**(復号しないため。MARUHI_TOKEN 経由のセッションでも動く)
//  8. 書き方の誤り(環境 1 つ・同一環境 ID・他操作専用オプション)は
//     usage エラー(2)で、**通信より前**に落ちる

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { reportEnvironmentDiff } from "../src/env-diff.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const DEV = "dev";
const PROD = "prod";

let owner: TestUser;
let chain: BuiltChain;
let devStatement: WireDistributedEnvironmentStatement;
let prodStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  chain = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(DEV, crypto.getRandomValues(new Uint8Array(32))),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(PROD, crypto.getRandomValues(new Uint8Array(32))),
    },
  ]);
  devStatement = await environmentStatementOf(DEV);
  prodStatement = await environmentStatementOf(PROD);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function environmentStatementOf(
  environmentId: string,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId: chain.projectId,
    environmentId,
    name: environmentId,
    author: owner,
    head: headOf(chain, 1),
  });
}

/** 検証済みステートメント 1 件(宣言ヘッドは既定で genesis)。 */
function variableOf(
  environmentId: string,
  variableId: string,
  name: string,
  headSeq = 1,
): Promise<WireDistributedVariableStatement> {
  return statementFor({
    projectId: chain.projectId,
    environmentId,
    variableId,
    name,
    author: owner,
    head: headOf(chain, headSeq),
  });
}

/**
 * チェーン配布。呼び出しごとに `heads` を進む(最後で止まる)ため、
 * 「同期時点では短いチェーン → 有界再同期で伸びる」形を作れる。接頭辞は
 * 同一ビルドから切り出すので prev_hash 連鎖は正しいまま。
 */
function chainHandlerOf(heads: readonly number[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chain.projectId}/chain`, () => {
    const headSeq = heads[Math.min(call, heads.length - 1)] ?? chain.entries.length;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chain.projectId,
        entries: chain.entries.slice(0, headSeq),
        headSeq,
        headHashHex: chain.hashes[headSeq - 1],
      },
    };
  });
}

/** メタデータのみ pull(§12-7)の応答。値も DEK も運ばない形。 */
function pullMetadataHandlerOf(
  environmentId: string,
  statement: WireDistributedEnvironmentStatement,
  variables: readonly WireDistributedVariableStatement[],
): MockHandler {
  return onRequest(
    "GET",
    `/projects/${chain.projectId}/environments/${environmentId}/pull/metadata`,
    () => ({
      status: 200,
      json: { environmentId, currentEpoch: 1, statement, variables, deletedVariables: [] },
    }),
  );
}

async function startEnv(
  handlers: readonly MockHandler[],
  /** 同期のたびに配布するチェーンの長さ(既定は常に全長)。 */
  chainHeads: readonly number[] = [chain.entries.length],
): Promise<TestEnv & { origin: string }> {
  const server = await MockServer.start([chainHandlerOf(chainHeads), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: chain.projectId });
  return Object.assign(env, { origin: server.origin });
}

/** 直近に起動したモックサーバー(assert 用)。 */
function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/**
 * 値を運ぶ経路へ 1 度も触れていないこと。`/pull/metadata` は値も DEK も
 * 返さないので、末尾一致で値 pull(`/pull`)と区別できる。
 */
function expectNoValueFetches(): void {
  const valuePaths = lastServer()
    .requests.map((request) => request.path)
    .filter((path) => path.endsWith("/pull") || path.endsWith("/deks"));
  expect(valuePaths).toEqual([]);
}

/** 名前だけを与えて 2 環境ぶんのメタデータ pull ハンドラを組む。 */
async function handlersFor(
  devNames: readonly string[],
  prodNames: readonly string[],
): Promise<readonly MockHandler[]> {
  const dev = await Promise.all(
    devNames.map((name, index) => variableOf(DEV, `var-dev-${index}`, name)),
  );
  const prod = await Promise.all(
    prodNames.map((name, index) => variableOf(PROD, `var-prod-${index}`, name)),
  );
  return [
    pullMetadataHandlerOf(DEV, devStatement, dev),
    pullMetadataHandlerOf(PROD, prodStatement, prod),
  ];
}

describe("maruhi env diff", () => {
  it("片方にしか無い変数名を報告し、値の取得経路には触れない", async () => {
    const env = await startEnv(
      await handlersFor(["ZULU", "SHARED_ONE", "ALPHA", "MIKE"], ["PROD_ONLY", "SHARED_ONE"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    // 差分の内容・件数と、名前でソートされた並び
    expect(env.logs).toEqual([
      `同期・検証 OK: 環境 ${DEV} = 4 変数 / 環境 ${PROD} = 2 変数`,
      `環境 ${DEV} のみにある変数: 3`,
      "  ALPHA",
      "  MIKE",
      "  ZULU",
      `環境 ${PROD} のみにある変数: 1`,
      "  PROD_ONLY",
      "両方にある変数: 1(名前が一致するだけです — 値を取得も復号もしていないため、値が同じかどうかは比較していません)",
    ]);
    // 値 pull / DEK 配布は 1 度も叩かない(pullMetadata だけ)
    expectNoValueFetches();
    expect(
      lastServer().requests.filter((request) => request.path.endsWith("/pull/metadata")),
    ).toHaveLength(2);
    // 前段は 1 回だけ = チェーン同期も 1 回だけ(環境ごとに開くと §6.3 検証が
    // 2 度走り、食い違う 2 つの検証済みビューで比較しかねない)
    expect(lastServer().requests.filter((request) => request.path.endsWith("/chain"))).toHaveLength(
      1,
    );
  });

  it("標本のずれは差分の有無によらず注意書きする(stderr。助言だけ結論に合わせる)", async () => {
    // 2 環境は順に読むので、実行中の push は一時的に片側だけに見える = 偽の差分。
    // 真に受けた「修正」は取り消せない push なので、埋める前の再確認を促す
    const drifted = await startEnv(await handlersFor(["ONLY_DEV"], []));
    expect(await runCli(["env", "diff", DEV, PROD], drifted.layer)).toBe(0);
    const driftNotices = drifted.errors.filter((line) =>
      line.includes("同時ではなく順に読んでいます"),
    );
    expect(driftNotices).toHaveLength(1);
    expect(driftNotices[0]).toContain("push で埋める前にもう一度実行して確かめてください");
    // 助言は stdout(差分一覧)へ混ぜない
    expect(drifted.logs.some((line) => line.includes("同時ではなく順に読んでいます"))).toBe(false);

    // **差分ゼロでも黙らない**: 1 つ目を読んだ後の削除は「両方にある」と報告
    // されて差分ゼロで終わる = 実在する差分の見落としになるため、その結論こそ
    // 覆されうる
    const clean = await startEnv(await handlersFor(["SAME"], ["SAME"]));
    expect(await runCli(["env", "diff", DEV, PROD], clean.layer)).toBe(0);
    const cleanNotices = clean.errors.filter((line) =>
      line.includes("同時ではなく順に読んでいます"),
    );
    expect(cleanNotices).toHaveLength(1);
    expect(cleanNotices[0]).toContain("差分ゼロを「揃っている」の根拠にする場合");
    expect(cleanNotices[0]).not.toContain("push で埋める前に");
  });

  it("環境 ID も端末中和する(EnvironmentId はブランド付きではない)", async () => {
    // `EnvironmentId` は Schema.String.check の別名で、未検証の string がそのまま
    // 代入できる(型は検証を強制しない)。CLI 側は requireEnvironmentId を通すが、
    // 表示側がその不変条件に寄りかからないことを直接固定する
    const env = await makeTestEnv();
    await Effect.runPromise(
      reportEnvironmentDiff({
        firstEnvironmentId: "\u001b[2Kdev" as EnvironmentId,
        secondEnvironmentId: "prod\u0007" as EnvironmentId,
        onlyInFirst: ["ONLY_DEV"],
        onlyInSecond: [],
        shared: 0,
        firstWarnings: [],
        secondWarnings: [],
      }).pipe(Effect.provide(env.layer)),
    );
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    expect(env.logs).toContain("環境 \uFFFD[2Kdev のみにある変数: 1");
    expect(env.logs).toContain(
      "同期・検証 OK: 環境 \uFFFD[2Kdev = 1 変数 / 環境 prod\uFFFD = 0 変数",
    );
  });

  it("警告のラベルに使う環境 ID も端末中和する", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(
      reportEnvironmentDiff({
        firstEnvironmentId: "dev" as EnvironmentId,
        secondEnvironmentId: "\u001b[2Kprod" as EnvironmentId,
        onlyInFirst: [],
        onlyInSecond: [],
        shared: 0,
        firstWarnings: [],
        // 警告そのものは values.ts が組む生の文面(ラベル付けは報告側の仕事)
        secondWarnings: ["変数 v1 の名前が NFC 正規形ではありません"],
      }).pipe(Effect.provide(env.layer)),
    );
    const warnings = env.errors.filter((line) => line.includes("NFC 正規形ではありません"));
    expect(warnings).toEqual([
      "警告: 環境 \uFFFD[2Kprod: 変数 v1 の名前が NFC 正規形ではありません",
    ]);
    expect(env.errors.join("\n")).not.toContain("\u001b");
  });

  it("環境のメタ水準の床はコミットしない(チェーン床のヘッドだけ前進する)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], ["ONLY_PROD"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    // 床ファイルは全コマンド共通のチェーン床ヘッドだけを持つ。値を読んでいない
    // 以上、環境・変数の床レコードを作らない(値のダイジェストを要するため)
    const floor: unknown = JSON.parse(
      await readFile(join(env.floorDir, `${chain.projectId}.json`), "utf8"),
    );
    expect(floor).toMatchObject({
      v: 1,
      chainHead: { seq: chain.entries.length, hashHex: chain.hashes[chain.entries.length - 1] },
      environments: {},
    });
  });

  it("ワイヤの並びが変わっても出力は変わらない(名前でソートして安定させる)", async () => {
    const forward = await startEnv(await handlersFor(["ALPHA", "MIKE", "ZULU"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], forward.layer)).toBe(0);

    const reversed = await startEnv(await handlersFor(["ZULU", "MIKE", "ALPHA"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], reversed.layer)).toBe(0);

    expect(reversed.logs).toEqual(forward.logs);
    expect(forward.logs).toContain("  ALPHA");
  });

  it("差分が無い環境どうしでも 0 件として報告する(終了コードは 0 のまま)", async () => {
    const env = await startEnv(await handlersFor(["A", "B"], ["B", "A"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      `同期・検証 OK: 環境 ${DEV} = 2 変数 / 環境 ${PROD} = 2 変数`,
      `環境 ${DEV} のみにある変数: 0`,
      `環境 ${PROD} のみにある変数: 0`,
      "両方にある変数: 2(名前が一致するだけです — 値を取得も復号もしていないため、値が同じかどうかは比較していません)",
    ]);
  });

  it("変数名の大文字小文字は区別する(byte-exact 照合 — AUTH_SPEC §12-1)", async () => {
    const env = await startEnv(await handlersFor(["API_KEY"], ["api_key"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  API_KEY");
    expect(env.logs).toContain("  api_key");
    expect(env.logs).toContain(
      "両方にある変数: 0(名前が一致するだけです — 値を取得も復号もしていないため、値が同じかどうかは比較していません)",
    );
  });

  it("変数名の ANSI / BEL / 改行を中和して表示する", async () => {
    const env = await startEnv(
      await handlersFor(["\u001b[31mEVIL\u0007", "LINE\nBREAK"], ["KEEP"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  \uFFFD[31mEVIL\uFFFD");
    expect(env.logs).toContain("  LINE\uFFFDBREAK");
    // 生の制御文字がどの出力行にも残っていないこと
    expect(env.logs.some((line) => /\p{Cc}/u.test(line))).toBe(false);
  });

  it("視覚的に同名でも正規化形が違えば別の変数として報告する(NFC / NFD)", async () => {
    // 端末上は同じ「CAFÉ」に見えるが、byte-exact では別物。パリティチェックは
    // まさにここで誤解が起きやすいので、一致扱いにせず両側の差分として出し、
    // 非 NFC の側には §12-1 の SHOULD 警告を添える(検出は values.ts のまま)
    const nfc = "CAF\u00C9";
    const nfd = "CAFE\u0301";
    expect(nfd.normalize("NFC")).toBe(nfc);
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, [await variableOf(DEV, "var-dev-0", nfc)]),
      pullMetadataHandlerOf(PROD, prodStatement, [await variableOf(PROD, "var-prod-0", nfd)]),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain(`  ${nfc}`);
    expect(env.logs).toContain(`  ${nfd}`);
    expect(env.logs).toContain(
      "両方にある変数: 0(名前が一致するだけです — 値を取得も復号もしていないため、値が同じかどうかは比較していません)",
    );
    // 警告が立つのは非 NFC を配布した側だけ
    const warnings = env.errors.filter((line) => line.includes("NFC 正規形ではありません"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`警告: 環境 ${PROD}: `);
  });

  it("2 環境ぶんの警告は環境 ID でラベルする(同一文面が畳まれて消えない)", async () => {
    // 非 NFC 名(E + 合成アキュート)。同じ variableId・同じ名前を両環境に置くと
    // 警告の文面は完全に一致する — 集合で畳むと片方の事実が黙って消える形
    const nonNfc = "CAFE\u0301";
    const dev = [await variableOf(DEV, "var-nfc", nonNfc)];
    const prod = [await variableOf(PROD, "var-nfc", nonNfc)];
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, dev),
      pullMetadataHandlerOf(PROD, prodStatement, prod),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const warnings = env.errors.filter((line) => line.includes("NFC 正規形ではありません"));
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain(`警告: 環境 ${DEV}: `);
    expect(warnings[1]).toContain(`警告: 環境 ${PROD}: `);
  });

  it("1 つ目の pull が前進させたビューを 2 つ目の pull へ渡す", async () => {
    // チェーンは genesis(1)→ create dev(2)→ create prod(3)。同期時点では
    // 2 エントリしか配布されず、prod はまだ自ビューに存在しない
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const prod = [await variableOf(PROD, "var-prod-0", "ONLY_PROD")];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ],
      [2, 3],
    );

    // dev のステートメントは自ビューより先のヘッド(seq 3)へ束縛されているので、
    // 1 つ目の pull が §6.3-2b の有界再同期でビューを 3 エントリへ前進させる。
    // 2 つ目の pull にそのビューを渡さないと、prod は「チェーン上に存在しない」
    // 環境のまま照合され、比較が別々の履歴に対するものになる
    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.errors.some((line) => line.includes("チェーン上に存在しません"))).toBe(false);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.logs).toContain("  ONLY_PROD");
  });

  it("master 鍵が無い端末でも実行できる(復号しないため要求しない)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], []));
    // セッションはあるが master 鍵はキーチェーンに無い状態(MARUHI_TOKEN 経由の
    // 実行や、鍵をまだ復元していない端末)
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.errors.some((line) => line.includes("master 鍵がありません"))).toBe(false);
  });

  describe("書き方の誤り(usage エラー = 2)", () => {
    it("環境を 1 つしか書いていない実行を落とす(通信より前)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: 比較する環境を 2 つ指定してください(例: maruhi env diff dev prod)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("同じ環境 ID を 2 つ書いた実行を落とす(指定値は出さない)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: 同じ環境 ID を 2 つ指定しています。比較する 2 つの環境を指定してください",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("2 つ目の環境 ID にも形式検査を掛ける(指定値は出さない)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, "not a valid id"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: 環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで。例: maruhi env diff dev prod)",
      ]);
      expect(env.errors[0]).not.toContain("not a valid id");
      expect(lastServer().requests).toEqual([]);
    });

    it("create 専用の --name を diff で拒否する", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, PROD, "--name", "x"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: --name は env diff では使えません(env create 用のオプションです)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("rotate 専用の --reason / --new-epoch を diff で拒否する", async () => {
      const withReason = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--reason", "x"], withReason.layer)).toBe(2);
      expect(withReason.errors).toEqual([
        "maruhi: --reason は env diff では使えません(env rotate 用のオプションです)",
      ]);

      const withEpoch = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--new-epoch"], withEpoch.layer)).toBe(2);
      expect(withEpoch.errors).toEqual([
        "maruhi: --new-epoch は env diff では使えません(env rotate 用のオプションです)",
      ]);
      // 否定形(`--no-new-epoch`)も同じオプションの綴りとして拒否する
      const negated = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--no-new-epoch"], negated.layer)).toBe(2);
      expect(negated.errors).toEqual([
        "maruhi: --no-new-epoch は env diff では使えません(env rotate 用のオプションです)",
      ]);
    });

    it("diff 専用の 3 つ目の位置引数は create / rotate では余分な引数になる", async () => {
      const created = await startEnv([]);
      expect(await runCli(["env", "create", DEV, PROD], created.layer)).toBe(2);
      expect(created.errors[0]).toContain("余分な引数です(1 個");
      expect(created.errors[0]).toContain(
        "maruhi env が取る位置引数は action environment-id だけです",
      );

      const rotated = await startEnv([]);
      expect(await runCli(["env", "rotate", DEV, PROD], rotated.layer)).toBe(2);
      expect(rotated.errors[0]).toContain("余分な引数です(1 個");
    });

    it("未知の操作では 3 つ目を除かない(操作名の誤りを先に報告する)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "bogus", DEV, PROD], env.layer)).toBe(2);
      expect(env.errors).toEqual(["maruhi: 不明な操作です(create | rotate | diff)"]);
      expect(lastServer().requests).toEqual([]);
    });

    it("未知の操作 + 空の位置引数は、空の方を先に報告する(構造的な誤りが先)", async () => {
      const env = await startEnv([]);

      // 3 つ目を除かないので、空の位置引数の検査もこのスロットを見る。args.ts は
      // 構造的な誤り(空の値・重複・`--` の位置)を操作別の指摘より先に言う設計
      // なので、ここで「不明な操作です」が後回しになるのは**意図どおり**
      // (直して再実行すれば操作名の誤りが出る)。名指しされる位置引数名が
      // その操作に無いものである点は許容する — 空の引数を渡した事実は本当
      expect(await runCli(["env", "bogus", DEV, " "], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: 位置引数 other-environment-id が空です(空白だけの値も受け付けません)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });
  });
});
